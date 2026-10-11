"""账号 cookies 有效性探测：定期请求 AI Studio 判断会话是否仍有效。

关键背景：Google 服务端可随时吊销会话（风控/过期），本地 cookie 文件可能
仍存在但已失效。只有实际请求才能确认。这里用轻量探测 + 缓存，避免频繁
请求 Google。缓存由 app 后台任务定期刷新（见 app.py _auth_probe_loop）。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("aistudio.auth_probe")

_PROBE_URL = "https://aistudio.google.com/api/v1beta1/generateContent"
_PROBE_TIMEOUT = 20
_CACHE_TTL = 60  # 秒

_lock = threading.Lock()
# {account_id: (valid: bool, checked_at: float)}
_cache: dict[str, tuple[bool, float]] = {}


def _probe_once(auth_file: str) -> bool:
    """返回该账号 cookies 是否有效（请求未被重定向到 Google 登录页）。"""
    try:
        data = json.loads(Path(auth_file).read_text(encoding="utf-8"))
        cookies = data.get("cookies") or []
        jar = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name") and c.get("value"))
        if not jar:
            return False
        req = urllib.request.Request(
            _PROBE_URL,
            data=b"{}",
            method="POST",
            headers={
                "Cookie": jar,
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/json",
            },
        )
        try:
            resp = urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT)
            return "accounts.google.com" not in (resp.url or "")
        except urllib.error.HTTPError as exc:
            # 4xx/5xx 也是"已到服务器"，只要没被重定向到登录页即视为会话有效
            return bool(exc.url) and "accounts.google.com" not in exc.url
    except Exception:
        return False


def probe_account(account_id: str, auth_file: str | None) -> bool | None:
    """探测单个账号；读取缓存，缓存未命中才实际请求。返回 None 表示无 auth 文件。"""
    if not auth_file or not Path(auth_file).exists():
        return None
    with _lock:
        cached = _cache.get(account_id)
        if cached and time.time() - cached[1] < _CACHE_TTL:
            return cached[0]
    valid = _probe_once(auth_file)
    with _lock:
        _cache[account_id] = (valid, time.time())
    return valid


def refresh_all(accounts: list[tuple[str, str | None]]) -> None:
    """后台任务：刷新所有账号的有效性缓存。accounts = [(account_id, auth_file), ...]"""
    for account_id, auth_file in accounts:
        try:
            probe_account(account_id, auth_file)
        except Exception:
            pass


def is_valid(account_id: str, auth_file: str | None) -> bool | None:
    """读取缓存（不触发请求）；缓存未命中返回 None（未探测）。"""
    with _lock:
        cached = _cache.get(account_id)
        if cached and time.time() - cached[1] < _CACHE_TTL:
            return cached[0]
    return None
