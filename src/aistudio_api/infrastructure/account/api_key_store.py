"""API Key 存储：支持运行时生成/删除，与 .env 配置的 key 合并鉴权。

存储文件：data/api_keys.json（持久化，重启不丢）。
鉴权逻辑：env 配置的 key（AISTUDIO_API_KEY / AISTUDIO_API_KEYS）∪ 运行时生成的 key。
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path

import aistudio_api.config as _config_mod
from aistudio_api.config import settings

# 与 config.py 的 data 路径保持一致（容器内 /app/data，宿主机 ./data，持久化挂载卷）
_PROJECT_ROOT = Path(_config_mod.__file__).resolve().parents[2]
_KEYS_FILE = Path(
    os.getenv("AISTUDIO_API_KEYS_FILE") or (_PROJECT_ROOT / "data" / "api_keys.json")
)


class ApiKeyStore:
    def __init__(self, env_keys: frozenset[str], path: Path):
        self._env_keys = env_keys
        self._path = path
        self._lock = threading.Lock()
        self._keys: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._keys = {item["key"]: item for item in data if item.get("key")}
        except Exception:
            self._keys = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(list(self._keys.values()), indent=2, ensure_ascii=False), encoding="utf-8")

    def enabled(self) -> bool:
        """是否启用了任何鉴权 key（env 或文件）。"""
        return bool(self._env_keys) or bool(self._keys)

    def has(self, key: str) -> bool:
        return key in self._env_keys or key in self._keys

    def list(self) -> list[dict]:
        with self._lock:
            return [
                {"key": k, "name": v.get("name", ""), "created_at": v.get("created_at", "")}
                for k, v in self._keys.items()
            ]

    def generate(self, name: str = "") -> str:
        key = "sk-" + secrets.token_urlsafe(24)
        with self._lock:
            self._keys[key] = {"key": key, "name": name, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
            self._save()
        return key

    def remove(self, key: str) -> bool:
        with self._lock:
            if key in self._keys:
                del self._keys[key]
                self._save()
                return True
        return False


api_key_store = ApiKeyStore(settings.api_keys, _KEYS_FILE)
