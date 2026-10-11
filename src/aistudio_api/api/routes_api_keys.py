"""API Key 管理路由：生成、列表、删除。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from aistudio_api.infrastructure.account.api_key_store import api_key_store

router = APIRouter(prefix="/api-keys")


class GenerateKeyRequest(BaseModel):
    name: str | None = None


class ApiKeyItem(BaseModel):
    key: str
    name: str = ""
    created_at: str = ""


@router.get("")
def list_keys():
    return {"keys": [ApiKeyItem(**item) for item in api_key_store.list()]}


@router.post("")
def generate_key(req: GenerateKeyRequest):
    key = api_key_store.generate((req.name or "").strip() or "API Key")
    return {"key": key}


@router.delete("/{key:path}")
def delete_key(key: str):
    if not api_key_store.remove(key):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}
