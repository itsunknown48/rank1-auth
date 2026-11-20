from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AuthRequest(BaseModel):
    key: str = Field(min_length=8, max_length=64)
    hwid: str = Field(min_length=16, max_length=64)
    version: str = Field(default="", max_length=32)


class AuthResponse(BaseModel):
    token: str
    ttl: int
    tier: str
    key_id: str
    key_prefix: str
    expires_at: str
    server_time: int


class HeartbeatResponse(AuthResponse):
    status: Literal["ok"] = "ok"


class PayloadResponse(BaseModel):
    url: str
    sha256: str
    key_b64: str
    nonce_b64: str
    size: int = 0
    version: str = ""
    expires_at: int = 0


class IssueRequest(BaseModel):
    tier: str = Field(default="1d", max_length=8)
    count: int = Field(default=1, ge=1, le=100)
    note: str = Field(default="", max_length=120)


class IssuedKey(BaseModel):
    key: str
    key_prefix: str
    tier: str
    expires_at: str


class IssueResponse(BaseModel):
    keys: list[IssuedKey]


class KeyOut(BaseModel):
    key_id: str
    key_prefix: str
    tier: str
    note: str
    hwid: str | None
    revoked: bool
    created_at: str
    expires_at: str
    last_seen_at: str | None
    last_ip: str
    use_count: int
    seconds_left: int
    status: str


class KeyList(BaseModel):
    total: int
    items: list[KeyOut]


class ResetHwidRequest(BaseModel):
    key_prefix: str = Field(min_length=9, max_length=16)


class ExtendRequest(BaseModel):
    key_prefix: str = Field(min_length=9, max_length=16)
    days: int = Field(default=0, ge=-365, le=365)
    tier: str = Field(default="", max_length=8)


class RevokeRequest(BaseModel):
    key_prefix: str = Field(min_length=9, max_length=16)
    reason: str = Field(default="", max_length=120)


class KillSwitchRequest(BaseModel):
    on: bool


class OkResponse(BaseModel):
    ok: bool = True
    detail: str = ""


class PublicKeyResponse(BaseModel):
    alg: str
    public_key_b64: str
    server_time: int
