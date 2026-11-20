from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import ec

from .config import get_settings

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def hash_key(raw: str) -> str:
    return _hasher.hash(raw.strip().upper())


def verify_key(raw: str, stored: str) -> bool:
    try:
        return _hasher.verify(stored, raw.strip().upper())
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def hwid_digest(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", "ignore"))
        h.update(b"\x00")
    return h.hexdigest()


def _seed() -> bytes:
    s = get_settings()
    raw = s.jwt_seed_b64 or ""
    if raw:
        try:
            seed = base64.b64decode(raw)
        except Exception:
            seed = b""
        if len(seed) != 32:
            seed = hashlib.sha256(seed or raw.encode()).digest()
    else:
        seed = hashlib.sha256(b"rank1-dev-seed").digest()
    return seed


def _private_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(_seed(), "big"), ec.SECP256R1())


def _public_key() -> ec.EllipticCurvePublicKey:
    return _private_key().public_key()


def public_key_b64() -> str:
    nums = _public_key().public_numbers()
    raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return base64.b64encode(raw).decode()


def public_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization

    return (
        _public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


def issue_token(key_id: str, hwid: str, tier: str, ttl: int | None = None) -> tuple[str, int]:
    s = get_settings()
    ttl = ttl or s.token_ttl_seconds
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": key_id,
        "hwid": hwid,
        "tier": tier,
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
        "iss": "rank1",
        "aud": "loader",
    }
    return jwt.encode(claims, _private_key(), algorithm="ES256"), ttl


def read_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(
            token,
            _public_key(),
            algorithms=["ES256"],
            audience="loader",
            issuer="rank1",
        )
    except Exception:
        return None


class _Memory:
    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}

    def get(self, key: str) -> str | None:
        item = self._data.get(key)
        if not item:
            return None
        value, expires = item
        if expires and expires < time.time():
            self._data.pop(key, None)
            return None
        return value

    def setex(self, key: str, ttl: int, value: str) -> None:
        self._data[key] = (value, time.time() + ttl if ttl else 0)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)


class _Redis:
    def __init__(self, url: str) -> None:
        import redis

        self._r = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)

    def get(self, key: str) -> str | None:
        try:
            return self._r.get(key)
        except Exception:
            return None

    def setex(self, key: str, ttl: int, value: str) -> None:
        try:
            self._r.setex(key, ttl, value)
        except Exception:
            pass

    def delete(self, key: str) -> None:
        try:
            self._r.delete(key)
        except Exception:
            pass


_cache = None


def cache():
    global _cache
    if _cache is None:
        url = get_settings().redis_url or os.environ.get("REDIS_URL", "")
        _cache = _Redis(url) if url else _Memory()
    return _cache


def mark_session(jti: str, ttl: int, key_id: str) -> None:
    cache().setex(f"rank1:sess:{jti}", max(ttl, 60), key_id)


def session_dead(jti: str) -> bool:
    return cache().get(f"rank1:sess:{jti}") == "dead"


def drop_session(jti: str) -> None:
    cache().setex(f"rank1:sess:{jti}", 60, "dead")


def kill_switch_on() -> bool:
    return cache().get("rank1:kill") == "1"


def set_kill_switch(on: bool) -> None:
    if on:
        cache().setex("rank1:kill", 86400 * 30, "1")
    else:
        cache().delete("rank1:kill")
