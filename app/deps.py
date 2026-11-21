from __future__ import annotations

import hmac
import os
import time
from typing import Generator

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from .config import get_settings
from .db import LicenseKey, session_factory
from .security import read_token


def get_db() -> Generator[Session, None, None]:
    db = session_factory()()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "")[:64]


def require_admin(x_admin_secret: str = Header(default="")) -> str:
    expected = get_settings().admin_secret
    if not expected:
        raise HTTPException(status_code=503, detail="admin disabled")
    if not hmac.compare_digest(x_admin_secret, expected):
        raise HTTPException(status_code=401, detail="bad admin secret")
    return "admin"


async def verify_signature(
    request: Request,
    x_r1_ts: str = Header(default=""),
    x_r1_sig: str = Header(default=""),
) -> None:
    import hashlib

    expected = get_settings().sign_secret
    if not expected:
        return
    if not x_r1_ts or not x_r1_sig:
        raise HTTPException(status_code=401, detail="unsigned request")
    try:
        ts = int(x_r1_ts)
    except ValueError:
        raise HTTPException(status_code=401, detail="bad timestamp")
    if abs(int(time.time()) - ts) > 300:
        raise HTTPException(status_code=401, detail="stale request")

    body = await request.body()
    canonical = f"{ts}\n{request.method}\n{request.url.path}\n"
    if body:
        canonical += hashlib.sha256(body).hexdigest()
    mac = hmac.new(expected.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, x_r1_sig.lower()):
        raise HTTPException(status_code=401, detail="bad signature")


class Session_:
    __slots__ = ("token", "claims", "key")

    def __init__(self, token: str, claims: dict, key: LicenseKey) -> None:
        self.token = token
        self.claims = claims
        self.key = key


def require_session(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Session_:
    from .security import kill_switch_on, session_dead

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = authorization[7:].strip()
    claims = read_token(token)
    if not claims:
        raise HTTPException(status_code=401, detail="invalid token")
    if kill_switch_on():
        raise HTTPException(status_code=403, detail="disabled")
    if session_dead(str(claims.get("jti", ""))):
        raise HTTPException(status_code=403, detail="revoked")

    key = db.get(LicenseKey, str(claims.get("sub", "")))
    if key is None:
        raise HTTPException(status_code=401, detail="unknown key")
    if key.revoked:
        raise HTTPException(status_code=403, detail="revoked")
    if _expired(key):
        raise HTTPException(status_code=403, detail="expired")
    if str(claims.get("hwid", "")) != (key.hwid or ""):
        raise HTTPException(status_code=403, detail="hwid mismatch")

    key.last_seen_at = _utcnow()
    db.commit()
    return Session_(token, claims, key)


def _utcnow():
    from .db import utcnow

    return utcnow()


def _expired(key: LicenseKey) -> bool:
    exp = key.expires_at
    if exp is None:
        return True
    if exp.tzinfo is None:
        from datetime import timezone

        exp = exp.replace(tzinfo=timezone.utc)
    return exp.timestamp() <= time.time()


def remaining_seconds(key: LicenseKey) -> int:
    exp = key.expires_at
    if exp is None:
        return 0
    if exp.tzinfo is None:
        from datetime import timezone

        exp = exp.replace(tzinfo=timezone.utc)
    return max(0, int(exp.timestamp() - time.time()))
