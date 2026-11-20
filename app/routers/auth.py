from __future__ import annotations

import time
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import LicenseKey, utcnow
from ..deps import Session_ as LiveSession
from ..deps import client_ip, get_db, remaining_seconds, require_session
from ..keyformat import is_well_formed, normalize, prefix_of
from ..schemas import AuthRequest, AuthResponse, HeartbeatResponse, OkResponse
from ..security import drop_session, issue_token, kill_switch_on, mark_session, read_token, verify_key

router = APIRouter(prefix="/v1", tags=["auth"])


def _iso(dt) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _lookup(db: Session, raw: str) -> LicenseKey | None:
    handle = prefix_of(raw)
    if not handle:
        return None
    return db.scalar(select(LicenseKey).where(LicenseKey.prefix == handle))


@router.post("/auth", response_model=AuthResponse)
def auth(body: AuthRequest, request: Request, db: Session = Depends(get_db)) -> AuthResponse:
    if kill_switch_on():
        raise HTTPException(status_code=403, detail="disabled")
    if not is_well_formed(body.key):
        raise HTTPException(status_code=400, detail="malformed key")

    record = _lookup(db, body.key)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown key")
    if not verify_key(normalize(body.key), record.key_hash):
        raise HTTPException(status_code=401, detail="invalid key")
    if record.revoked:
        raise HTTPException(status_code=403, detail="revoked")
    if remaining_seconds(record) <= 0:
        raise HTTPException(status_code=403, detail="expired")

    hwid = body.hwid.strip().lower()
    if len(hwid) < 16:
        raise HTTPException(status_code=400, detail="malformed hwid")
    if record.hwid and record.hwid != hwid:
        raise HTTPException(status_code=409, detail="hwid mismatch")
    if not record.hwid:
        record.hwid = hwid

    token, ttl = issue_token(record.id, hwid, record.tier)
    claims = read_token(token) or {}
    mark_session(str(claims.get("jti", "")), ttl, record.id)

    record.last_seen_at = utcnow()
    record.last_ip = client_ip(request)
    record.use_count = (record.use_count or 0) + 1
    db.commit()

    return AuthResponse(
        token=token,
        ttl=ttl,
        tier=record.tier,
        key_id=record.id,
        key_prefix=record.prefix,
        expires_at=_iso(record.expires_at),
        server_time=int(time.time()),
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(
    request: Request,
    session: LiveSession = Depends(require_session),
) -> HeartbeatResponse:
    record = session.key
    token, ttl = issue_token(record.id, record.hwid or "", record.tier)
    claims = read_token(token) or {}
    mark_session(str(claims.get("jti", "")), ttl, record.id)
    drop_session(str(session.claims.get("jti", "")))

    record.last_ip = client_ip(request)
    return HeartbeatResponse(
        status="ok",
        token=token,
        ttl=ttl,
        tier=record.tier,
        key_id=record.id,
        key_prefix=record.prefix,
        expires_at=_iso(record.expires_at),
        server_time=int(time.time()),
    )


@router.post("/revoke-self", response_model=OkResponse)
def revoke_self(session: LiveSession = Depends(require_session)) -> OkResponse:
    from ..db import session_factory

    own = session_factory()()
    try:
        record = own.get(LicenseKey, session.key.id)
        if record is not None:
            record.revoked = True
            own.commit()
    finally:
        own.close()
    drop_session(str(session.claims.get("jti", "")))
    return OkResponse(detail="revoked")
