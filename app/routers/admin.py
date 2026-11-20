from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..db import Audit, LicenseKey, utcnow
from ..deps import get_db, remaining_seconds, require_admin
from ..keyformat import TIERS, generate, normalize, prefix_of, tier_days
from ..schemas import (
    ExtendRequest,
    IssueRequest,
    IssueResponse,
    IssuedKey,
    KeyList,
    KeyOut,
    KillSwitchRequest,
    OkResponse,
    ResetHwidRequest,
    RevokeRequest,
)
from ..security import hash_key, kill_switch_on, open_key, seal_key, set_kill_switch

router = APIRouter(prefix="/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def _iso(dt) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _audit(db: Session, action: str, key_id: str, detail: str = "") -> None:
    db.add(Audit(actor="admin", action=action, key_id=key_id, detail=detail[:240]))


def _status(record: LicenseKey) -> str:
    if record.revoked:
        return "revoked"
    return "active" if remaining_seconds(record) > 0 else "expired"


def _out(record: LicenseKey) -> KeyOut:
    return KeyOut(
        key_id=record.id,
        key_prefix=record.prefix,
        tier=record.tier,
        note=record.note or "",
        hwid=record.hwid,
        revoked=record.revoked,
        created_at=_iso(record.created_at),
        expires_at=_iso(record.expires_at),
        last_seen_at=_iso(record.last_seen_at) if record.last_seen_at else None,
        last_ip=record.last_ip or "",
        use_count=record.use_count or 0,
        seconds_left=remaining_seconds(record),
        status=_status(record),
        revealable=bool(record.key_sealed),
    )


def _by_prefix(db: Session, prefix: str) -> LicenseKey:
    record = db.scalar(select(LicenseKey).where(LicenseKey.prefix == prefix.strip().upper()))
    if record is None:
        raise HTTPException(status_code=404, detail="unknown key")
    return record


@router.post("/issue", response_model=IssueResponse)
def issue(body: IssueRequest, db: Session = Depends(get_db)) -> IssueResponse:
    tier = body.tier.lower().strip()
    days = tier_days(tier)
    if days <= 0:
        raise HTTPException(status_code=400, detail="tier must be one of " + ",".join(TIERS))

    now = utcnow()
    expires = now + timedelta(days=days)
    issued: list[IssuedKey] = []

    for _ in range(body.count):
        for _attempt in range(8):
            plain = generate()
            handle = prefix_of(plain)
            if handle and db.scalar(select(LicenseKey.id).where(LicenseKey.prefix == handle)) is None:
                break
        else:
            raise HTTPException(status_code=500, detail="prefix collision")

        record = LicenseKey(
            prefix=handle,
            key_hash=hash_key(normalize(plain)),
            key_sealed=seal_key(plain),
            tier=tier,
            note=body.note or "",
            created_at=now,
            expires_at=expires,
        )
        db.add(record)
        db.flush()
        _audit(db, "issue", record.id, f"{tier} {handle}")
        issued.append(
            IssuedKey(key=plain, key_prefix=handle, tier=tier, expires_at=_iso(expires))
        )

    db.commit()
    return IssueResponse(keys=issued)


@router.get("/keys", response_model=KeyList)
def list_keys(
    db: Session = Depends(get_db),
    status: str = Query(default="all", max_length=16),
    q: str = Query(default="", max_length=40),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> KeyList:
    stmt = select(LicenseKey)
    now = utcnow()
    if status == "revoked":
        stmt = stmt.where(LicenseKey.revoked.is_(True))
    elif status == "expired":
        stmt = stmt.where(LicenseKey.revoked.is_(False), LicenseKey.expires_at <= now)
    elif status == "active":
        stmt = stmt.where(LicenseKey.revoked.is_(False), LicenseKey.expires_at > now)

    if q:
        needle = q.strip()
        stmt = stmt.where(
            or_(
                LicenseKey.prefix.ilike(f"%{needle.upper()}%"),
                LicenseKey.hwid.ilike(f"%{needle.lower()}%"),
                LicenseKey.note.ilike(f"%{needle}%"),
            )
        )

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(LicenseKey.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return KeyList(total=int(total), items=[_out(r) for r in rows])


@router.get("/reveal")
def reveal(
    key_prefix: str = Query(min_length=9, max_length=16),
    db: Session = Depends(get_db),
) -> dict:
    record = _by_prefix(db, key_prefix)
    if not record.key_sealed:
        raise HTTPException(status_code=404, detail="this key was issued before reveal existed")
    plain = open_key(record.key_sealed)
    if not plain:
        raise HTTPException(status_code=409, detail="cannot decrypt, signing seed changed")
    _audit(db, "reveal", record.id, record.prefix)
    db.commit()
    return {"key": plain, "key_prefix": record.prefix}


@router.post("/revoke", response_model=OkResponse)
def revoke(body: RevokeRequest, db: Session = Depends(get_db)) -> OkResponse:
    record = _by_prefix(db, body.key_prefix)
    record.revoked = True
    _audit(db, "revoke", record.id, body.reason)
    db.commit()
    return OkResponse(detail=f"{record.prefix} revoked")


@router.post("/unrevoke", response_model=OkResponse)
def unrevoke(body: RevokeRequest, db: Session = Depends(get_db)) -> OkResponse:
    record = _by_prefix(db, body.key_prefix)
    record.revoked = False
    _audit(db, "unrevoke", record.id, body.reason)
    db.commit()
    return OkResponse(detail=f"{record.prefix} restored")


@router.post("/reset-hwid", response_model=OkResponse)
def reset_hwid(body: ResetHwidRequest, db: Session = Depends(get_db)) -> OkResponse:
    record = _by_prefix(db, body.key_prefix)
    record.hwid = None
    _audit(db, "reset-hwid", record.id, "")
    db.commit()
    return OkResponse(detail=f"{record.prefix} unbound")


@router.post("/extend", response_model=OkResponse)
def extend(body: ExtendRequest, db: Session = Depends(get_db)) -> OkResponse:
    record = _by_prefix(db, body.key_prefix)
    now = utcnow()

    if body.tier:
        days = tier_days(body.tier)
        if days <= 0:
            raise HTTPException(status_code=400, detail="bad tier")
        record.tier = body.tier.lower().strip()
        record.expires_at = now + timedelta(days=days)
    elif body.days:
        base = record.expires_at
        if base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)
        base = max(base, now) if body.days > 0 else base
        record.expires_at = base + timedelta(days=body.days)
    else:
        raise HTTPException(status_code=400, detail="nothing to change")

    _audit(db, "extend", record.id, f"{body.tier or body.days}")
    db.commit()
    return OkResponse(detail=_iso(record.expires_at))


@router.delete("/key", response_model=OkResponse)
def delete_key(key_prefix: str = Query(min_length=9, max_length=16), db: Session = Depends(get_db)) -> OkResponse:
    record = _by_prefix(db, key_prefix)
    handle = record.prefix
    db.delete(record)
    _audit(db, "delete", "", handle)
    db.commit()
    return OkResponse(detail=f"{handle} deleted")


@router.get("/stats")
def stats(db: Session = Depends(get_db)) -> dict:
    now = utcnow()
    total = db.scalar(select(func.count()).select_from(LicenseKey)) or 0
    active = (
        db.scalar(
            select(func.count())
            .select_from(LicenseKey)
            .where(LicenseKey.revoked.is_(False), LicenseKey.expires_at > now)
        )
        or 0
    )
    expired = (
        db.scalar(
            select(func.count())
            .select_from(LicenseKey)
            .where(LicenseKey.revoked.is_(False), LicenseKey.expires_at <= now)
        )
        or 0
    )
    revoked = db.scalar(select(func.count()).select_from(LicenseKey).where(LicenseKey.revoked.is_(True))) or 0
    bound = db.scalar(select(func.count()).select_from(LicenseKey).where(LicenseKey.hwid.isnot(None))) or 0
    seen = db.scalar(select(func.max(LicenseKey.last_seen_at)))
    return {
        "total": int(total),
        "active": int(active),
        "expired": int(expired),
        "revoked": int(revoked),
        "hwid_bound": int(bound),
        "last_seen": _iso(seen) if seen else "",
        "kill_switch": kill_switch_on(),
        "server_time": int(now.timestamp()),
    }


@router.post("/kill-switch", response_model=OkResponse)
def kill_switch(body: KillSwitchRequest, db: Session = Depends(get_db)) -> OkResponse:
    set_kill_switch(body.on)
    _audit(db, "kill-switch", "", "on" if body.on else "off")
    db.commit()
    return OkResponse(detail="on" if body.on else "off")


@router.get("/audit")
def audit(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)) -> dict:
    rows = db.scalars(select(Audit).order_by(Audit.id.desc()).limit(limit)).all()
    return {
        "items": [
            {
                "id": r.id,
                "at": _iso(r.at),
                "actor": r.actor,
                "action": r.action,
                "key_id": r.key_id,
                "detail": r.detail,
            }
            for r in rows
        ]
    }


@router.post("/purge-expired", response_model=OkResponse)
def purge_expired(db: Session = Depends(get_db)) -> OkResponse:
    now = utcnow()
    cutoff = now - timedelta(days=30)
    rows = db.scalars(
        select(LicenseKey).where(LicenseKey.revoked.is_(False), LicenseKey.expires_at < cutoff)
    ).all()
    for record in rows:
        db.delete(record)
    _audit(db, "purge", "", f"{len(rows)} removed")
    db.commit()
    return OkResponse(detail=f"{len(rows)} removed")
