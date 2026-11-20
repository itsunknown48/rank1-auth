from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import PayloadRelease
from ..deps import Session_ as LiveSession
from ..deps import get_db, require_session
from ..schemas import PayloadResponse

router = APIRouter(prefix="/v1", tags=["payload"])


def _blob_path() -> Path:
    return Path(os.environ.get("PAYLOAD_BLOB_PATH", "rank1-overlay.bin"))


def _local_url() -> str:
    base = get_settings().public_base_url.rstrip("/")
    if not base:
        return "blob"
    return f"{base}/v1/payload/blob"


@router.post("/payload", response_model=PayloadResponse)
def payload(
    session: LiveSession = Depends(require_session),
    db: Session = Depends(get_db),
) -> PayloadResponse:
    release = db.scalars(
        select(PayloadRelease)
        .where(PayloadRelease.active.is_(True))
        .order_by(PayloadRelease.id.desc())
        .limit(1)
    ).first()

    if release is not None:
        return PayloadResponse(
            url=release.url or _local_url(),
            sha256=release.sha256,
            key_b64=release.key_b64,
            nonce_b64=release.nonce_b64,
            size=release.size or 0,
            version=release.version or "",
            expires_at=0,
        )

    s = get_settings()
    if not s.payload_url or not s.payload_key_b64 or not s.payload_nonce_b64:
        raise HTTPException(status_code=503, detail="payload unavailable")
    return PayloadResponse(
        url=s.payload_url,
        sha256=s.payload_sha256,
        key_b64=s.payload_key_b64,
        nonce_b64=s.payload_nonce_b64,
        size=0,
        version=s.payload_version,
        expires_at=0,
    )


@router.get("/payload/blob")
def payload_blob(session: LiveSession = Depends(require_session)) -> FileResponse:
    path = _blob_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="payload blob not staged")
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)
