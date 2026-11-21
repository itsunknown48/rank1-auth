from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import LoaderRelease
from ..deps import Session_ as LiveSession
from ..deps import get_db, require_session, verify_signature
from ..schemas import VersionResponse

router = APIRouter(prefix="/v1", tags=["version"], dependencies=[Depends(verify_signature)])


def _loader_path() -> Path:
    return Path(os.environ.get("LOADER_BLOB_PATH", "rank1-loader.exe"))


def _local_url() -> str:
    base = get_settings().public_base_url.rstrip("/")
    if not base:
        return "blob"
    return f"{base}/v1/loader/blob"


@router.get("/version", response_model=VersionResponse)
def version(
    session: LiveSession = Depends(require_session),
    db: Session = Depends(get_db),
) -> VersionResponse:
    release = db.scalars(
        select(LoaderRelease)
        .where(LoaderRelease.active.is_(True))
        .order_by(LoaderRelease.id.desc())
        .limit(1)
    ).first()

    if release is not None:
        return VersionResponse(
            version=release.version,
            url=release.url or _local_url(),
            sha256=release.sha256,
            size=release.size or 0,
            mandatory=bool(release.mandatory),
            server_time=int(time.time()),
        )

    s = get_settings()
    return VersionResponse(
        version=s.loader_version,
        url=s.loader_url,
        sha256=s.loader_sha256,
        size=0,
        mandatory=False,
        server_time=int(time.time()),
    )


@router.get("/loader/blob")
def loader_blob(session: LiveSession = Depends(require_session)) -> FileResponse:
    path = _loader_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="loader blob not staged")
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)
