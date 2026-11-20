from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..config import get_settings
from ..deps import Session_ as LiveSession
from ..deps import require_session
from ..schemas import PayloadResponse

router = APIRouter(prefix="/v1", tags=["payload"])


@router.post("/payload", response_model=PayloadResponse)
def payload(session: LiveSession = Depends(require_session)) -> PayloadResponse:
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
