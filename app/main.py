from __future__ import annotations

import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .db import init_db
from .routers import admin, auth, payload, version
from .schemas import PublicKeyResponse
from .security import public_key_b64

logging.basicConfig(level=get_settings().log_level)
log = logging.getLogger("rank1")

app = FastAPI(title="Rank1 Auth", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(payload.router)
app.include_router(version.router)
app.include_router(admin.router)


@app.on_event("startup")
def startup() -> None:
    init_db()
    log.info("rank1 auth up")


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "server error"})


@app.get("/health")
def health() -> dict:
    return {"ok": True, "server_time": int(time.time())}


@app.get("/v1/pubkey", response_model=PublicKeyResponse)
def pubkey() -> PublicKeyResponse:
    return PublicKeyResponse(alg="ES256", public_key_b64=public_key_b64(), server_time=int(time.time()))
