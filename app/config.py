import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite:///./rank1.db"
    redis_url: str = ""
    admin_secret: str = ""
    token_ttl_seconds: int = 600
    hwid_lock: bool = True
    payload_url: str = ""
    payload_sha256: str = ""
    payload_version: str = ""
    payload_key_b64: str = ""
    payload_nonce_b64: str = ""
    jwt_seed_b64: str = ""
    public_base_url: str = ""
    allow_register_default: bool = False
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.admin_secret:
        s.admin_secret = os.environ.get("ADMIN_SECRET", "")
    return s
