"""API-key protection for write endpoints."""

import hmac
from typing import Callable, Optional

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from .config import Settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def make_auth_dependency(settings: Settings) -> Callable:
    def require_api_key(key: Optional[str] = Security(api_key_header)) -> None:
        if not settings.api_key:
            return  # auth disabled (local development)
        if not key or not hmac.compare_digest(key, settings.api_key):
            raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")

    return require_api_key
