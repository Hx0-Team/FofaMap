"""REST bearer/JWT protection and safe loopback-only unauthenticated mode."""

from __future__ import annotations

import ipaddress
import os

from fastapi import Header, HTTPException, Request


def _loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value in {"localhost", "testclient"}


async def require_service_auth(request: Request, authorization: str | None = Header(default=None)) -> None:
    service_token = os.getenv("FOFAMAP_SERVICE_TOKEN", "")
    bind_host = os.getenv("FOFAMAP_BIND_HOST", "127.0.0.1")
    if not service_token:
        if not _loopback(bind_host):
            raise HTTPException(status_code=503, detail="unauthenticated service may bind only to loopback")
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.removeprefix("Bearer ").strip()
    if token == service_token:
        return
    public_key = os.getenv("FOFAMAP_JWT_PUBLIC_KEY", "")
    issuer = os.getenv("FOFAMAP_JWT_ISSUER", "")
    audience = os.getenv("FOFAMAP_JWT_AUDIENCE", "fofamap")
    if public_key and issuer:
        try:
            import jwt  # type: ignore

            jwt.decode(token, public_key, algorithms=["RS256", "ES256"], issuer=issuer, audience=audience)
            return
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid JWT") from exc
    raise HTTPException(status_code=401, detail="invalid bearer token")
