# chat/auth.py
import logging
import time
from typing import Any

import httpx
from cachetools import TTLCache
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwk, jwt

from config import settings

logger = logging.getLogger(__name__)

# Cache the entire JWKS key set as one entry keyed by the JWKS URL.
# On unknown kid, force-refresh once before rejecting (throttled to avoid
# hammering the JWKS endpoint with invalid-kid attacks).
_jwks_cache: TTLCache = TTLCache(maxsize=4, ttl=settings.jwks_cache_ttl)
_bearer = HTTPBearer()

_last_force_refresh: float = 0.0
_FORCE_REFRESH_COOLDOWN: float = 10.0  # minimum seconds between force-refreshes


async def _load_jwks(force: bool = False) -> dict[str, dict]:
    """Fetch and cache the full JWKS key set, returning a dict keyed by kid."""
    global _last_force_refresh
    cache_key = settings.jwt_jwks_url

    if force:
        now = time.monotonic()
        if now - _last_force_refresh < _FORCE_REFRESH_COOLDOWN:
            # Throttled — return cached set without hitting the endpoint again.
            return _jwks_cache.get(cache_key, {})
        _last_force_refresh = now
    elif cache_key in _jwks_cache:
        return _jwks_cache[cache_key]

    async with httpx.AsyncClient(verify=True, timeout=5.0) as client:
        resp = await client.get(cache_key)
        resp.raise_for_status()

    keys: dict[str, dict] = {k["kid"]: k for k in resp.json().get("keys", [])}
    _jwks_cache[cache_key] = keys
    return keys


async def _fetch_jwk(kid: str) -> dict:
    keys = await _load_jwks()
    if kid not in keys:
        # Unknown kid — refresh once in case a new key was just published.
        keys = await _load_jwks(force=True)
    if kid not in keys:
        logger.warning("JWK kid '%s' not found in JWKS after refresh", kid)
        raise HTTPException(status_code=401, detail="Token validation failed: unknown signing key")
    return keys[kid]


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict[str, Any]:
    token = credentials.credentials

    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        logger.warning("Malformed JWT header received")
        raise HTTPException(status_code=401, detail="Malformed token header")

    kid = header.get("kid", "default")

    try:
        jwk_data = await _fetch_jwk(kid)
    except httpx.HTTPError as exc:
        logger.error("JWKS fetch failed: %s", exc)
        raise HTTPException(status_code=401, detail="JWKS fetch failed")

    try:
        public_key = jwk.construct(jwk_data)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"verify_exp": True, "verify_iat": True},
        )
    except JWTError as exc:
        logger.warning("JWT validation failed: %s", exc)
        raise HTTPException(status_code=401, detail="Token validation failed")

    # Validate and extract AD groups claim.
    raw = payload.get("groups", [])
    if isinstance(raw, str):
        groups: list[str] = [raw]
    elif isinstance(raw, list) and all(isinstance(g, str) for g in raw):
        groups = raw
    else:
        logger.warning("Invalid groups claim type in token for sub=%s", payload.get("sub"))
        raise HTTPException(status_code=401, detail="Token validation failed: invalid groups claim")

    # If ACCESS_GROUPS is configured, reject users not in any allowed group.
    access = settings.access_groups_set
    if access and not (set(groups) & access):
        logger.warning("Access denied for sub=%s — not in required groups", payload.get("sub"))
        raise HTTPException(status_code=403, detail="Not authorized")

    return {"sub": payload["sub"], "groups": groups}
