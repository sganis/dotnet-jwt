# chatproxy/auth.py
from typing import Any

import httpx
from cachetools import TTLCache
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwk, jwt

from config import settings

_jwks_cache: TTLCache = TTLCache(maxsize=16, ttl=settings.jwks_cache_ttl)
_bearer = HTTPBearer()


async def _fetch_jwk(kid: str) -> dict:
    cache_key = f"jwk:{kid}"
    if cache_key in _jwks_cache:
        return _jwks_cache[cache_key]

    async with httpx.AsyncClient(verify=True, timeout=5.0) as client:
        resp = await client.get(settings.jwt_jwks_url)
        resp.raise_for_status()

    jwks = resp.json()
    keys = {k["kid"]: k for k in jwks.get("keys", [])}

    if kid not in keys:
        raise HTTPException(status_code=401, detail=f"JWK kid '{kid}' not found in JWKS")

    _jwks_cache[cache_key] = keys[kid]
    return keys[kid]


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict[str, Any]:
    token = credentials.credentials

    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Malformed token header")

    kid = header.get("kid", "default")

    try:
        jwk_data = await _fetch_jwk(kid)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=401, detail=f"JWKS fetch failed: {exc}")

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
        raise HTTPException(status_code=401, detail=f"Token validation failed: {exc}")

    # The JWT roles claim carries raw AD group sAMAccountNames issued by iisjwt.
    # Translate them to application roles via group_role_map; unknown groups are
    # dropped. A set comprehension deduplicates when multiple groups share a role.
    raw_groups = payload.get("roles", [])
    groups: list[str] = [raw_groups] if isinstance(raw_groups, str) else list(raw_groups)

    app_roles = list({settings.group_role_map[g] for g in groups if g in settings.group_role_map})

    if not (set(app_roles) & settings.allowed_roles_set):
        raise HTTPException(status_code=403, detail="Insufficient role")

    return {"sub": payload["sub"], "roles": app_roles}
