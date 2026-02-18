# chatproxy/test_auth.py
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException
from jose import JWTError

import auth
from auth import _fetch_jwk, require_auth

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_KID = "test-key-1"
SAMPLE_JWK = {"kid": SAMPLE_KID, "kty": "RSA", "n": "abc", "e": "AQAB"}
SAMPLE_JWKS = {"keys": [SAMPLE_JWK]}


def _creds(token: str = "fake.jwt.token"):
    c = MagicMock()
    c.credentials = token
    return c


def _fake_settings(
    group_role_map=None,
    allowed_roles: str = "llm:user,llm:admin",
    **kwargs,
):
    gmap = (
        group_role_map
        if group_role_map is not None
        else {"LLM_Users": "llm:user", "LLM_Admins": "llm:admin"}
    )
    return SimpleNamespace(
        jwt_issuer="https://test.local",
        jwt_audience="test-audience",
        jwt_jwks_url="https://test.local/jwks",
        jwks_cache_ttl=300,
        group_role_map=gmap,
        allowed_roles=allowed_roles,
        allowed_roles_set={r.strip() for r in allowed_roles.split(",") if r.strip()},
        **kwargs,
    )


def _mock_http_response(jwks: dict):
    resp = MagicMock()
    resp.json.return_value = jwks
    resp.raise_for_status.return_value = None
    return resp


def _mock_http_client(resp):
    """Async context manager wrapping a client whose .get() returns resp."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _auth_patches(payload=None, header=None, jwk_data=None, cfg=None) -> ExitStack:
    """Return a ready-to-enter ExitStack that mocks the full require_auth chain."""
    _payload = payload or {"sub": "DOMAIN\\alice", "roles": ["LLM_Users"]}
    _header = header or {"kid": SAMPLE_KID}
    _jwk_data = jwk_data or SAMPLE_JWK
    _cfg = cfg or _fake_settings()

    stack = ExitStack()
    stack.enter_context(patch("auth._fetch_jwk", AsyncMock(return_value=_jwk_data)))
    stack.enter_context(patch("auth.jwt.get_unverified_header", return_value=_header))
    stack.enter_context(patch("auth.jwt.decode", return_value=_payload))
    stack.enter_context(patch("auth.jwk.construct", return_value=MagicMock()))
    stack.enter_context(patch("auth.settings", _cfg))
    return stack


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_jwks_cache():
    """Prevent JWKS cache from leaking state between tests."""
    auth._jwks_cache.clear()
    yield
    auth._jwks_cache.clear()


# ---------------------------------------------------------------------------
# _fetch_jwk
# ---------------------------------------------------------------------------

class TestFetchJwk:
    async def test_returns_key_for_known_kid(self):
        cm = _mock_http_client(_mock_http_response(SAMPLE_JWKS))
        with patch("auth.httpx.AsyncClient", return_value=cm), \
             patch("auth.settings", _fake_settings()):
            result = await _fetch_jwk(SAMPLE_KID)
        assert result == SAMPLE_JWK

    async def test_key_cached_after_first_fetch(self):
        cm = _mock_http_client(_mock_http_response(SAMPLE_JWKS))
        with patch("auth.httpx.AsyncClient", return_value=cm) as mock_cls, \
             patch("auth.settings", _fake_settings()):
            await _fetch_jwk(SAMPLE_KID)
            await _fetch_jwk(SAMPLE_KID)
        assert mock_cls.call_count == 1  # second call served from cache

    async def test_cache_hit_skips_http_call(self):
        auth._jwks_cache[f"jwk:{SAMPLE_KID}"] = SAMPLE_JWK
        with patch("auth.httpx.AsyncClient") as mock_cls:
            result = await _fetch_jwk(SAMPLE_KID)
        mock_cls.assert_not_called()
        assert result == SAMPLE_JWK

    async def test_kid_not_in_jwks_raises_401(self):
        other_jwks = {"keys": [{"kid": "other-key", "kty": "RSA"}]}
        cm = _mock_http_client(_mock_http_response(other_jwks))
        with patch("auth.httpx.AsyncClient", return_value=cm), \
             patch("auth.settings", _fake_settings()):
            with pytest.raises(HTTPException) as exc_info:
                await _fetch_jwk(SAMPLE_KID)
        assert exc_info.value.status_code == 401
        assert SAMPLE_KID in exc_info.value.detail

    async def test_http_error_propagates(self):
        """Connection errors are not swallowed — require_auth handles them."""
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("refused"))
        cm.__aexit__ = AsyncMock(return_value=False)
        with patch("auth.httpx.AsyncClient", return_value=cm), \
             patch("auth.settings", _fake_settings()):
            with pytest.raises(httpx.ConnectError):
                await _fetch_jwk(SAMPLE_KID)

    async def test_multiple_keys_returns_correct_one(self):
        key1 = {"kid": "key-1", "kty": "RSA", "n": "aaa"}
        key2 = {"kid": "key-2", "kty": "RSA", "n": "bbb"}
        cm = _mock_http_client(_mock_http_response({"keys": [key1, key2]}))
        with patch("auth.httpx.AsyncClient", return_value=cm), \
             patch("auth.settings", _fake_settings()):
            result = await _fetch_jwk("key-2")
        assert result == key2


# ---------------------------------------------------------------------------
# require_auth — happy path
# ---------------------------------------------------------------------------

class TestRequireAuthHappyPath:
    async def test_user_role_returned(self):
        with _auth_patches():
            result = await require_auth(_creds())
        assert result["roles"] == ["llm:user"]

    async def test_admin_role_returned(self):
        payload = {"sub": "DOMAIN\\bob", "roles": ["LLM_Admins"]}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert result["roles"] == ["llm:admin"]

    async def test_sub_passed_through(self):
        payload = {"sub": "CORP\\charlie", "roles": ["LLM_Users"]}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert result["sub"] == "CORP\\charlie"

    async def test_both_roles_when_user_in_both_groups(self):
        payload = {"sub": "alice", "roles": ["LLM_Users", "LLM_Admins"]}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert set(result["roles"]) == {"llm:user", "llm:admin"}


# ---------------------------------------------------------------------------
# require_auth — group mapping
# ---------------------------------------------------------------------------

class TestRequireAuthGroupMapping:
    async def test_unknown_groups_silently_dropped(self):
        """Only groups present in group_role_map produce app roles."""
        payload = {"sub": "alice", "roles": ["LLM_Users", "Domain Users", "VPN_Users"]}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert result["roles"] == ["llm:user"]

    async def test_multiple_groups_mapping_to_same_role_deduplicated(self):
        gmap = {"LLM_Admins": "llm:admin", "LLM_SuperAdmins": "llm:admin"}
        payload = {"sub": "alice", "roles": ["LLM_Admins", "LLM_SuperAdmins"]}
        with _auth_patches(payload=payload, cfg=_fake_settings(group_role_map=gmap)):
            result = await require_auth(_creds())
        assert result["roles"] == ["llm:admin"]  # not doubled

    async def test_roles_claim_as_string_not_list(self):
        """Scalar string in roles is wrapped before mapping."""
        payload = {"sub": "alice", "roles": "LLM_Users"}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert "llm:user" in result["roles"]

    async def test_default_kid_used_when_header_has_no_kid(self):
        """Missing kid in header falls back to the string 'default'."""
        fetch_mock = AsyncMock(return_value=SAMPLE_JWK)
        with _auth_patches():
            with patch("auth.jwt.get_unverified_header", return_value={}), \
                 patch("auth._fetch_jwk", fetch_mock):
                await require_auth(_creds())
        fetch_mock.assert_awaited_once_with("default")


# ---------------------------------------------------------------------------
# require_auth — 403 cases
# ---------------------------------------------------------------------------

class TestRequireAuth403:
    async def test_no_roles_claim_raises_403(self):
        payload = {"sub": "alice"}  # no roles key at all
        with _auth_patches(payload=payload):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 403

    async def test_all_groups_unknown_raises_403(self):
        payload = {"sub": "alice", "roles": ["Domain Users", "VPN_Users"]}
        with _auth_patches(payload=payload):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 403

    async def test_empty_group_role_map_raises_403(self):
        payload = {"sub": "alice", "roles": ["LLM_Users"]}
        cfg = _fake_settings(group_role_map={})
        with _auth_patches(payload=payload, cfg=cfg):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 403

    async def test_mapped_role_absent_from_allowed_roles_raises_403(self):
        """Group maps to a valid string, but it's not in allowed_roles."""
        gmap = {"SPECIAL_GROUP": "llm:superuser"}
        payload = {"sub": "alice", "roles": ["SPECIAL_GROUP"]}
        cfg = _fake_settings(group_role_map=gmap, allowed_roles="llm:user,llm:admin")
        with _auth_patches(payload=payload, cfg=cfg):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# require_auth — 401 cases
# ---------------------------------------------------------------------------

class TestRequireAuth401:
    async def test_malformed_token_header_raises_401(self):
        with _auth_patches():
            with patch("auth.jwt.get_unverified_header", side_effect=JWTError("bad header")):
                with pytest.raises(HTTPException) as exc_info:
                    await require_auth(_creds())
        assert exc_info.value.status_code == 401
        assert "Malformed" in exc_info.value.detail

    async def test_jwks_http_error_raises_401(self):
        with _auth_patches():
            with patch("auth._fetch_jwk", AsyncMock(side_effect=httpx.ConnectError("refused"))):
                with pytest.raises(HTTPException) as exc_info:
                    await require_auth(_creds())
        assert exc_info.value.status_code == 401
        assert "JWKS fetch failed" in exc_info.value.detail

    async def test_kid_not_found_in_jwks_propagates_401(self):
        """HTTPException from _fetch_jwk (kid not found) passes through."""
        exc = HTTPException(status_code=401, detail="JWK kid 'x' not found in JWKS")
        with _auth_patches():
            with patch("auth._fetch_jwk", AsyncMock(side_effect=exc)):
                with pytest.raises(HTTPException) as exc_info:
                    await require_auth(_creds())
        assert exc_info.value.status_code == 401

    async def test_jwt_decode_failure_raises_401(self):
        with _auth_patches():
            with patch("auth.jwt.decode", side_effect=JWTError("expired")):
                with pytest.raises(HTTPException) as exc_info:
                    await require_auth(_creds())
        assert exc_info.value.status_code == 401
        assert "Token validation failed" in exc_info.value.detail
