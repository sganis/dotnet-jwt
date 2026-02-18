# embed/test_auth.py
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
FAKE_JWKS_URL = "https://test.local/jwks"


def _creds(token: str = "fake.jwt.token"):
    c = MagicMock()
    c.credentials = token
    return c


def _fake_settings(access_groups: str = "dep1,dep2", **kwargs):
    """Return a Settings-like namespace for auth tests."""
    access_set = {x.strip() for x in access_groups.split(",") if x.strip()} if access_groups else set()
    return SimpleNamespace(
        jwt_issuer="https://test.local",
        jwt_audience="test-audience",
        jwt_jwks_url=FAKE_JWKS_URL,
        jwks_cache_ttl=300,
        access_groups_set=access_set,
        **kwargs,
    )


def _mock_http_response(jwks: dict):
    resp = MagicMock()
    resp.json.return_value = jwks
    resp.raise_for_status.return_value = None
    return resp


def _mock_http_client(resp):
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _auth_patches(payload=None, header=None, jwk_data=None, cfg=None) -> ExitStack:
    """Return a ready-to-enter ExitStack that mocks the full require_auth chain."""
    _payload = payload or {"sub": "DOMAIN\\alice", "groups": ["dep1"]}
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
    auth._jwks_cache.clear()
    auth._last_force_refresh = 0.0
    yield
    auth._jwks_cache.clear()
    auth._last_force_refresh = 0.0


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
        assert mock_cls.call_count == 1

    async def test_cache_hit_skips_http_call(self):
        fake_cfg = _fake_settings()
        with patch("auth.settings", fake_cfg):
            auth._jwks_cache[fake_cfg.jwt_jwks_url] = {SAMPLE_KID: SAMPLE_JWK}
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

    async def test_http_error_propagates(self):
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

    async def test_unknown_kid_triggers_force_refresh(self):
        """An unknown kid fetches JWKS normally, then force-refreshes once."""
        other_jwks = {"keys": [{"kid": "other-key", "kty": "RSA"}]}
        cm = _mock_http_client(_mock_http_response(other_jwks))
        with patch("auth.httpx.AsyncClient", return_value=cm) as mock_cls, \
             patch("auth.settings", _fake_settings()):
            with pytest.raises(HTTPException):
                await _fetch_jwk(SAMPLE_KID)
        assert mock_cls.call_count == 2

    async def test_force_refresh_throttled_after_recent_refresh(self):
        """A force-refresh within the cooldown window skips the HTTP call."""
        import time as _time
        auth._last_force_refresh = _time.monotonic()
        other_jwks = {"keys": [{"kid": "other-key", "kty": "RSA"}]}
        cm = _mock_http_client(_mock_http_response(other_jwks))
        with patch("auth.httpx.AsyncClient", return_value=cm) as mock_cls, \
             patch("auth.settings", _fake_settings()):
            with pytest.raises(HTTPException):
                await _fetch_jwk(SAMPLE_KID)
        assert mock_cls.call_count == 1


# ---------------------------------------------------------------------------
# require_auth — happy path
# ---------------------------------------------------------------------------

class TestRequireAuthHappyPath:
    async def test_groups_returned(self):
        with _auth_patches():
            result = await require_auth(_creds())
        assert result["groups"] == ["dep1"]

    async def test_sub_passed_through(self):
        payload = {"sub": "CORP\\charlie", "groups": ["dep1"]}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert result["sub"] == "CORP\\charlie"

    async def test_multiple_groups_returned(self):
        payload = {"sub": "alice", "groups": ["dep1", "max_group"]}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert set(result["groups"]) == {"dep1", "max_group"}

    async def test_groups_claim_as_string_wrapped_to_list(self):
        """Scalar string in groups claim is normalized to a list."""
        payload = {"sub": "alice", "groups": "dep1"}
        with _auth_patches(payload=payload):
            result = await require_auth(_creds())
        assert result["groups"] == ["dep1"]

    async def test_default_kid_used_when_header_has_no_kid(self):
        fetch_mock = AsyncMock(return_value=SAMPLE_JWK)
        with _auth_patches():
            with patch("auth.jwt.get_unverified_header", return_value={}), \
                 patch("auth._fetch_jwk", fetch_mock):
                await require_auth(_creds())
        fetch_mock.assert_awaited_once_with("default")


# ---------------------------------------------------------------------------
# require_auth — groups claim validation
# ---------------------------------------------------------------------------

class TestRequireAuthGroupsValidation:
    async def test_invalid_groups_type_raises_401(self):
        payload = {"sub": "alice", "groups": 42}
        with _auth_patches(payload=payload):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 401

    async def test_groups_list_with_non_string_raises_401(self):
        payload = {"sub": "alice", "groups": ["dep1", 99]}
        with _auth_patches(payload=payload):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# require_auth — access control
# ---------------------------------------------------------------------------

class TestRequireAuthAccessControl:
    async def test_empty_access_groups_allows_any_user(self):
        payload = {"sub": "alice", "groups": ["random_group"]}
        cfg = _fake_settings(access_groups="")
        with _auth_patches(payload=payload, cfg=cfg):
            result = await require_auth(_creds())
        assert result["sub"] == "alice"

    async def test_empty_access_groups_allows_user_with_no_groups(self):
        payload = {"sub": "alice", "groups": []}
        cfg = _fake_settings(access_groups="")
        with _auth_patches(payload=payload, cfg=cfg):
            result = await require_auth(_creds())
        assert result["groups"] == []

    async def test_user_in_access_group_allowed(self):
        payload = {"sub": "alice", "groups": ["dep1"]}
        cfg = _fake_settings(access_groups="dep1,dep2")
        with _auth_patches(payload=payload, cfg=cfg):
            result = await require_auth(_creds())
        assert result["sub"] == "alice"

    async def test_user_in_one_of_multiple_access_groups_allowed(self):
        payload = {"sub": "alice", "groups": ["dep2", "other"]}
        cfg = _fake_settings(access_groups="dep1,dep2")
        with _auth_patches(payload=payload, cfg=cfg):
            result = await require_auth(_creds())
        assert result["sub"] == "alice"


# ---------------------------------------------------------------------------
# require_auth — 403 cases
# ---------------------------------------------------------------------------

class TestRequireAuth403:
    async def test_user_not_in_access_groups_raises_403(self):
        payload = {"sub": "alice", "groups": ["random_group"]}
        cfg = _fake_settings(access_groups="dep1,dep2")
        with _auth_patches(payload=payload, cfg=cfg):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "Not authorized"

    async def test_no_groups_claim_raises_403_when_access_required(self):
        payload = {"sub": "alice"}
        cfg = _fake_settings(access_groups="dep1")
        with _auth_patches(payload=payload, cfg=cfg):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth(_creds())
        assert exc_info.value.status_code == 403

    async def test_empty_groups_raises_403_when_access_required(self):
        payload = {"sub": "alice", "groups": []}
        cfg = _fake_settings(access_groups="dep1")
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
        exc = HTTPException(status_code=401, detail="Token validation failed: unknown signing key")
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
