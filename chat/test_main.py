# chat/test_main.py
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException
from fastapi.responses import Response

import main
from auth import require_auth
from main import _forward_with_limits, app, lifespan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_USER = {"sub": "alice", "groups": ["dep1"]}
FAKE_MAX_USER = {"sub": "bob", "groups": ["dep1", "max_group"]}


def _ok_response():
    return Response(content=b'{"ok":true}', status_code=200, media_type="application/json")


def _mock_rl(rpm_raises=None, conc_raises=None):
    rl = MagicMock()
    rl.check_rpm = AsyncMock(side_effect=rpm_raises)
    rl.acquire_conc = AsyncMock(side_effect=conc_raises)
    rl.release_conc = AsyncMock()
    return rl


def _fake_settings(**overrides):
    base = dict(
        rl_enabled=True,
        tier_max_set={"max_group"},
        tier_pro_set={"pro_group"},
        default_tier="basic",
        rl_rpm_basic=10,
        rl_rpm_pro=30,
        rl_rpm_max=120,
        rl_conc_basic=1,
        rl_conc_pro=3,
        rl_conc_max=10,
        redis_url=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _mock_redis():
    r = AsyncMock()
    r.ping = AsyncMock(return_value=True)
    return r


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_state():
    main._rl = None
    main._redis = None
    app.dependency_overrides.clear()
    yield
    main._rl = None
    main._redis = None
    app.dependency_overrides.clear()


@pytest.fixture
async def client():
    app.dependency_overrides[require_auth] = lambda: FAKE_USER
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


@pytest.fixture
async def anon_client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

class TestHealth:
    async def test_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_no_auth_required(self, anon_client):
        resp = await anon_client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Request ID middleware
# ---------------------------------------------------------------------------

class TestRequestId:
    async def test_request_id_added_to_response(self, client):
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())):
            resp = await client.post("/v1/chat/completions", content=b"{}")
        assert "x-request-id" in resp.headers

    async def test_existing_request_id_propagated(self, client):
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())):
            resp = await client.post(
                "/v1/chat/completions", content=b"{}", headers={"x-request-id": "my-trace-id"}
            )
        assert resp.headers["x-request-id"] == "my-trace-id"


# ---------------------------------------------------------------------------
# /v1/chat
# ---------------------------------------------------------------------------

class TestChat:
    async def test_forwards_proxy_response(self, client):
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())):
            resp = await client.post("/v1/chat/completions", content=b"{}")
        assert resp.status_code == 200

    async def test_requires_auth(self, anon_client):
        resp = await anon_client.post("/v1/chat/completions")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /v1/{path:path} catchall
# ---------------------------------------------------------------------------

class TestCatchall:
    @pytest.mark.parametrize("method,path", [
        ("GET", "/v1/models"),
        ("POST", "/v1/completions"),
        ("DELETE", "/v1/sessions/abc"),
        ("PUT", "/v1/resource/1"),
        ("PATCH", "/v1/resource/1"),
    ])
    async def test_method_and_path_routed(self, client, method, path):
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())):
            resp = await client.request(method, path)
        assert resp.status_code == 200

    async def test_requires_auth(self, anon_client):
        resp = await anon_client.get("/v1/models")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# _forward_with_limits
# ---------------------------------------------------------------------------

class TestForwardWithLimits:
    # -- bypass cases --------------------------------------------------------

    async def test_no_rl_skips_rate_limiting(self):
        fwd = AsyncMock(return_value=_ok_response())
        with patch("proxy.forward", fwd):
            await _forward_with_limits(MagicMock(), FAKE_USER)
        fwd.assert_awaited_once()

    async def test_rl_disabled_skips_even_with_limiter(self):
        rl = _mock_rl()
        main._rl = rl
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())), \
             patch("main.settings", _fake_settings(rl_enabled=False)):
            await _forward_with_limits(MagicMock(), FAKE_USER)
        rl.check_rpm.assert_not_awaited()
        rl.acquire_conc.assert_not_awaited()
        rl.release_conc.assert_not_awaited()

    # -- happy path ----------------------------------------------------------

    async def test_rpm_and_conc_checked_on_success(self):
        rl = _mock_rl()
        main._rl = rl
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())), \
             patch("main.settings", _fake_settings()):
            await _forward_with_limits(MagicMock(), FAKE_USER)
        rl.check_rpm.assert_awaited_once()
        rl.acquire_conc.assert_awaited_once()

    async def test_release_called_on_success(self):
        rl = _mock_rl()
        main._rl = rl
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())), \
             patch("main.settings", _fake_settings()):
            await _forward_with_limits(MagicMock(), FAKE_USER)
        rl.release_conc.assert_awaited_once_with("basic", "alice")

    async def test_basic_tier_limits_passed_for_plain_user(self):
        rl = _mock_rl()
        main._rl = rl
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())), \
             patch("main.settings", _fake_settings()):
            await _forward_with_limits(MagicMock(), FAKE_USER)
        rl.check_rpm.assert_awaited_once_with("basic", "alice", 10)
        rl.acquire_conc.assert_awaited_once_with("basic", "alice", 1)

    async def test_max_tier_limits_passed_for_max_user(self):
        rl = _mock_rl()
        main._rl = rl
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())), \
             patch("main.settings", _fake_settings()):
            await _forward_with_limits(MagicMock(), FAKE_MAX_USER)
        rl.check_rpm.assert_awaited_once_with("max", "bob", 120)
        rl.acquire_conc.assert_awaited_once_with("max", "bob", 10)

    # -- proxy raises --------------------------------------------------------

    async def test_release_called_when_proxy_raises(self):
        rl = _mock_rl()
        main._rl = rl
        with patch("proxy.forward", AsyncMock(side_effect=RuntimeError("upstream down"))), \
             patch("main.settings", _fake_settings()):
            with pytest.raises(RuntimeError):
                await _forward_with_limits(MagicMock(), FAKE_USER)
        rl.release_conc.assert_awaited_once()

    async def test_proxy_exception_propagates(self):
        rl = _mock_rl()
        main._rl = rl
        with patch("proxy.forward", AsyncMock(side_effect=RuntimeError("boom"))), \
             patch("main.settings", _fake_settings()):
            with pytest.raises(RuntimeError, match="boom"):
                await _forward_with_limits(MagicMock(), FAKE_USER)

    # -- rpm 429 -------------------------------------------------------------

    async def test_rpm_429_aborts_conc_and_release(self):
        rpm_exc = HTTPException(status_code=429, detail="Rate limit exceeded")
        rl = _mock_rl(rpm_raises=rpm_exc)
        main._rl = rl
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())), \
             patch("main.settings", _fake_settings()):
            with pytest.raises(HTTPException) as exc_info:
                await _forward_with_limits(MagicMock(), FAKE_USER)
        assert exc_info.value.status_code == 429
        rl.acquire_conc.assert_not_awaited()
        rl.release_conc.assert_not_awaited()

    # -- concurrency 429 -----------------------------------------------------

    async def test_conc_429_aborts_release(self):
        conc_exc = HTTPException(status_code=429, detail="Too many concurrent requests")
        rl = _mock_rl(conc_raises=conc_exc)
        main._rl = rl
        with patch("proxy.forward", AsyncMock(return_value=_ok_response())), \
             patch("main.settings", _fake_settings()):
            with pytest.raises(HTTPException) as exc_info:
                await _forward_with_limits(MagicMock(), FAKE_USER)
        assert exc_info.value.status_code == 429
        rl.release_conc.assert_not_awaited()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

class TestLifespan:
    async def test_no_redis_url_rl_stays_none(self):
        with patch("main.settings", _fake_settings(rl_enabled=False, redis_url=None)):
            async with lifespan(app):
                assert main._rl is None

    async def test_rl_enabled_without_redis_url_raises(self):
        with patch("main.settings", _fake_settings(rl_enabled=True, redis_url=None)):
            with pytest.raises(RuntimeError, match="REDIS_URL"):
                async with lifespan(app):
                    pass

    async def test_redis_url_creates_rate_limiter(self):
        mock_redis = _mock_redis()
        with patch("main.settings", _fake_settings(redis_url="redis://localhost:6379/0")), \
             patch("main.aioredis.from_url", return_value=mock_redis):
            async with lifespan(app):
                assert main._rl is not None

    async def test_from_url_called_with_redis_url(self):
        mock_redis = _mock_redis()
        from_url = MagicMock(return_value=mock_redis)
        with patch("main.settings", _fake_settings(redis_url="redis://myhost:6379/1")), \
             patch("main.aioredis.from_url", from_url):
            async with lifespan(app):
                pass
        from_url.assert_called_once()
        assert from_url.call_args[0][0] == "redis://myhost:6379/1"

    async def test_redis_pinged_at_startup(self):
        mock_redis = _mock_redis()
        with patch("main.settings", _fake_settings(redis_url="redis://localhost:6379/0")), \
             patch("main.aioredis.from_url", return_value=mock_redis):
            async with lifespan(app):
                pass
        mock_redis.ping.assert_awaited_once()

    async def test_shutdown_closes_redis(self):
        mock_redis = _mock_redis()
        with patch("main.settings", _fake_settings(redis_url="redis://localhost:6379/0")), \
             patch("main.aioredis.from_url", return_value=mock_redis):
            async with lifespan(app):
                pass
        mock_redis.aclose.assert_awaited_once()

    async def test_no_redis_url_no_close_on_shutdown(self):
        with patch("main.settings", _fake_settings(rl_enabled=False, redis_url=None)), \
             patch("main.aioredis.from_url") as from_url_mock:
            async with lifespan(app):
                pass
        from_url_mock.assert_not_called()
