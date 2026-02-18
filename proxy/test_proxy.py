# proxy/test_proxy.py
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.responses import Response

import proxy

FAKE_USER = {"sub": "alice", "groups": ["dep1"]}

CHAT_BACKEND = "http://chat:8000"
EMBED_BACKEND = "http://embed:8000"


def _fake_settings(**overrides):
    base = dict(
        chat_backend_url=CHAT_BACKEND,
        embed_backend_url=EMBED_BACKEND,
        chat_proxy_timeout=120.0,
        embed_proxy_timeout=30.0,
        chat_max_body_bytes=10 * 1024 * 1024,
        embed_max_body_bytes=1 * 1024 * 1024,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _mock_http_client(upstream_resp):
    """Return a mock AsyncClient whose .request() returns upstream_resp."""
    client = AsyncMock()
    client.request = AsyncMock(return_value=upstream_resp)
    return client


def _mock_request(path: str, body: bytes = b"{}", method: str = "POST", query: str = ""):
    req = MagicMock()
    req.url.path = path
    req.url.query = query
    req.method = method
    req.headers = {}
    req.body = AsyncMock(return_value=body)
    # Provide a default mock client; override via req.app.state.http_client in tests
    # that need to inspect call args or control the upstream response.
    req.app.state.http_client = AsyncMock()
    req.app.state.http_client.request = AsyncMock()
    return req


def _upstream_response(status: int = 200, body: bytes = b'{"ok":true}') -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.headers = {"content-type": "application/json"}
    return resp


# ---------------------------------------------------------------------------
# Routing — correct backend selected by path
# ---------------------------------------------------------------------------

class TestRouting:
    async def test_chat_path_goes_to_chat_backend(self):
        cfg = _fake_settings()
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/chat/completions")
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        called_url = inner.request.call_args[1]["url"]
        assert called_url.startswith(CHAT_BACKEND)

    async def test_embed_path_goes_to_embed_backend(self):
        cfg = _fake_settings()
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/embeddings")
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        called_url = inner.request.call_args[1]["url"]
        assert called_url.startswith(EMBED_BACKEND)

    async def test_models_path_goes_to_chat_backend(self):
        cfg = _fake_settings()
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/models", method="GET")
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        called_url = inner.request.call_args[1]["url"]
        assert called_url.startswith(CHAT_BACKEND)


# ---------------------------------------------------------------------------
# Per-route timeouts — timeout is now passed per-request, not to the constructor
# ---------------------------------------------------------------------------

class TestTimeout:
    async def test_chat_path_uses_chat_timeout(self):
        cfg = _fake_settings(chat_proxy_timeout=90.0, embed_proxy_timeout=15.0)
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/chat/completions")
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        assert inner.request.call_args[1]["timeout"] == 90.0

    async def test_embed_path_uses_embed_timeout(self):
        cfg = _fake_settings(chat_proxy_timeout=90.0, embed_proxy_timeout=15.0)
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/embeddings")
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        assert inner.request.call_args[1]["timeout"] == 15.0


# ---------------------------------------------------------------------------
# Body size limits
# ---------------------------------------------------------------------------

class TestBodySizeLimit:
    async def test_chat_body_too_large_raises_413(self):
        cfg = _fake_settings(chat_max_body_bytes=100)
        req = _mock_request("/v1/chat/completions", body=b"x" * 101)
        req.headers = {"content-length": "101"}

        with patch("proxy.settings", cfg):
            with pytest.raises(HTTPException) as exc_info:
                await proxy.forward(req, FAKE_USER)
        assert exc_info.value.status_code == 413

    async def test_embed_body_too_large_raises_413(self):
        cfg = _fake_settings(embed_max_body_bytes=50)
        req = _mock_request("/v1/embeddings", body=b"x" * 51)
        req.headers = {"content-length": "51"}

        with patch("proxy.settings", cfg):
            with pytest.raises(HTTPException) as exc_info:
                await proxy.forward(req, FAKE_USER)
        assert exc_info.value.status_code == 413

    async def test_embed_limit_does_not_apply_to_chat(self):
        """A body that exceeds embed limit is fine for chat (uses chat limit)."""
        cfg = _fake_settings(chat_max_body_bytes=10 * 1024 * 1024, embed_max_body_bytes=50)
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        body = b"x" * 100  # over embed limit, under chat limit
        req = _mock_request("/v1/chat/completions", body=body)
        req.headers = {"content-length": str(len(body))}
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            resp = await proxy.forward(req, FAKE_USER)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Header handling
# ---------------------------------------------------------------------------

class TestHeaders:
    async def test_authorization_header_stripped(self):
        cfg = _fake_settings()
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/chat/completions")
        req.headers = {"authorization": "Bearer secret", "content-type": "application/json"}
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        sent_headers = inner.request.call_args[1]["headers"]
        assert "authorization" not in {k.lower() for k in sent_headers}

    async def test_audit_headers_injected(self):
        cfg = _fake_settings()
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/chat/completions")
        req.headers = {}
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        sent_headers = inner.request.call_args[1]["headers"]
        assert sent_headers["x-orion-user"] == "alice"
        assert sent_headers["x-orion-groups"] == "dep1"

    async def test_query_string_appended(self):
        cfg = _fake_settings()
        upstream_resp = _upstream_response()
        inner = _mock_http_client(upstream_resp)
        req = _mock_request("/v1/models", query="limit=5", method="GET")
        req.app.state.http_client = inner

        with patch("proxy.settings", cfg):
            await proxy.forward(req, FAKE_USER)

        called_url = inner.request.call_args[1]["url"]
        assert "?limit=5" in called_url
