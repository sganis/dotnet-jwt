# proxy/test_router.py
from types import SimpleNamespace

import pytest

from router import is_embed_path, upstream_url


def _settings(chat="http://chat:8000", embed="http://embed:8000"):
    return SimpleNamespace(chat_backend_url=chat, embed_backend_url=embed)


# ---------------------------------------------------------------------------
# is_embed_path
# ---------------------------------------------------------------------------

class TestIsEmbedPath:
    def test_embeddings_exact(self):
        assert is_embed_path("/v1/embeddings") is True

    def test_embeddings_subpath(self):
        assert is_embed_path("/v1/embeddings/batch") is True

    def test_chat_completions_is_not_embed(self):
        assert is_embed_path("/v1/chat/completions") is False

    def test_models_is_not_embed(self):
        assert is_embed_path("/v1/models") is False

    def test_root_is_not_embed(self):
        assert is_embed_path("/v1/embeddings-extra") is False

    def test_health_is_not_embed(self):
        assert is_embed_path("/health") is False


# ---------------------------------------------------------------------------
# upstream_url
# ---------------------------------------------------------------------------

class TestUpstreamUrl:
    def test_embeddings_path_uses_embed_backend(self):
        cfg = _settings(embed="http://embed:8000")
        url = upstream_url("/v1/embeddings", cfg)
        assert url == "http://embed:8000/v1/embeddings"

    def test_chat_path_uses_chat_backend(self):
        cfg = _settings(chat="http://chat:8000")
        url = upstream_url("/v1/chat/completions", cfg)
        assert url == "http://chat:8000/v1/chat/completions"

    def test_models_path_uses_chat_backend(self):
        cfg = _settings(chat="http://chat:8000")
        url = upstream_url("/v1/models", cfg)
        assert url == "http://chat:8000/v1/models"

    def test_trailing_slash_on_backend_url_stripped(self):
        cfg = _settings(chat="http://chat:8000/")
        url = upstream_url("/v1/models", cfg)
        assert url == "http://chat:8000/v1/models"

    def test_embed_subpath_uses_embed_backend(self):
        cfg = _settings(embed="http://embed:8000")
        url = upstream_url("/v1/embeddings/batch", cfg)
        assert url == "http://embed:8000/v1/embeddings/batch"

    def test_different_backends_dont_cross(self):
        cfg = _settings(chat="http://chat:8001", embed="http://embed:8002")
        assert "8002" in upstream_url("/v1/embeddings", cfg)
        assert "8001" in upstream_url("/v1/chat/completions", cfg)
