# proxy/router.py
_EMBED_PREFIX = "/v1/embeddings"


def is_embed_path(path: str) -> bool:
    """Return True if the request path targets the embed backend."""
    return path == _EMBED_PREFIX or path.startswith(_EMBED_PREFIX + "/")


def upstream_url(path: str, settings) -> str:
    """Resolve the upstream backend URL for the given request path.

    /v1/embeddings (and sub-paths) → embed_backend_url
    everything else                → chat_backend_url
    """
    base = settings.embed_backend_url if is_embed_path(path) else settings.chat_backend_url
    return base.rstrip("/") + path
