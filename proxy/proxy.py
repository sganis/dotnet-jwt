# proxy/proxy.py
import logging

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import Response

import router
from config import settings

logger = logging.getLogger(__name__)

_STRIP_REQUEST_HEADERS  = {"authorization", "host", "content-length", "transfer-encoding"}
_STRIP_RESPONSE_HEADERS = {"transfer-encoding", "content-encoding", "content-length", "connection"}


async def forward(request: Request, user: dict) -> Response:
    path = str(request.url.path)
    is_embed = router.is_embed_path(path)

    # Select per-route limits.
    max_body = settings.embed_max_body_bytes if is_embed else settings.chat_max_body_bytes
    timeout = settings.embed_proxy_timeout if is_embed else settings.chat_proxy_timeout

    # Enforce body size limit before reading into memory.
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_body:
        raise HTTPException(status_code=413, detail="Request body too large")

    body = await request.body()
    if len(body) > max_body:
        raise HTTPException(status_code=413, detail="Request body too large")

    query = request.url.query
    upstream = router.upstream_url(path, settings)
    if query:
        upstream += f"?{query}"

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _STRIP_REQUEST_HEADERS
    }
    headers["x-orion-user"]   = user["sub"]
    # Semicolon-separated; commas are valid in AD group names.
    headers["x-orion-groups"] = ";".join(user["groups"])

    async with httpx.AsyncClient(timeout=timeout) as client:
        upstream_resp = await client.request(
            method=request.method,
            url=upstream,
            headers=headers,
            content=body,
        )

    if upstream_resp.status_code >= 500:
        logger.error(
            "Upstream error %s for %s %s (user=%s)",
            upstream_resp.status_code, request.method, path, user["sub"],
        )

    resp_headers = {
        k: v
        for k, v in upstream_resp.headers.items()
        if k.lower() not in _STRIP_RESPONSE_HEADERS
    }

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )
