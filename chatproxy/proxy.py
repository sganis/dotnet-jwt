# chatproxy/proxy.py
import httpx
from fastapi import Request
from fastapi.responses import Response

from config import settings

_STRIP_REQUEST_HEADERS = {"authorization", "host", "content-length", "transfer-encoding"}


async def forward(request: Request, user: dict) -> Response:
    path = str(request.url.path)
    query = request.url.query
    upstream = settings.llm_backend_url.rstrip("/") + path
    if query:
        upstream += f"?{query}"

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _STRIP_REQUEST_HEADERS
    }
    headers["x-orion-user"] = user["sub"]
    headers["x-orion-roles"] = ",".join(user["roles"])

    body = await request.body()

    async with httpx.AsyncClient(timeout=120.0) as client:
        upstream_resp = await client.request(
            method=request.method,
            url=upstream,
            headers=headers,
            content=body,
        )

    # strip hop-by-hop headers that must not be forwarded
    _STRIP_RESPONSE_HEADERS = {
        "transfer-encoding", "content-encoding", "content-length", "connection"
    }
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
