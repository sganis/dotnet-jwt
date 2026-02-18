# chatproxy/main.py
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Request

import proxy
from auth import require_auth
from config import settings
from ratelimit import RateLimiter, limits_for_role, pick_role

_rl: RateLimiter | None = None
_redis: aioredis.Redis | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _rl, _redis
    if settings.redis_url:
        _redis = aioredis.from_url(
            settings.redis_url, encoding="utf-8", decode_responses=True
        )
        _rl = RateLimiter(_redis)
    yield
    if _redis:
        await _redis.aclose()


app = FastAPI(title="Orion Chat Proxy", version="1.0.0", lifespan=lifespan)


async def _forward_with_limits(request: Request, user: dict[str, Any]):
    if settings.rl_enabled and _rl:
        role = pick_role(user["roles"])
        lim = limits_for_role(role, settings)
        await _rl.check_and_incr_rpm(role, user["sub"], lim.rpm)
        await _rl.acquire_concurrency(user["sub"], lim.conc)
    try:
        return await proxy.forward(request, user)
    finally:
        if settings.rl_enabled and _rl:
            await _rl.release_concurrency(user["sub"])


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/chat")
async def chat(request: Request, user: dict[str, Any] = Depends(require_auth)):
    return await _forward_with_limits(request, user)


@app.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
async def catchall(
    path: str,
    request: Request,
    user: dict[str, Any] = Depends(require_auth),
):
    return await _forward_with_limits(request, user)
