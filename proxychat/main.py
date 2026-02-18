# proxychat/main.py
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Request

import proxy
from auth import require_auth
from config import settings
from ratelimit import RateLimiter, limits_for_tier, pick_tier

logger = logging.getLogger(__name__)

_rl: RateLimiter | None = None
_redis: aioredis.Redis | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _rl, _redis

    if settings.rl_enabled and not settings.redis_url:
        raise RuntimeError(
            "RL_ENABLED=true requires REDIS_URL to be configured. "
            "Set RL_ENABLED=false to run without rate limiting."
        )

    if settings.redis_url:
        _redis = aioredis.from_url(
            settings.redis_url, encoding="utf-8", decode_responses=True
        )
        await _redis.ping()  # Fail fast if Redis is unreachable at startup.
        _rl = RateLimiter(_redis)
        logger.info("Redis rate limiter connected: %s", settings.redis_url)

    yield

    if _redis:
        await _redis.aclose()


app = FastAPI(title="Orion Chat Proxy", version="1.0.0", lifespan=lifespan)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Propagate or generate an X-Request-ID header for end-to-end tracing."""
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["x-request-id"] = req_id
    return response


async def _forward_with_limits(request: Request, user: dict[str, Any]):
    tier: str | None = None
    if settings.rl_enabled and _rl:
        groups = set(user["groups"])
        tier = pick_tier(groups, settings.tier_max_set, settings.tier_pro_set, settings.default_tier)
        lim = limits_for_tier(tier, settings)
        await _rl.check_rpm(tier, user["sub"], lim.rpm)
        await _rl.acquire_conc(tier, user["sub"], lim.conc)
    try:
        return await proxy.forward(request, user)
    finally:
        if settings.rl_enabled and _rl and tier is not None:
            await _rl.release_conc(tier, user["sub"])


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
