# proxy/main.py
import logging
import logging.config
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Request
from fastapi.responses import Response

import proxy
from auth import require_auth
from config import settings
from ratelimit import RateLimiter, limits_for_tier, pick_tier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
)
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

    # Shared HTTP client — connection pools are reused across all proxy requests.
    app.state.http_client = httpx.AsyncClient()
    logger.info("HTTP client initialised")

    if settings.redis_url:
        _redis = aioredis.from_url(
            settings.redis_url, encoding="utf-8", decode_responses=True
        )
        await _redis.ping()  # Fail fast if Redis is unreachable at startup.
        _rl = RateLimiter(_redis)
        logger.info("Redis rate limiter connected: %s", settings.redis_url)

    yield

    await app.state.http_client.aclose()
    if _redis:
        await _redis.aclose()


app = FastAPI(title="Orion Proxy", version="1.0.0", lifespan=lifespan)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Propagate or generate an X-Request-ID header for end-to-end tracing."""
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["x-request-id"] = req_id
    return response


async def _forward_with_limits(request: Request, user: dict[str, Any]) -> Response:
    remaining: int | None = None
    reset: int | None = None
    tier: str | None = None
    if settings.rl_enabled and _rl:
        groups = set(user["groups"])
        tier = pick_tier(groups, settings.tier_max_set, settings.tier_pro_set, settings.default_tier)
        lim = limits_for_tier(tier, settings)
        remaining = await _rl.check_rpm(tier, user["sub"], lim.rpm)
        reset = 60 - (int(time.time()) % 60)
        await _rl.acquire_conc(tier, user["sub"], lim.conc)
    try:
        response = await proxy.forward(request, user)
        if remaining is not None:
            response.headers["ratelimit-remaining"] = str(remaining)
            response.headers["ratelimit-reset"] = str(reset)
        return response
    finally:
        if settings.rl_enabled and _rl and tier is not None:
            await _rl.release_conc(tier, user["sub"])


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
async def catchall(
    path: str,
    request: Request,
    user: dict[str, Any] = Depends(require_auth),
) -> Response:
    return await _forward_with_limits(request, user)
