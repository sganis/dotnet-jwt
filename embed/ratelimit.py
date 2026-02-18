# embed/ratelimit.py
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import HTTPException

if TYPE_CHECKING:
    import redis.asyncio as aioredis
    from config import Settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Limits:
    rpm: int
    conc: int


def pick_tier(
    user_groups: set[str],
    max_groups: set[str],
    pro_groups: set[str],
    default: str,
) -> str:
    """Return the highest rate-limit tier the user qualifies for."""
    if user_groups & max_groups:
        return "max"
    if user_groups & pro_groups:
        return "pro"
    return default


def limits_for_tier(tier: str, cfg: "Settings") -> Limits:
    """Return Limits for the given tier, reading values from Settings."""
    t = tier.lower()
    if t == "max":
        return Limits(rpm=cfg.rl_rpm_max, conc=cfg.rl_conc_max)
    if t == "pro":
        return Limits(rpm=cfg.rl_rpm_pro, conc=cfg.rl_conc_pro)
    return Limits(rpm=cfg.rl_rpm_basic, conc=cfg.rl_conc_basic)


def minute_bucket(ts: float) -> str:
    """Return a fixed-window bucket string for the given timestamp (UTC)."""
    return time.strftime("%Y%m%d%H%M", time.gmtime(ts))


class RateLimiter:
    def __init__(self, r: "aioredis.Redis") -> None:
        self.r = r

    async def check_rpm(self, tier: str, user: str, limit: int) -> None:
        """Increment the per-user per-minute counter; raise 429 if over limit."""
        bucket = minute_bucket(time.time())
        key = f"rl:rpm:{tier}:{user}:{bucket}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 120)
        if val > limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    async def acquire_conc(self, tier: str, user: str, limit: int) -> None:
        """Increment concurrency counter; raise 429 and rollback if over limit."""
        key = f"rl:conc:{tier}:{user}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 300)
        if val > limit:
            await self.r.decr(key)
            raise HTTPException(status_code=429, detail="Too many concurrent requests")

    async def release_conc(self, tier: str, user: str) -> None:
        """Decrement concurrency counter; logs but does not re-raise on Redis errors."""
        key = f"rl:conc:{tier}:{user}"
        try:
            await self.r.decr(key)
        except Exception as exc:
            logger.error("release_conc failed for %s/%s: %s", tier, user, exc)
