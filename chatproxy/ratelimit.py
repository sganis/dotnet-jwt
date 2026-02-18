# chatproxy/ratelimit.py
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

from fastapi import HTTPException

if TYPE_CHECKING:
    import redis.asyncio as aioredis
    from config import Settings


@dataclass(frozen=True)
class Limits:
    rpm: int
    conc: int


def pick_role(roles: Iterable[str]) -> str:
    """Return the highest-privilege role present in the token."""
    s = set(roles)
    if "llm:admin" in s:
        return "llm:admin"
    if "llm:user" in s:
        return "llm:user"
    return "unknown"


def limits_for_role(role: str, cfg: "Settings") -> Limits:
    """Return Limits for the given role, reading values from Settings."""
    if role == "llm:admin":
        return Limits(rpm=cfg.rl_user_rpm_admin, conc=cfg.rl_conc_admin)
    return Limits(rpm=cfg.rl_user_rpm_user, conc=cfg.rl_conc_user)


def minute_bucket(ts: float) -> str:
    """Return a fixed-window bucket string for the given timestamp (UTC)."""
    return time.strftime("%Y%m%d%H%M", time.gmtime(ts))


class RateLimiter:
    def __init__(self, r: "aioredis.Redis") -> None:
        self.r = r

    async def check_and_incr_rpm(self, role: str, user: str, limit: int) -> None:
        """Increment the per-user per-minute counter; raise 429 if over limit."""
        bucket = minute_bucket(time.time())
        key = f"rl:rpm:{role}:{user}:{bucket}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 120)
        if val > limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    async def acquire_concurrency(self, user: str, limit: int) -> None:
        """Increment concurrency counter; raise 429 and rollback if over limit."""
        key = f"rl:conc:{user}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 300)
        if val > limit:
            await self.r.decr(key)
            raise HTTPException(status_code=429, detail="Too many concurrent requests")

    async def release_concurrency(self, user: str) -> None:
        """Decrement concurrency counter; swallows exceptions for safety."""
        key = f"rl:conc:{user}"
        try:
            await self.r.decr(key)
        except Exception:
            pass
