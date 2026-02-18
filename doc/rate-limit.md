# Rate Limiting — Chat-Proxy (Redis, OpenShift)

Cluster-wide rate limiting enforced by a shared Redis instance across all proxy pods.

> Related: [auth.md](auth.md) · [deploy.md](deploy.md)

---

## Table of Contents

1. [Tier Selection](#1-tier-selection)
2. [Limits](#2-limits)
3. [Redis Key Schema](#3-redis-key-schema)
4. [Policy Module](#4-policy-module-policypy)
5. [Rate Limiter](#5-rate-limiter-ratelimitpy)
6. [Handler Integration](#6-handler-integration)

---

## 1. Tier Selection

Tier is determined by the **highest-privilege group** the user belongs to (from the JWT `groups` claim):

1. User ∈ `TIER_MAX_GROUPS` → tier `max`
2. User ∈ `TIER_PRO_GROUPS` → tier `pro`
3. Otherwise → `DEFAULT_TIER` (default: `basic`)

**Example:** user groups `["dep1", "max_group"]` → access granted by `dep1`, tier `max` by `max_group`.

---

## 2. Limits

Configured entirely via environment variables — no redeploy needed to adjust limits.

| Tier | rpm (per user) | Concurrent (per user) | Env vars |
|---|---|---|---|
| basic | 10 | 1 | `RL_RPM_BASIC`, `RL_CONC_BASIC` |
| pro | 30 | 3 | `RL_RPM_PRO`, `RL_CONC_PRO` |
| max | 120 | 10 | `RL_RPM_MAX`, `RL_CONC_MAX` |

---

## 3. Redis Key Schema

| Limit type | Key pattern | TTL |
|---|---|---|
| Requests / minute | `rl:rpm:{tier}:{user}:{YYYYMMDDHHMM}` | 120 s |
| Concurrency | `rl:conc:{tier}:{user}` | 300 s (safety TTL) |

**Algorithm — requests/min (fixed window):**

1. `INCR key`
2. If value == 1 → `EXPIRE key 120`
3. If value > limit → return `429`

**Algorithm — concurrency:**

1. On request start: `INCR key`, set `EXPIRE 300` if first
2. If value > limit → `DECR key`, return `429`
3. On request end (`finally`): `DECR key`

The 300 s safety TTL on concurrency keys prevents stuck slots if a pod crashes mid-request.
It must be longer than the maximum upstream LLM response time.

---

## 4. Policy Module (`policy.py`)

```python
import os
from fastapi import HTTPException

def _csv_set(name: str) -> set[str]:
    return {x.strip() for x in os.getenv(name, "").split(",") if x.strip()}

ACCESS = _csv_set("ACCESS_GROUPS")
PRO    = _csv_set("TIER_PRO_GROUPS")
MAX    = _csv_set("TIER_MAX_GROUPS")

def ensure_access(user_groups: set[str]) -> None:
    if ACCESS and not (user_groups & ACCESS):
        raise HTTPException(status_code=403, detail="Not authorized")

def pick_tier(user_groups: set[str]) -> str:
    if user_groups & MAX:
        return "max"
    if user_groups & PRO:
        return "pro"
    return os.getenv("DEFAULT_TIER", "basic")

def limits_for_tier(tier: str) -> tuple[int, int]:
    t = tier.upper()
    rpm  = int(os.getenv(f"RL_RPM_{t}", "10"))
    conc = int(os.getenv(f"RL_CONC_{t}", "1"))
    return rpm, conc
```

---

## 5. Rate Limiter (`ratelimit.py`)

```python
import time
import redis.asyncio as redis
from fastapi import HTTPException

def _minute_bucket() -> str:
    return time.strftime("%Y%m%d%H%M", time.gmtime())

class RateLimiter:
    def __init__(self, r: redis.Redis):
        self.r = r

    async def check_rpm(self, tier: str, user: str, limit: int) -> None:
        key = f"rl:rpm:{tier}:{user}:{_minute_bucket()}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 120)
        if val > limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    async def acquire_conc(self, tier: str, user: str, limit: int) -> None:
        key = f"rl:conc:{tier}:{user}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 300)
        if val > limit:
            await self.r.decr(key)
            raise HTTPException(status_code=429, detail="Too many concurrent requests")

    async def release_conc(self, tier: str, user: str) -> None:
        try:
            await self.r.decr(f"rl:conc:{tier}:{user}")
        except Exception:
            pass
```

---

## 6. Handler Integration

App startup:

```python
import os
import redis.asyncio as redis
from ratelimit import RateLimiter

REDIS_URL  = os.getenv("REDIS_URL")
RL_ENABLED = os.getenv("RL_ENABLED", "true").lower() == "true"

redis_client = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
rl = RateLimiter(redis_client)
```

Inside the `/v1/chat` handler, after JWT validation:

```python
user   = claims["sub"]
groups = set(claims.get("groups", []))

ensure_access(groups)
tier = pick_tier(groups)
rpm_limit, conc_limit = limits_for_tier(tier)

if RL_ENABLED:
    await rl.check_rpm(tier, user, rpm_limit)
    await rl.acquire_conc(tier, user, conc_limit)

try:
    response = await forward_to_llm(request)
    return response
finally:
    if RL_ENABLED:
        await rl.release_conc(tier, user)
```
