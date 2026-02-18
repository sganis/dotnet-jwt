## Orion → SEECloud-IIS (Windows Auth) → OpenShift FastAPI Proxy → LLM

### With Windows Group-Based Authorization

---

# 1️⃣ Objective

Allow **ORION-DESKTOP** (native Windows app) to call the internal **LLM-BACKEND** using:

* Silent Windows authentication (no browser, no password)
* Bearer JWT tokens
* Authorization enforced by **Windows AD groups**
* Scalable OpenShift proxy
* No authentication on LLM service itself

---

# 2️⃣ Architecture Overview

### Components

1. **ORION-DESKTOP**

   * Windows executable
   * Uses Negotiate to get JWT
   * Sends Bearer token to proxy

2. **SEECLOUD-IIS**

   * Windows Authentication (Negotiate)
   * Validates AD user
   * Checks Windows group membership
   * Issues signed JWT

3. **CHAT-PROXY (FastAPI, OpenShift)**

   * Validates JWT
   * Enforces authorization via roles derived from AD groups
   * Forwards request to LLM
   * Returns response unchanged

4. **LLM-BACKEND**

   * Private service
   * Network protected only
   * No authentication

---

# 3️⃣ End-to-End Flow

### Step A — Token Issuance

```
ORION-DESKTOP
   → POST https://seeccloud-iis/desktop/token
     (Windows Negotiate auth)

SEECLOUD-IIS
   → Validates Windows user
   → Checks AD group membership
   → Issues signed JWT
```

Response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9....",
  "token_type": "Bearer",
  "expires_in": 14400
}
```

---

### Step B — Chat Request

```
ORION-DESKTOP
   → POST https://chat-proxy/v1/chat
     Authorization: Bearer <jwt>

CHAT-PROXY
   → Validate JWT
   → Authorize via roles
   → Forward to LLM

LLM-BACKEND
   → Process
   → Return response

CHAT-PROXY
   → Return response to Orion
```

---

# 4️⃣ Windows Group-Based Authorization (Authoritative Source = AD)

## AD Groups

Example:

* `CORP\LLM_CHAT_USERS`
* `CORP\LLM_CHAT_ADMINS`

These are the ONLY security groups controlling access.

---

# 5️⃣ SEECloud-IIS Responsibilities

### 1. Authenticate user via Windows Auth

Use:

* `HttpContext.User.Identity.Name`
* Validate group membership using AD

### 2. Map Windows Groups → Application Roles

| AD Group        | JWT Role  |
| --------------- | --------- |
| LLM_CHAT_USERS  | llm:user  |
| LLM_CHAT_ADMINS | llm:admin |

Only emit relevant roles.

---

## JWT Format (Required Claims)

### Header

* `alg`: RS256 (preferred)
* `kid`: key id

### Claims

```json
{
  "iss": "https://seeccloud-iis.company.local",
  "aud": "orion-chat-proxy",
  "sub": "CORP\\san",
  "roles": ["llm:user"],
  "iat": 1700000000,
  "exp": 1700003600
}
```

### Requirements

* Sign with RS256
* Publish public key via:

  * JWKS endpoint (preferred), or
  * Public certificate distributed to proxy

---

# 6️⃣ CHAT-PROXY Responsibilities

## A. Validate JWT

Must validate:

* Signature (RS256)
* `iss` matches expected issuer
* `aud` equals `orion-chat-proxy`
* `exp` not expired
* `iat` present

Reject with `401` if invalid.

---

## B. Authorize via Roles

Allowed roles:

```
llm:user
llm:admin
```

If token does not contain at least one allowed role → `403`.

---

## C. Forward Request to LLM

* Remove Authorization header
* Forward body, method, query params
* Add identity headers for audit:

```
x-orion-user: CORP\san
x-orion-roles: llm:user
```

Return upstream response unchanged.

---

# 7️⃣ FastAPI Authorization Logic (Final Version)

```python
ALLOWED_ROLES = {"llm:user", "llm:admin"}

roles = claims.get("roles", [])
if isinstance(roles, str):
    roles = [roles]

if not any(role in ALLOWED_ROLES for role in roles):
    raise HTTPException(status_code=403, detail="Not authorized")
```

---

# 8️⃣ OpenShift Requirements

### Deployment

* Multiple replicas (stateless)
* No session storage required

### Networking

* Route only to CHAT-PROXY
* No public route to LLM-BACKEND
* NetworkPolicy:

  * Allow CHAT-PROXY → LLM
  * Allow CHAT-PROXY → SEECloud-IIS (if JWKS needed)

---

# 9️⃣ Token Lifetime Strategy

If “hours” required:

Option A (recommended):

* 30-minute JWT
* Orion silently re-requests from IIS via Negotiate

Option B:

* 4-hour JWT
* Ensure Authorization headers are never logged

---

# 🔟 Security Boundaries

| Component         | Responsibility                   |
| ----------------- | -------------------------------- |
| SEECloud-IIS      | Authentication + role assignment |
| CHAT-PROXY        | Token validation + authorization |
| LLM               | Compute only                     |
| OpenShift Network | Isolation                        |

---

# 11️⃣ Final Authorization Model

Authorization source of truth = **Active Directory groups**

* Add/remove users from AD groups
* No changes needed in OpenShift
* No redeploy required
* No token changes needed

---

# 12️⃣ Why This Is Correct for Orion

* Uses native Windows trust
* No browser complexity
* No ADFS redirect flows
* Scales in OpenShift
* Keeps LLM private
* Clear separation of auth vs compute
* Centralized access control via AD groups

---

# 13️⃣ Acceptance Criteria

✅ Domain Windows user can get JWT silently
✅ Only members of `LLM_CHAT_USERS` can access LLM
✅ Non-members receive 403
✅ Proxy scales across pods
✅ LLM remains inaccessible directly



# HANDOFF — Rate Limiting in CHAT-PROXY (FastAPI) using Redis on OpenShift

## Goal

Add **cluster-wide rate limiting** to **CHAT-PROXY** (multi-pod) using a shared **Redis** service in OpenShift.

Enforce limits **by AD-derived role** from JWT (`roles` claim), with optional per-user and concurrency limits.

---

## 1) Policy (defaults)

### Roles (from JWT)

* `llm:admin`
* `llm:user`

### Limits

| Role      | Requests / minute (per user) | Concurrent requests (per user) |
| --------- | ---------------------------- | ------------------------------ |
| llm:admin | 120                          | 10                             |
| llm:user  | 30                           | 3                              |

Notes:

* Apply **per user** limits (most important).
* Optionally add a **global per-role** cap later if needed.

---

## 2) Redis in OpenShift

### Redis service name

* `redis-rate-limit`

### Connection string (in-cluster)

* `redis://redis-rate-limit:6379/0`

### Minimal deployment approach

Use any standard Redis chart/operator or a simple Deployment+Service.
Persistence is optional for rate limiting.

---

## 3) CHAT-PROXY environment variables

Add:

* `REDIS_URL=redis://redis-rate-limit:6379/0`
* `RL_ENABLED=true`

Optional overrides:

* `RL_USER_RPM_ADMIN=120`
* `RL_USER_RPM_USER=30`
* `RL_CONC_ADMIN=10`
* `RL_CONC_USER=3`

---

## 4) Algorithm (simple + correct across pods)

### A) Requests/minute (per user) — fixed window (per minute)

Redis key:

* `rl:rpm:{role}:{user}:{YYYYMMDDHHMM}`

Implementation:

* `INCR key`
* If first time, `EXPIRE key 120`
* If count > limit → reject `429`

This is extremely simple, fast, and good enough for LLM protection.

### B) Concurrency (per user)

Redis key:

* `rl:conc:{user}`

Implementation:

* on request start: `INCR`, set `EXPIRE` safety TTL (e.g., 300s)
* if value > limit → `DECR` and reject `429`
* on request end (finally): `DECR`

This prevents one user from occupying all LLM workers.

---

## 5) FastAPI implementation (drop-in)

### Dependencies

Add to `requirements.txt`:

* `redis>=5.0.0`  (redis-py)
* `httpx`
* `pyjwt[crypto]`
* `fastapi`
* `uvicorn`

### `rate_limit.py`

```python
import os
import time
from dataclasses import dataclass
from typing import Iterable, Tuple

import redis.asyncio as redis
from fastapi import HTTPException

@dataclass(frozen=True)
class Limits:
    rpm: int
    conc: int

def pick_role(roles: Iterable[str]) -> str:
    # Highest privilege wins
    s = set(roles)
    if "llm:admin" in s:
        return "llm:admin"
    if "llm:user" in s:
        return "llm:user"
    return "unknown"

def limits_for_role(role: str) -> Limits:
    if role == "llm:admin":
        return Limits(
            rpm=int(os.getenv("RL_USER_RPM_ADMIN", "120")),
            conc=int(os.getenv("RL_CONC_ADMIN", "10")),
        )
    # default to user limits
    return Limits(
        rpm=int(os.getenv("RL_USER_RPM_USER", "30")),
        conc=int(os.getenv("RL_CONC_USER", "3")),
    )

def minute_bucket(ts: float) -> str:
    return time.strftime("%Y%m%d%H%M", time.gmtime(ts))

class RateLimiter:
    def __init__(self, r: "redis.Redis"):
        self.r = r

    async def check_and_incr_rpm(self, role: str, user: str, rpm_limit: int) -> None:
        bucket = minute_bucket(time.time())
        key = f"rl:rpm:{role}:{user}:{bucket}"
        # Atomic enough: INCR then set EXPIRE only if new
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 120)
        if val > rpm_limit:
            # Retry-After: until next minute boundary (rough)
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    async def acquire_concurrency(self, user: str, conc_limit: int) -> None:
        key = f"rl:conc:{user}"
        val = await self.r.incr(key)
        if val == 1:
            # Safety TTL in case of crashes; refreshed implicitly by activity
            await self.r.expire(key, 300)
        if val > conc_limit:
            await self.r.decr(key)
            raise HTTPException(status_code=429, detail="Too many concurrent requests")

    async def release_concurrency(self, user: str) -> None:
        key = f"rl:conc:{user}"
        # Best-effort; don't raise
        try:
            await self.r.decr(key)
        except Exception:
            pass
```

---

## 6) Wire it into CHAT-PROXY `/v1/chat`

In your `main.py`, after JWT validation + authorization:

```python
import os
import redis.asyncio as redis
from rate_limit import RateLimiter, pick_role, limits_for_role

REDIS_URL = os.getenv("REDIS_URL")
RL_ENABLED = os.getenv("RL_ENABLED", "true").lower() == "true"

redis_client = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True) if REDIS_URL else None
rl = RateLimiter(redis_client) if redis_client else None
```

Inside the handler, after you have `claims`, `user`, `roles`:

```python
role = pick_role(roles)
limits = limits_for_role(role)

if RL_ENABLED:
    if not rl:
        raise HTTPException(status_code=500, detail="Rate limiter not configured")
    await rl.check_and_incr_rpm(role=role, user=user, rpm_limit=limits.rpm)
    await rl.acquire_concurrency(user=user, conc_limit=limits.conc)

try:
    # call upstream LLM (existing code)
    upstream = await client.request(...)
    return Response(...)
finally:
    if RL_ENABLED and rl:
        await rl.release_concurrency(user=user)
```

---

## 7) OpenShift deployment notes

### A) Add Redis dependency

* Deploy Redis in same namespace (recommended).
* Create Service `redis-rate-limit`.

### B) Add env vars to CHAT-PROXY Deployment

* `REDIS_URL`
* `RL_ENABLED`
* optional limit overrides

### C) NetworkPolicy

Allow CHAT-PROXY pods to connect to Redis service on 6379.

---

## 8) Operational guardrails (recommended)

* Do **not** log Authorization headers.
* Add proxy timeouts to prevent stuck concurrency slots:

  * upstream timeout (e.g., 120s)
* Keep concurrency TTL safety (300s) > max request time.

---

## 9) Acceptance tests

1. Same user sends 31 requests/min with role `llm:user` → request 31 gets `429`.
2. Same user opens 4 concurrent requests with role `llm:user` → 4th gets `429`.
3. Two proxy pods: limits still apply globally (Redis-backed).
4. Redis restart: proxy continues; limits reset (acceptable).

---

## 10) Future improvements (optional)

* Add per-role global cap: `rl:role:{role}:{bucket}`
* Use Lua script for stricter atomicity (only if needed)
* Add `Retry-After` seconds precisely



# HANDOFF — Group-Based Access + Tiered Rate Limits in CHAT-PROXY (FastAPI) via Redis (OpenShift)

## Goal

Implement **simple, policy-driven** access control + rate limiting in **CHAT-PROXY** using:

* **Department / team AD groups** for **access**
* Separate **tier groups** (`pro_group`, `max_group`) for **rate limit level**
* **Redis** for **cluster-wide** enforcement across multiple pods

No “plans” system. No issuer-side plan logic. Chat-proxy owns policy.

---

## 1) Core Rule

### A) Access

User is allowed **if in any** group listed in `ACCESS_GROUPS`.

### B) Rate limit tier

Tier is chosen by **highest tier group** membership:

1. If user ∈ `TIER_MAX_GROUPS` → tier = `max`
2. Else if user ∈ `TIER_PRO_GROUPS` → tier = `pro`
3. Else → `DEFAULT_TIER` (e.g., `basic`)

Example:

* user groups = `["dep1", "max_group"]`

  * `dep1` grants access
  * `max_group` grants max rate limits

---

## 2) JWT Requirement (from issuer)

Issuer only needs to include **group membership** (already derived from Windows/AD).

### Required claim

* `groups`: array of group names, e.g.

```json
{
  "sub": "CORP\\san",
  "groups": ["dep1", "max_group"],
  "iat": 1700000000,
  "exp": 1700003600,
  "aud": "orion-chat-proxy",
  "iss": "https://seeccloud-iis.company.local"
}
```

Notes:

* Group strings can be short names (`dep1`) or full (`CORP\\dep1`). Chat-proxy must match whatever format you standardize on.
* If you currently only emit `roles`, you may reuse it, but **`groups` is clearer**.

---

## 3) Chat-Proxy Configuration (env vars)

### A) Group policy

```bash
ACCESS_GROUPS=dep1,dep2,team-ai
TIER_PRO_GROUPS=pro_group
TIER_MAX_GROUPS=max_group
DEFAULT_TIER=basic
```

### B) Tier limits

```bash
RL_RPM_BASIC=10
RL_CONC_BASIC=1

RL_RPM_PRO=30
RL_CONC_PRO=3

RL_RPM_MAX=120
RL_CONC_MAX=10
```

### C) Redis

```bash
REDIS_URL=redis://redis-rate-limit:6379/0
RL_ENABLED=true
```

---

## 4) Tier Selection & Access Check (drop-in)

```python
import os
from fastapi import HTTPException

def _csv_set(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {x.strip() for x in raw.split(",") if x.strip()}

ACCESS = _csv_set("ACCESS_GROUPS")
PRO = _csv_set("TIER_PRO_GROUPS")
MAX = _csv_set("TIER_MAX_GROUPS")

def ensure_access(user_groups: set[str]) -> None:
    if ACCESS and not (user_groups & ACCESS):
        raise HTTPException(status_code=403, detail="Not authorized")

def pick_tier(user_groups: set[str]) -> str:
    if user_groups & MAX:
        return "max"
    if user_groups & PRO:
        return "pro"
    return os.getenv("DEFAULT_TIER", "basic")
```

---

## 5) Limits Per Tier

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Limits:
    rpm: int
    conc: int

def limits_for_tier(tier: str) -> Limits:
    t = tier.upper()
    rpm = int(os.getenv(f"RL_RPM_{t}", "10"))
    conc = int(os.getenv(f"RL_CONC_{t}", "1"))
    return Limits(rpm=rpm, conc=conc)
```

---

## 6) Redis Rate Limiting (cluster-wide)

### Algorithm

A) **Requests/minute per user** (fixed 1-minute window, simple)

* key: `rl:rpm:{tier}:{user}:{YYYYMMDDHHMM}`
* `INCR`, if first set `EXPIRE 120`
* if value > limit → `429`

B) **Concurrency per user**

* key: `rl:conc:{tier}:{user}`
* `INCR`, if first set `EXPIRE 300`
* if value > limit → `DECR` then `429`
* on request end: `DECR` in `finally`

---

## 7) RateLimiter Module (async redis-py)

```python
import time
import redis.asyncio as redis
from fastapi import HTTPException

def minute_bucket(ts: float) -> str:
    return time.strftime("%Y%m%d%H%M", time.gmtime(ts))

class RateLimiter:
    def __init__(self, r: "redis.Redis"):
        self.r = r

    async def check_rpm(self, tier: str, user: str, rpm_limit: int) -> None:
        bucket = minute_bucket(time.time())
        key = f"rl:rpm:{tier}:{user}:{bucket}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 120)
        if val > rpm_limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    async def acquire_conc(self, tier: str, user: str, conc_limit: int) -> None:
        key = f"rl:conc:{tier}:{user}"
        val = await self.r.incr(key)
        if val == 1:
            await self.r.expire(key, 300)
        if val > conc_limit:
            await self.r.decr(key)
            raise HTTPException(status_code=429, detail="Too many concurrent requests")

    async def release_conc(self, tier: str, user: str) -> None:
        key = f"rl:conc:{tier}:{user}"
        try:
            await self.r.decr(key)
        except Exception:
            pass
```

---

## 8) Wire into `/v1/chat`

### Setup (app init)

```python
import os
import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL")
RL_ENABLED = os.getenv("RL_ENABLED", "true").lower() == "true"

redis_client = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
rl = RateLimiter(redis_client)
```

### Handler flow

After JWT validation, extract:

* `user = claims["sub"]`
* `groups = set(claims.get("groups", []))`

Then:

```python
ensure_access(groups)

tier = pick_tier(groups)
limits = limits_for_tier(tier)

if RL_ENABLED:
    await rl.check_rpm(tier=tier, user=user, rpm_limit=limits.rpm)
    await rl.acquire_conc(tier=tier, user=user, conc_limit=limits.conc)

try:
    # Forward to LLM (existing code)
    ...
finally:
    if RL_ENABLED:
        await rl.release_conc(tier=tier, user=user)
```

---

## 9) OpenShift Notes

### Redis

* Service name: `redis-rate-limit`
* No persistence required (limits can reset on restart)

### NetworkPolicy

Allow:

* CHAT-PROXY → Redis on 6379
* CHAT-PROXY → LLM-BACKEND

### Pod scaling

Because Redis is shared, limits work across all replicas.

---

## 10) Operational Guardrails

* Never log `Authorization` header.
* Set upstream timeout (e.g. 120s) so concurrency slots aren’t held forever.
* Concurrency TTL (300s) must be **> max request duration**.

---

## 11) Acceptance Tests

1. **Access**

* User groups = `["dep1"]` and `ACCESS_GROUPS` contains `dep1` → allowed
* User groups = `["random"]` → `403`

2. **Tier**

* User groups = `["dep1","pro_group"]` → tier `pro`
* User groups = `["dep1","max_group"]` → tier `max`
* User groups = `["dep1"]` only → tier `basic`

3. **Rate limit**

* Exceed rpm → `429`
* Exceed concurrency → `429`
* Multi-pod: limits still enforced globally

---

## 12) What to Configure (example)

* `ACCESS_GROUPS=dep1,dep2,team-ai`
* `TIER_PRO_GROUPS=pro_group`
* `TIER_MAX_GROUPS=max_group`
* `DEFAULT_TIER=basic`
* `RL_RPM_BASIC=10 RL_CONC_BASIC=1`
* `RL_RPM_PRO=30 RL_CONC_PRO=3`
* `RL_RPM_MAX=120 RL_CONC_MAX=10`

This exactly implements:

> “If user is in dep1 they have access, and if they are in max_group they have the max rate limit.”
