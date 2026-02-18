# OpenShift Deployment — Chat + Redis

> Related: [auth.md](auth.md) · [rate-limit.md](rate-limit.md)

---

## Table of Contents

1. [Chat Environment Variables](#1-chat-proxy-environment-variables)
2. [Redis](#2-redis)
3. [NetworkPolicy](#3-networkpolicy)
4. [Pod Scaling](#4-pod-scaling)
5. [Acceptance Criteria](#5-acceptance-criteria)

---

## 1. Chat Environment Variables

```bash
# JWT validation
JWT_ISSUER=https://seecloud-iis.company.local
JWT_AUDIENCE=orion-chat-proxy
JWKS_URL=https://seecloud-iis.company.local/.well-known/jwks.json

# Access control (comma-separated AD group short names)
ACCESS_GROUPS=dep1,dep2,team-ai
TIER_PRO_GROUPS=pro_group
TIER_MAX_GROUPS=max_group
DEFAULT_TIER=basic

# Rate limiting
RL_ENABLED=true
REDIS_URL=redis://redis-rate-limit:6379/0
RL_RPM_BASIC=10    RL_CONC_BASIC=1
RL_RPM_PRO=30      RL_CONC_PRO=3
RL_RPM_MAX=120     RL_CONC_MAX=10
```

---

## 2. Redis

- Service name: `redis-rate-limit`
- In-cluster URL: `redis://redis-rate-limit:6379/0`
- Persistence: not required — rate-limit counters reset on restart (acceptable)
- Deploy using any standard Redis chart, operator, or a simple `Deployment + Service`

---

## 3. NetworkPolicy

```
Chat pods  →  redis-rate-limit:6379   (rate limit store)
Chat pods  →  LLM-Backend             (inference)
Chat pods  →  SEECloud-IIS:443        (JWKS public key fetch)
```

- No public route to LLM-Backend — only Chat is exposed via an OpenShift Route
- No public route to Redis

---

## 4. Pod Scaling

Chat is fully stateless. Scale replicas freely — Redis enforces all limits globally across pods.

Operational guardrails:

- Set an upstream timeout (e.g., 120 s) so concurrency slots are not held open by hung LLM requests
- Redis concurrency key TTL (300 s) must exceed the maximum LLM response time
- Never log `Authorization` headers

---

## 5. Acceptance Criteria

**Authentication**
- [ ] Domain user gets a JWT silently (no browser, no password prompt)
- [ ] JWT contains correct `groups` claim from AD

**Access control**
- [ ] User in `ACCESS_GROUPS` can reach the LLM
- [ ] User not in any `ACCESS_GROUPS` receives `403`

**Rate limiting**
- [ ] `basic` tier: 11th request in a minute receives `429`
- [ ] `basic` tier: 2nd concurrent request receives `429`
- [ ] Limits hold across multiple proxy pods (Redis-backed)
- [ ] Redis restart resets counters — limits resume on next request

**Isolation**
- [ ] LLM backend is unreachable directly (NetworkPolicy enforced)
- [ ] `Authorization` header is never forwarded to LLM or written to logs
