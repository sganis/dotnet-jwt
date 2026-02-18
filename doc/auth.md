# Orion Auth — SEECloud-IIS → Chat-Proxy → LLM

Windows-authenticated JWT flow with group-based access control.

> Related: [rate-limit.md](rate-limit.md) · [deploy.md](deploy.md)

---

## Table of Contents

1. [Objective](#1-objective)
2. [Architecture](#2-architecture)
3. [End-to-End Flow](#3-end-to-end-flow)
4. [SEECloud-IIS — Token Issuer](#4-seecloud-iis--token-issuer)
5. [Chat-Proxy — Enforcer](#5-chat-proxy--enforcer)
6. [Token Lifetime](#6-token-lifetime)
7. [Security Boundaries](#7-security-boundaries)

---

## 1. Objective

Allow **Orion Desktop** (native Windows app) to call an internal **LLM backend** with:

- Silent Windows authentication — no browser, no password prompt
- Bearer JWT tokens passed to a stateless proxy
- Access control enforced by **Active Directory groups**
- Scalable multi-pod proxy on OpenShift
- LLM backend completely unexposed — network-isolated only

---

## 2. Architecture

```
Orion Desktop (Windows)
    │
    ├─ 1. GET token ──────────────────► SEECloud-IIS (Windows Auth, IIS)
    │                                       • NTLM/Negotiate handshake
    │       ◄─────────────── JWT ───────────• Validates user + AD groups
    │                                       • Issues signed JWT (RS256)
    │
    └─ 2. POST /v1/chat ──────────────► Chat-Proxy (FastAPI, OpenShift)
         Authorization: Bearer <jwt>        │  • Validate JWT (RS256, JWKS)
                                            │  • Check AD group → access
         ◄──────────── response ────────────│  • Pick tier from group
                                            │  • Check rpm + concurrency
                                            │        │           ▲
                                            │    INCR/DECR   429 if over
                                            │        ▼           │
                                            │    Redis (rate-limit store)
                                            │
                                            └──► LLM Backend (private, no auth)
                                                 x-orion-user / x-orion-groups
```

### Components

| Component | Runtime | Responsibility |
|---|---|---|
| **Orion Desktop** | Windows | Acquires JWT via Negotiate; sends Bearer token |
| **SEECloud-IIS** | ASP.NET Core 9 on IIS | Windows Auth → AD group check → JWT issuance |
| **Chat-Proxy** | FastAPI on OpenShift | JWT validation, access control, rate limiting, LLM forwarding |
| **LLM Backend** | Private service | Inference only — no auth |

---

## 3. End-to-End Flow

### Step 1 — Get a token

```
Orion Desktop
  POST https://seecloud-iis.company.local/desktop/token
  (Windows Negotiate — silent, no user interaction)

SEECloud-IIS
  → Reads HttpContext.User.Identity.Name
  → Checks AD group membership
  → Issues signed JWT (RS256)
```

Response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

### Step 2 — Call the LLM

```
Orion Desktop
  POST https://chat-proxy.openshift.company.local/v1/chat
  Authorization: Bearer <jwt>

Chat-Proxy
  → Validate JWT signature, iss, aud, exp
  → Check user is in an ACCESS_GROUP
  → Determine rate-limit tier from group membership
  → Enforce rpm + concurrency limits (Redis)
  → Forward to LLM (strip Authorization header)
  → Return LLM response to Orion
```

---

## 4. SEECloud-IIS — Token Issuer

### AD Groups

AD groups are the **single source of truth** for access and tier. No application-side user lists.

| AD Group | Purpose |
|---|---|
| `CORP\dep1`, `CORP\dep2`, `CORP\team-ai` | Grant access to the LLM |
| `CORP\pro_group` | Pro rate-limit tier |
| `CORP\max_group` | Max rate-limit tier |

### JWT Format

**Header:**

```json
{ "alg": "RS256", "kid": "key-id-1" }
```

**Claims:**

```json
{
  "iss": "https://seecloud-iis.company.local",
  "aud": "orion-chat-proxy",
  "sub": "CORP\\san",
  "groups": ["dep1", "max_group"],
  "iat": 1700000000,
  "exp": 1700001800
}
```

**Rules:**

- Sign with **RS256** — the proxy must not hold the private key
- Emit `groups` as short names (e.g., `dep1`) — standardize the format across issuer and proxy
- Publish the public key via a JWKS endpoint (`/.well-known/jwks.json`) — preferred over distributing a cert file

### ASP.NET Core implementation sketch

```csharp
// LoginController.cs
var windowsUser = HttpContext.User.Identity.Name;      // "CORP\\san"
var groups = adService.GetGroups(windowsUser);         // ["dep1", "max_group"]

var claims = new List<Claim>
{
    new(JwtRegisteredClaimNames.Sub, windowsUser),
    new(JwtRegisteredClaimNames.Iss, _settings.Issuer),
    new(JwtRegisteredClaimNames.Aud, "orion-chat-proxy"),
};
foreach (var g in groups)
    claims.Add(new Claim("groups", g));

// sign with RSA private key, return Bearer token
```

---

## 5. Chat-Proxy — Enforcer

### A. Validate JWT

Reject with `401` if any of these fail:

- Signature valid (RS256, via JWKS)
- `iss` matches expected issuer
- `aud` equals `orion-chat-proxy`
- `exp` not expired
- `iat` present

### B. Check access

```python
ACCESS = _csv_set("ACCESS_GROUPS")   # e.g. {"dep1", "dep2", "team-ai"}

def ensure_access(user_groups: set[str]) -> None:
    if ACCESS and not (user_groups & ACCESS):
        raise HTTPException(status_code=403, detail="Not authorized")
```

If the user's `groups` claim has no intersection with `ACCESS_GROUPS` → `403`.

### C. Forward to LLM

- Strip `Authorization` header before forwarding
- Add audit headers:

```
x-orion-user:   CORP\san
x-orion-groups: dep1,max_group
```

- Return LLM response unchanged

---

## 6. Token Lifetime

**Recommended: short-lived tokens with silent refresh**

| Option | TTL | Notes |
|---|---|---|
| A (recommended) | 30 min | Orion silently re-requests via Negotiate — zero user friction, <100 ms |
| B | 4 hours | No refresh logic needed; longer exposure window if token is leaked |

> Never log `Authorization` headers regardless of which option is used.

---

## 7. Security Boundaries

| Component | Responsibility |
|---|---|
| **Active Directory** | Single source of truth for users and group membership |
| **SEECloud-IIS** | Windows authentication + JWT issuance (RS256) |
| **Chat-Proxy** | JWT validation, access enforcement, rate limiting |
| **LLM Backend** | Compute only — no auth, no public route |
| **OpenShift NetworkPolicy** | Prevents direct access to LLM or Redis from outside |
