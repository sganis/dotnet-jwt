# JWT Key Rotation

RS256 signing using certificates in the Windows Certificate Store. No UI — everything is config + PowerShell.

---

## How it works

`auth` signs JWTs with an RSA private key stored in `Cert:\LocalMachine\My`. The public key is published at `GET /desktop/jwks` so `chat` can verify signatures without sharing any secret.

Each certificate has a **kid** (key ID) — a short label like `2026-Q1`. The kid appears in the JWT header and in the JWKS response, so the proxy always knows which public key to use.

During rotation, both the old and new certs are listed in `JwksCerts`, so tokens signed by either key validate successfully. Once old tokens have expired, the old cert is removed.

---

## Configuration (`appsettings.json`)

```json
"JwtSettings": {
  "Issuer": "https://seecloud-iis.company.local",
  "Audience": "orion-chat-proxy",
  "ActiveKid": "2026-Q1",
  "ActiveSigningThumbprint": "A1B2C3...",
  "JwksCerts": [
    { "Thumbprint": "A1B2C3...", "Kid": "2026-Q1" }
  ],
  "TokenLifetimeMinutes": 30
}
```

- `ActiveSigningThumbprint` — cert used to sign new tokens
- `ActiveKid` — kid stamped into new JWT headers
- `JwksCerts` — all certs whose public keys are published; during rotation this has two entries

---

## Generating a certificate

Run `keygen.ps1` as Administrator on the IIS server:

```powershell
.\keygen.ps1 -Kid "2026-Q1" -AppPoolName "SEECloud-IIS"
```

This:
1. Generates an RSA-3072 self-signed cert (non-exportable private key)
2. Installs it into `Cert:\LocalMachine\My`
3. Grants Read on the private key to the specified IIS App Pool identity
4. Prints the thumbprint and the config snippet to paste into `appsettings.json`

---

## Rotation procedure

Token lifetime is 30 min. Allow ~60 min overlap (30 min token + 10 min JWKS cache + buffer).

### Step 1 — Generate new cert

```powershell
.\keygen.ps1 -Kid "2026-Q2" -AppPoolName "SEECloud-IIS"
```

Copy the printed thumbprint.

### Step 2 — Add new cert to JWKS (keep old — overlap begins)

```json
"JwksCerts": [
  { "Thumbprint": "NEW...", "Kid": "2026-Q2" },
  { "Thumbprint": "OLD...", "Kid": "2026-Q1" }
]
```

Restart the app pool. Chat will now accept tokens signed by either key.

### Step 3 — Switch signing to new cert

```json
"ActiveKid": "2026-Q2",
"ActiveSigningThumbprint": "NEW..."
```

Restart the app pool. New tokens are signed with the new key; old tokens still validate.

### Step 4 — Wait ~60 minutes

Let all old tokens expire and JWKS caches refresh.

### Step 5 — Remove old cert

```json
"JwksCerts": [
  { "Thumbprint": "NEW...", "Kid": "2026-Q2" }
]
```

Restart the app pool. Rotation complete. Old tokens will now be rejected.

Optionally delete the old cert from `certlm.msc`.

---

## Notes

- Never log the raw JWT or `Authorization` header
- Chat refreshes JWKS immediately if it sees an unknown kid, before rejecting 401
- Rotate quarterly (or monthly for tighter security)
