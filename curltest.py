# inttest.py
"""
Integration test: Windows Negotiate → IIS JWT → Proxy-Chat / Proxy-Embed.

  python inttest.py

Requires:
  - curl in PATH (Windows built-in, curl.exe 7.55+)
  - Active Windows session with domain credentials (Kerberos/NTLM via SSPI)
  - All three services reachable from this machine
"""
import base64
import datetime
import json
import subprocess
import sys

# ── Configure endpoints ──────────────────────────────────────────────────────
IIS_URL        = "https://seecloud-iis.company.local"
PROXYCHAT_URL  = "http://proxy-chat.openshift.company.local"
PROXYEMBED_URL = "http://proxy-embed.openshift.company.local"
# ────────────────────────────────────────────────────────────────────────────


def curl(*args: str) -> tuple[str, str]:
    """
    Run curl and return (body, http_status_code).
    Exits on curl transport error (non-zero returncode).
    """
    cmd = ["curl", "--silent", "-w", "\n%{http_code}", *args]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        _fail(f"curl transport error (rc={r.returncode}): {r.stderr.strip()}")
    *body_lines, status = r.stdout.rsplit("\n", 1)
    return "\n".join(body_lines).strip(), status.strip()


def decode_jwt(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _sep(title: str) -> None:
    print(f"\n{'─' * 64}")
    print(f"  {title}")
    print("─" * 64)


def _ok(label: str, value: object) -> None:
    print(f"  {'OK':<6} {label:<14} {value}")


def _fail(msg: str) -> None:
    print(f"\n  FAIL  {msg}", file=sys.stderr)
    sys.exit(1)


def _assert_http(status: str, expected: str, context: str) -> None:
    if status != expected:
        _fail(f"{context} — expected HTTP {expected}, got {status}")


# ── 1. Obtain JWT from IIS via Windows Negotiate ─────────────────────────────
_sep("1 · IIS /desktop/token  (--negotiate, no password)")

body, status = curl(
    "--negotiate", "-u", ":",
    "-X", "POST",
    f"{IIS_URL}/desktop/token",
)
_assert_http(status, "200", "IIS token endpoint")

try:
    resp = json.loads(body)
except json.JSONDecodeError:
    _fail(f"Expected JSON from IIS, got:\n{body}")

token = resp.get("access_token") or _fail("No access_token in response")

_ok("HTTP",        status)
_ok("token_type",  resp.get("token_type"))
_ok("expires_in",  f"{resp.get('expires_in')} s")
_ok("access_token", f"{token[:48]}…")


# ── 2. Decode JWT — print claims ──────────────────────────────────────────────
_sep("2 · JWT claims (decoded, not verified)")

claims = decode_jwt(token)

_ok("sub",    claims.get("sub"))
_ok("iss",    claims.get("iss"))
_ok("aud",    claims.get("aud"))
_ok("groups", claims.get("groups"))

if exp := claims.get("exp"):
    dt = datetime.datetime.fromtimestamp(exp).isoformat(timespec="seconds")
    _ok("exp",  f"{exp}  ({dt} local)")

if jti := claims.get("jti"):
    _ok("jti", jti)


# ── 3. Proxy-Chat: GET /v1/models ─────────────────────────────────────────────
_sep(f"3 · Proxy-Chat  GET /v1/models  ({PROXYCHAT_URL})")

body, status = curl(
    "-H", f"Authorization: Bearer {token}",
    f"{PROXYCHAT_URL}/v1/models",
)
_assert_http(status, "200", "Proxy-Chat /v1/models")

try:
    models = json.loads(body)
except json.JSONDecodeError:
    _fail(f"Expected JSON from Proxy-Chat, got:\n{body}")

_ok("HTTP",     status)
_ok("response", json.dumps(models))


# ── 4. Proxy-Embed: GET /v1/models ────────────────────────────────────────────
_sep(f"4 · Proxy-Embed  GET /v1/models  ({PROXYEMBED_URL})")

body, status = curl(
    "-H", f"Authorization: Bearer {token}",
    f"{PROXYEMBED_URL}/v1/models",
)
_assert_http(status, "200", "Proxy-Embed /v1/models")

try:
    models = json.loads(body)
except json.JSONDecodeError:
    _fail(f"Expected JSON from Proxy-Embed, got:\n{body}")

_ok("HTTP",     status)
_ok("response", json.dumps(models))


# ── Done ──────────────────────────────────────────────────────────────────────
_sep("All checks passed")
