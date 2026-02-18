# proxy/config.py
from pydantic import PrivateAttr
from pydantic_settings import BaseSettings


def _csv_set(value: str) -> set[str]:
    return {x.strip() for x in value.split(",") if x.strip()}


class Settings(BaseSettings):
    # JWT validation
    jwt_issuer: str = "https://seecloud-iis.company.local"
    jwt_audience: str = "orion-proxy"
    jwt_jwks_url: str = "https://seecloud-iis.company.local/desktop/jwks"
    jwks_cache_ttl: int = 300  # seconds

    # LLM upstreams — routing is path-based (see router.py)
    chat_backend_url: str = "http://llm-service:8000"    # LLM_CHAT_BACKEND_URL
    embed_backend_url: str = "http://embed-service:8000"  # LLM_EMBED_BACKEND_URL

    # Per-route timeouts (seconds)
    chat_proxy_timeout: float = 120.0   # CHAT_PROXY_TIMEOUT
    embed_proxy_timeout: float = 30.0   # EMBED_PROXY_TIMEOUT

    # Per-route body limits (bytes)
    chat_max_body_bytes: int = 10 * 1024 * 1024  # CHAT_MAX_BODY_BYTES  (10 MB)
    embed_max_body_bytes: int = 1 * 1024 * 1024  # EMBED_MAX_BODY_BYTES (1 MB)

    # Access control (CSV of AD group names).
    # ACCESS_GROUPS=dep1,dep2,team-ai
    # If empty, any authenticated user is allowed.
    access_groups: str = ""       # ACCESS_GROUPS

    # Tier-assignment groups (highest tier wins).
    tier_max_groups: str = ""     # TIER_MAX_GROUPS
    tier_pro_groups: str = ""     # TIER_PRO_GROUPS
    default_tier: str = "basic"   # DEFAULT_TIER

    # Rate limiting
    redis_url: str | None = None  # REDIS_URL
    rl_enabled: bool = True       # RL_ENABLED

    # Per-tier: requests / minute (per user)
    rl_rpm_basic: int = 10        # RL_RPM_BASIC
    rl_rpm_pro: int = 30          # RL_RPM_PRO
    rl_rpm_max: int = 120         # RL_RPM_MAX

    # Per-tier: max concurrent requests (per user)
    rl_conc_basic: int = 1        # RL_CONC_BASIC
    rl_conc_pro: int = 3          # RL_CONC_PRO
    rl_conc_max: int = 10         # RL_CONC_MAX

    # Pre-computed sets — parsed once at startup, not on every request.
    _access_groups_set: set[str] = PrivateAttr(default_factory=set)
    _tier_max_set: set[str] = PrivateAttr(default_factory=set)
    _tier_pro_set: set[str] = PrivateAttr(default_factory=set)

    def model_post_init(self, __context) -> None:
        self._access_groups_set = _csv_set(self.access_groups)
        self._tier_max_set = _csv_set(self.tier_max_groups)
        self._tier_pro_set = _csv_set(self.tier_pro_groups)

    @property
    def access_groups_set(self) -> set[str]:
        return self._access_groups_set

    @property
    def tier_max_set(self) -> set[str]:
        return self._tier_max_set

    @property
    def tier_pro_set(self) -> set[str]:
        return self._tier_pro_set

    model_config = {"env_file": ".env", "case_sensitive": False}


settings = Settings()
