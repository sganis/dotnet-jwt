# chat/config.py
from pydantic_settings import BaseSettings


def _csv_set(value: str) -> set[str]:
    return {x.strip() for x in value.split(",") if x.strip()}


class Settings(BaseSettings):
    # JWT validation
    jwt_issuer: str = "https://seecloud-iis.company.local"
    jwt_audience: str = "orion-chat-proxy"
    jwt_jwks_url: str = "https://seecloud-iis.company.local/desktop/jwks"
    jwks_cache_ttl: int = 300  # seconds

    # LLM upstream
    llm_backend_url: str = "http://llm-service:8000"
    proxy_timeout: float = 120.0        # PROXY_TIMEOUT  (seconds)
    max_body_bytes: int = 10 * 1024 * 1024  # MAX_BODY_BYTES (default 10 MB)

    # Access control (CSV of AD group names).
    # ACCESS_GROUPS=dep1,dep2,team-ai
    # If empty, any authenticated user is allowed.
    access_groups: str = ""       # ACCESS_GROUPS

    # Tier-assignment groups (highest tier wins).
    # TIER_MAX_GROUPS=max_group
    # TIER_PRO_GROUPS=pro_group
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

    @property
    def access_groups_set(self) -> set[str]:
        return _csv_set(self.access_groups)

    @property
    def tier_max_set(self) -> set[str]:
        return _csv_set(self.tier_max_groups)

    @property
    def tier_pro_set(self) -> set[str]:
        return _csv_set(self.tier_pro_groups)

    model_config = {"env_file": ".env", "case_sensitive": False}


settings = Settings()
