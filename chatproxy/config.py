# chatproxy/config.py
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    jwt_issuer: str = "https://seecloud-iis.company.local"
    jwt_audience: str = "orion-chat-proxy"
    jwt_jwks_url: str = "https://seecloud-iis.company.local/desktop/jwks"
    llm_backend_url: str = "http://llm-service:8000"
    allowed_roles: str = "llm:user,llm:admin"
    jwks_cache_ttl: int = 300  # seconds

    # AD group → application role mapping.
    # Set via: GROUP_ROLE_MAP='{"LLM_Admins": "llm:admin", "LLM_Users": "llm:user"}'
    # Groups absent from the map are silently dropped; a user with no mapped
    # roles will receive 403 from require_auth.
    group_role_map: dict[str, str] = {}

    # Rate limiting
    redis_url: str | None = None   # REDIS_URL
    rl_enabled: bool = True        # RL_ENABLED
    rl_user_rpm_admin: int = 120   # RL_USER_RPM_ADMIN
    rl_user_rpm_user: int = 30     # RL_USER_RPM_USER
    rl_conc_admin: int = 10        # RL_CONC_ADMIN
    rl_conc_user: int = 3          # RL_CONC_USER

    @property
    def allowed_roles_set(self) -> set[str]:
        return {r.strip() for r in self.allowed_roles.split(",") if r.strip()}

    model_config = {"env_file": ".env", "case_sensitive": False}


settings = Settings()
