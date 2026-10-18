"""
Kelan Security Configuration
All settings loaded from .env — NO secrets hardcoded in source.
Generate secrets with: openssl rand -hex 32
"""
from functools import lru_cache
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Server ────────────────────────────────────────────────
    http_port: int = Field(default=3000, alias="AITP_HTTP_PORT")
    bind_host: str = Field(default="0.0.0.0", alias="AITP_BIND_HOST")
    log_level: str = Field(default="info", alias="KELAN_LOG_LEVEL")
    mode: str = Field(default="hybrid", alias="KELAN_MODE")

    # ── Database ───────────────────────────────────────────────
    DATA_DIR: str = Field("data", alias="DATA_DIR")
    database_url: str = Field(
        default="sqlite+aiosqlite:///data/aitp.db",
        alias="DATABASE_URL"
    )

    # ── Ollama — LOCAL AI (no API key, no external calls) ──────
    ollama_endpoint: str = Field(
        default="http://localhost:11434",
        alias="OLLAMA_ENDPOINT"
    )
    ollama_model: str = Field(
        default="gemma4:latest",
        alias="OLLAMA_MODEL"
    )
    ollama_timeout: int = Field(default=60, alias="OLLAMA_TIMEOUT_SECS")
    ollama_temperature: float = Field(default=0.1, alias="OLLAMA_TEMPERATURE")

    # ── Security ───────────────────────────────────────────────
    jwt_secret: str = Field(
        default="dev-only-change-in-production",
        alias="KELAN_JWT_SECRET"
    )
    require_pq: bool = Field(default=True, alias="REQUIRE_PQ")

    # ── eBPF Rate Limits ───────────────────────────────────────
    syn_rate_limit: int = Field(default=50, alias="SYN_RATE_LIMIT")
    udp_rate_limit: int = Field(default=200, alias="UDP_RATE_LIMIT")
    ebpf_enabled: bool = Field(default=True, alias="KELAN_EBPF_ENABLED")
    xdp_iface: str = Field(default="eth0", alias="KELAN_XDP_IFACE")

    # ── Agentic WebSocket ──────────────────────────────────────
    agentic_enabled: bool = Field(default=True, alias="AGENTIC_ENABLED")
    agent_auth_token: str = Field(
        default="dev-token-change-in-production",
        alias="AGENT_AUTH_TOKEN"
    )

    # ── Circuit Breaker ────────────────────────────────────────
    cb_failure_threshold: int = Field(default=3, alias="CB_FAILURE_THRESHOLD")
    cb_recovery_timeout: int = Field(default=30, alias="CB_RECOVERY_TIMEOUT")

    @model_validator(mode="after")
    def ensure_sqlite_db_url_uses_data_dir(self) -> 'Settings':
        if self.database_url and "sqlite" in self.database_url and ":memory:" not in self.database_url:
            self.database_url = f"sqlite+aiosqlite:///{self.DATA_DIR}/aitp.db"
        return self

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "populate_by_name": True,
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    return Settings()
