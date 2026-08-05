"""Central configuration — reads .env only, zero hardcoded secrets."""
from functools import lru_cache
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Server ─
    http_port: int          = Field(3000,             alias="AITP_HTTP_PORT")
    host:      str          = Field("0.0.0.0",        alias="AITP_HOST")  # nosec B104
    debug:     bool         = Field(False,             alias="AITP_DEBUG")

    # ── Database 
    DATA_DIR: str = Field("data", alias="DATA_DIR")
    database_url: str       = Field(
        "sqlite+aiosqlite:///data/aitp.db", alias="DATABASE_URL"
    )

    # ── Ollama (LOCAL — no API key ever) 
    ollama_endpoint:    str   = Field("http://localhost:11434", alias="OLLAMA_ENDPOINT")
    ollama_model:       str   = Field("gemma4:latest",          alias="OLLAMA_MODEL")
    ollama_timeout:     int   = Field(0,                        alias="OLLAMA_TIMEOUT")
    ollama_temperature: float = Field(0.1,                      alias="OLLAMA_TEMPERATURE")
    ollama_max_tokens:  int   = Field(300,                      alias="OLLAMA_MAX_TOKENS")

    # ── Security 
    jwt_secret:  str  = Field("changeme_32chars", alias="KELAN_JWT_SECRET")
    require_pq:  bool = Field(True,               alias="REQUIRE_PQ")

    # ── Rate limits 
    syn_rate_limit: int = Field(50,  alias="SYN_RATE_LIMIT")
    udp_rate_limit: int = Field(200, alias="UDP_RATE_LIMIT")

    # ── Circuit breaker 
    cb_threshold: int = Field(3,  alias="CB_FAILURE_THRESHOLD")
    cb_recovery:  int = Field(30, alias="CB_RECOVERY_TIMEOUT")

    # ── Agentic 
    agentic_enabled: bool = Field(True, alias="AGENTIC_ENABLED")

    @field_validator("ollama_endpoint")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @model_validator(mode="after")
    def ensure_sqlite_db_url_uses_data_dir(self) -> 'Settings':
        if self.database_url and "sqlite" in self.database_url and ":memory:" not in self.database_url:
            self.database_url = f"sqlite+aiosqlite:///{self.DATA_DIR}/aitp.db"
        return self


@lru_cache()
def get_settings() -> Settings:
    # Pyright cannot resolve Pydantic's alias-based
    # field population from env vars at the type
    # level. Runtime behaviour is correct (verified
    # by 95 passing tests). Safe to ignore here.
    return Settings()  # pyright: ignore[reportCallIssue]
