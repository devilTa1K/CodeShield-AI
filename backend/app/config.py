"""Application settings, loaded from environment variables (and an optional .env file)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Later files win: a backend/.env overrides the repo-root .env.
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- BharatCode API -----------------------------------------------------
    bharatcode_api_key: str = ""
    bharatcode_base_url: str = "https://bharatcode.ai/api/model/v1"
    bharatcode_model: str = "qwen-3.8-27b"
    bharatcode_timeout_seconds: float = 90.0
    bharatcode_max_output_tokens: int = 6000
    bharatcode_max_retries: int = 2

    # --- Input limits -------------------------------------------------------
    max_code_chars: int = 40_000
    max_code_lines: int = 1_500

    # --- Server -------------------------------------------------------------
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    rate_limit_per_minute: int = 20
    log_level: str = "INFO"

    # --- Scanners -----------------------------------------------------------
    scanner_timeout_seconds: float = 30.0
    # Semgrep only runs when this is set (a local rules file/dir or a registry
    # config such as "p/security-audit", which needs network access).
    semgrep_config: str = ""

    @property
    def ai_configured(self) -> bool:
        return bool(self.bharatcode_api_key.strip())

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
