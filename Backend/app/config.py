from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Piranha API"
    database_url: str = "sqlite:///./piranha.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    admin_api_key: str | None = None
    report_identity_secret: str = "piranha-local-development"
    resend_api_key: str | None = None
    email_from: str = "Piranha <onboarding@resend.dev>"
    urlhaus_auth_key: str | None = None
    phishtank_enabled: bool = True
    phishtank_api_key: str | None = None
    threatfox_auth_key: str | None = None
    google_safe_browsing_api_key: str | None = None
    virustotal_api_key: str | None = None
    hibp_api_key: str | None = None
    request_timeout_seconds: float = 5.0
    positive_cache_hours: int = 24

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[1] / ".env",
        extra="ignore",
    )

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
