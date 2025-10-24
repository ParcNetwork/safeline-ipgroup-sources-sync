from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    SAFELINE_BASE_URL: str
    SAFELINE_API_TOKEN: str

    ABUSEIPDB_KEY: str | None = None

    model_config = SettingsConfigDict(
        env_file="config/.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings() # type: ignore