from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    api_title: str = "AuditQuant API"
    api_version: str = "0.1.0"
    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", validation_alias="OPENAI_MODEL")
    slither_compose_path: str = Field(
        default="docker/docker-compose.yml", validation_alias="SLITHER_COMPOSE_PATH"
    )
    analysis_storage_path: str = Field(
        default="backend/.analysis", validation_alias="ANALYSIS_STORAGE_PATH"
    )


settings = Settings()
