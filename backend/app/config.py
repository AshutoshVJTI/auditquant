from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    api_title: str = "AuditQuant API"
    api_version: str = "0.1.0"
    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", validation_alias="OPENAI_MODEL")
    docker_compose_path: str = Field(
        default="docker/docker-compose.yml", validation_alias="DOCKER_COMPOSE_PATH"
    )
    # Legacy alias kept for backward compatibility with existing .env files
    slither_compose_path: str = Field(
        default="docker/docker-compose.yml", validation_alias="SLITHER_COMPOSE_PATH"
    )
    analysis_storage_path: str = Field(
        default="backend/.analysis", validation_alias="ANALYSIS_STORAGE_PATH"
    )
    
    # Multi-tool settings
    enable_securify: bool = Field(default=True, validation_alias="ENABLE_SECURIFY")
    enable_echidna: bool = Field(default=True, validation_alias="ENABLE_ECHIDNA")
    enable_oyente: bool = Field(default=True, validation_alias="ENABLE_OYENTE")
    echidna_test_limit: int = Field(default=50000, validation_alias="ECHIDNA_TEST_LIMIT")
    echidna_timeout: int = Field(default=300, validation_alias="ECHIDNA_TIMEOUT")
    oyente_timeout: int = Field(default=180, validation_alias="OYENTE_TIMEOUT")


settings = Settings()
