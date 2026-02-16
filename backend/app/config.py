from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    api_title: str = "AuditQuant API"
    api_version: str = "0.1.0"
    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", validation_alias="OPENAI_MODEL")
    openai_base_url: str | None = Field(default=None, validation_alias="OPENAI_BASE_URL")
    docker_compose_path: str = Field(
        default="docker/docker-compose.yml", validation_alias="DOCKER_COMPOSE_PATH"
    )
    slither_compose_path: str = Field(  # kept for old .env files
        default="docker/docker-compose.yml", validation_alias="SLITHER_COMPOSE_PATH"
    )
    analysis_storage_path: str = Field(
        default="backend/.analysis", validation_alias="ANALYSIS_STORAGE_PATH"
    )
    enable_oyente: bool = Field(default=True, validation_alias="ENABLE_OYENTE")
    oyente_timeout: int = Field(default=180, validation_alias="OYENTE_TIMEOUT")


settings = Settings()
