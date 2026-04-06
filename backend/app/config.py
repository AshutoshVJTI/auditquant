from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(_ENV_FILE), env_file_encoding="utf-8", extra="ignore")

    api_title: str = "AuditQuant API"
    api_version: str = "0.1.0"

    docker_compose_path: str = Field(
        default="docker/docker-compose.yml", validation_alias="DOCKER_COMPOSE_PATH"
    )
    analysis_storage_path: str = Field(
        default="backend/.analysis", validation_alias="ANALYSIS_STORAGE_PATH"
    )

    codebert_checkpoint_path: str = Field(
        default="evaluation/llm_training/checkpoints/checkpoint_best.pt",
        validation_alias="CODEBERT_CHECKPOINT_PATH",
    )

    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", validation_alias="OPENAI_MODEL")
    openai_base_url: str | None = Field(default=None, validation_alias="OPENAI_BASE_URL")


settings = Settings()
