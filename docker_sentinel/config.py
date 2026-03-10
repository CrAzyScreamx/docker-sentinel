"""
Centralised configuration for docker-sentinel.

Uses pydantic-settings to load and validate all settings from environment
variables and the .env file, providing a single typed source of truth so
every other module imports from here rather than calling os.environ directly.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables and the .env file.

    Pydantic-settings automatically reads values from the environment with
    the .env file as fallback. Field names map to env var names
    case-insensitively (e.g. docker_sentinel_model ↔ DOCKER_SENTINEL_MODEL).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LiteLLM model string forwarded to every LlmAgent.
    docker_sentinel_model: str = Field(
        default="anthropic/claude-sonnet-4-6",
    )

    # Anthropic API key — required at runtime, not validated here.
    anthropic_api_key: str = Field(default="")

    # Schema version stamped into every FinalReport.
    schema_version: str = Field(default="1.0.0")

    # Docker Hub REST API base URL.
    docker_hub_api_base: str = Field(
        default="https://hub.docker.com/v2/repositories",
    )

    # Timeout in seconds for all outbound HTTP requests.
    request_timeout: int = Field(default=10)

    # TruffleHog Docker image used for secret scanning.
    trufflehog_image: str = Field(
        default="trufflesecurity/trufflehog:latest",
    )


settings = Settings()
