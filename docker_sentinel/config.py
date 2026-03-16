"""
Centralised configuration for docker-sentinel.

Uses pydantic-settings to load and validate all settings from environment
variables and the .env file, providing a single typed source of truth so
every other module imports from here rather than calling os.environ directly.

When running as a PyInstaller bundle the .env is resolved relative to the
executable so users can place it next to the .exe. When running from source
it resolves to the project root. System environment variables always take
precedence over the .env file.
"""

import sys
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _resolve_env_file() -> Path:
    """
    Return the path to the .env file appropriate for the current runtime.

    When frozen by PyInstaller sys.frozen is True and sys.executable points
    to the .exe, so the .env is looked up next to it. In a normal Python
    environment the .env lives two levels above this file (the project root).
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / ".env"
    return Path(__file__).parent.parent / ".env"


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables and the .env file.

    Pydantic-settings reads system environment variables first, then falls
    back to the .env file resolved by _resolve_env_file(). Field names map
    to env var names case-insensitively
    (e.g. docker_sentinel_model ↔ DOCKER_SENTINEL_MODEL).
    """

    model_config = SettingsConfigDict(
        env_file=str(_resolve_env_file()),
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
    schema_version: str = Field(default="2.0.0")

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
