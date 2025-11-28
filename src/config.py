"""Configuration management with validation and security-first approach."""

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Discord Configuration
    discord_webhook_url: HttpUrl = Field(
        ...,
        description="Discord webhook URL for posting KEV notifications",
    )

    # NVD API Configuration
    nvd_api_key: str | None = Field(
        default=None,
        description="NVD API key for higher rate limits (optional)",
    )

    # KEV Configuration
    kev_url: str = Field(
        default="https://raw.githubusercontent.com/cisagov/KEV/develop/known_exploited_vulnerabilities.json",
        description="URL to CISA KEV JSON data",
    )

    kev_check_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="Check for vulnerabilities added in the last N hours",
    )

    # NVD API Rate Limiting
    nvd_request_delay_seconds: float = Field(
        default=6.0,
        ge=0.6,
        description="Delay between NVD API requests (6s without key, 0.6s with key)",
    )

    nvd_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD API base URL",
    )

    # Discord Formatting
    max_discord_embeds_per_message: int = Field(
        default=10,
        ge=1,
        le=10,
        description="Maximum embeds per Discord message (Discord limit is 10)",
    )

    # Timeout Configuration
    request_timeout_seconds: int = Field(
        default=30,
        ge=5,
        le=120,
        description="HTTP request timeout in seconds",
    )

    @field_validator("nvd_request_delay_seconds")
    @classmethod
    def validate_nvd_delay(cls, v: float, info: dict) -> float:
        """Ensure NVD delay respects rate limits based on API key presence."""
        # NVD rate limits: 5 requests/30s without key, 50 requests/30s with key
        # Safe defaults: 6s without key, 0.6s with key
        nvd_api_key = info.data.get("nvd_api_key")
        if nvd_api_key and v < 0.6:
            raise ValueError("NVD delay must be >= 0.6s even with API key")
        if not nvd_api_key and v < 6.0:
            raise ValueError("NVD delay must be >= 6s without API key")
        return v


def get_settings() -> Settings:
    """Get validated application settings."""
    return Settings()
