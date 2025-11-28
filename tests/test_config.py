"""Tests for configuration management."""

import pytest
from pydantic import ValidationError

from src.config import Settings


def test_settings_validation_with_api_key() -> None:
    """Test NVD delay validation with API key."""
    # Should fail with delay < 0.6s even with API key
    with pytest.raises(ValidationError):
        Settings(
            discord_webhook_url="https://discord.com/api/webhooks/123/abc",
            nvd_api_key="test-key",
            nvd_request_delay_seconds=0.5,
        )


def test_settings_validation_without_api_key() -> None:
    """Test NVD delay validation without API key."""
    # Should fail with delay < 6s without API key
    with pytest.raises(ValidationError):
        Settings(
            discord_webhook_url="https://discord.com/api/webhooks/123/abc",
            nvd_request_delay_seconds=3.0,
        )


def test_settings_valid_with_api_key() -> None:
    """Test valid settings with API key."""
    settings = Settings(
        discord_webhook_url="https://discord.com/api/webhooks/123/abc",
        nvd_api_key="test-key",
        nvd_request_delay_seconds=0.6,
    )

    assert settings.nvd_api_key == "test-key"
    assert settings.nvd_request_delay_seconds == 0.6


def test_settings_valid_without_api_key() -> None:
    """Test valid settings without API key."""
    settings = Settings(
        discord_webhook_url="https://discord.com/api/webhooks/123/abc",
        nvd_request_delay_seconds=6.0,
    )

    assert settings.nvd_api_key is None
    assert settings.nvd_request_delay_seconds == 6.0


def test_settings_defaults() -> None:
    """Test default settings values."""
    settings = Settings(
        discord_webhook_url="https://discord.com/api/webhooks/123/abc",
    )

    assert settings.kev_check_hours == 24
    assert settings.max_discord_embeds_per_message == 10
    assert settings.request_timeout_seconds == 30
