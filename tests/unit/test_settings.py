from __future__ import annotations

from pathlib import Path

import pytest
from vibelock.vault import SecretNotFoundError

from ai_log_sentinel.config.settings import Settings


def test_settings_loads_defaults(settings: Settings) -> None:
    assert settings.get("general.app_name") == "AI-Log-Sentinel"
    assert settings.get("general.log_level") == "INFO"
    assert settings.get("pipeline.batch_size") == 10
    assert settings.get("pipeline.batch_interval") == 30


def test_settings_user_override(tmp_path: Path) -> None:
    user_config = tmp_path / "user.toml"
    user_config.write_text('[general]\nlog_level = "DEBUG"\n\n[pipeline]\nbatch_size = 20\n')
    s = Settings(config_path=str(user_config))
    assert s.get("general.log_level") == "DEBUG"
    assert s.get("pipeline.batch_size") == 20
    assert s.get("pipeline.batch_interval") == 30


def test_settings_dotpath(settings: Settings) -> None:
    assert settings.get("pipeline.batch_size") == 10
    assert settings.get("reasoning.flash_model") == "gemini-1.5-flash"


def test_settings_dotpath_missing(settings: Settings) -> None:
    assert settings.get("nonexistent.key") is None
    assert settings.get("nonexistent.key", "fallback") == "fallback"


def test_settings_raw(settings: Settings) -> None:
    raw = settings.raw
    assert isinstance(raw, dict)
    assert "general" in raw
    assert "pipeline" in raw


@pytest.mark.asyncio
async def test_secrets_cached(settings: Settings) -> None:
    settings._secret_cache["TEST_KEY"] = "test_value"
    result = await settings.get_secret("TEST_KEY")
    assert result == "test_value"


@pytest.mark.asyncio
async def test_secrets_missing_key_raises(settings: Settings) -> None:
    with pytest.raises(SecretNotFoundError):
        await settings.get_secret("NONEXISTENT_KEY_12345")
