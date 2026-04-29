"""Configuration loader — TOML config + VibeLock secrets."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

import vibelock
from vibelock import VibeLockOptions


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class Settings:
    def __init__(self, config_path: str | Path | None = None) -> None:
        defaults_path = Path(__file__).parent / "defaults.toml"
        with open(defaults_path, "rb") as f:
            self._data: dict[str, Any] = tomllib.load(f)

        if config_path is not None:
            user_path = Path(config_path)
            with open(user_path, "rb") as f:
                user_data = tomllib.load(f)
            self._data = _deep_merge(self._data, user_data)

        self._secret_cache: dict[str, str] = {}

    def get(self, dotpath: str, default: Any = None) -> Any:
        keys = dotpath.split(".")
        node: Any = self._data
        for key in keys:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                return default
        return node

    async def get_secret(self, key: str) -> str:
        if key in self._secret_cache:
            return self._secret_cache[key]

        vault_path = self.get("secrets.vault_path", "./secrets.vibe")
        project_id = self.get("secrets.project_id", "AI-Log-Sentinel")
        file_key = self.get("secrets.file_key", False)
        options = VibeLockOptions(vault_path=vault_path, project_id=project_id, file_key=file_key)
        value = await vibelock.get(key, options)
        self._secret_cache[key] = value
        return value

    @property
    def raw(self) -> dict[str, Any]:
        return self._data
