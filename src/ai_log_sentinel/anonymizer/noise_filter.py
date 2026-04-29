"""Noise filter — flags non-security-relevant log entries."""

from __future__ import annotations

from os.path import splitext
from typing import Any

from ai_log_sentinel.models.log_entry import LogEntry

_SUSPICIOUS_PATH_SUBSTRINGS = (
    "/admin",
    "/etc/passwd",
    "/wp-admin",
    "/wp-login",
    ".env",
    "/phpmyadmin",
    "/phpinfo",
)

_SUSPICIOUS_STATUS_CODES = frozenset({403, 404, 500})

_DEFAULT_KNOWN_BOTS = (
    "Googlebot",
    "Bingbot",
    "Baiduspider",
    "YandexBot",
    "DuckDuckBot",
    "Slurp",
    "facebookexternalhit",
    "Twitterbot",
    "LinkedInBot",
)


class NoiseFilter:
    def __init__(self, config: dict[str, Any]) -> None:
        noise_cfg = config.get("noise_filter", {})
        self._enabled = noise_cfg.get("enabled", True)
        self._static_extensions = frozenset(
            ext.lower() for ext in noise_cfg.get("static_extensions", [])
        )
        self._health_paths = frozenset(noise_cfg.get("health_paths", []))
        self._ignore_status_codes = set(noise_cfg.get("ignore_status_codes", []))
        self._known_bots = noise_cfg.get("known_bots", list(_DEFAULT_KNOWN_BOTS))

    def is_noise(self, entry: LogEntry) -> tuple[bool, str | None]:
        if not self._enabled:
            return (False, None)

        if self._is_suspicious(entry):
            return (False, None)

        path = entry.path.split("?", 1)[0]
        _, ext = splitext(path)

        if ext.lower() in self._static_extensions:
            return (True, "static_asset")

        if entry.path in self._health_paths:
            return (True, "health_check")

        if any(bot in entry.user_agent for bot in self._known_bots):
            return (True, "known_bot")

        if entry.status_code in self._ignore_status_codes:
            return (True, "ignored_status")

        return (False, None)

    def _is_suspicious(self, entry: LogEntry) -> bool:
        if entry.status_code not in _SUSPICIOUS_STATUS_CODES:
            return False
        path_lower = entry.path.lower()
        return any(s in path_lower for s in _SUSPICIOUS_PATH_SUBSTRINGS)
