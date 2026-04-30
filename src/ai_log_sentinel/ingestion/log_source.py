"""Log source configuration model."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


@dataclass
class LogSource:
    name: str
    path: Path
    format: Literal["nginx", "apache", "syslog"]
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


def load_sources(config: dict[str, Any]) -> list[LogSource]:
    raw_sources = config.get("sources") or config.get("pipeline", {}).get("log_sources")
    if not raw_sources:
        return []

    sources: list[LogSource] = []
    for entry in raw_sources:
        sources.append(
            LogSource(
                name=entry["name"],
                path=Path(entry["path"]),
                format=entry["format"],
                enabled=entry.get("enabled", True),
                tags=list(entry.get("tags", [])),
            )
        )
    return sources
