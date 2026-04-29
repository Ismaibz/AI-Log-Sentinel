from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_log_sentinel.models.log_entry import LogEntry


@dataclass
class AnonymizedEntry:
    original: LogEntry
    sanitized_line: str
    tokens: dict[str, str] = field(default_factory=dict)
    is_noise: bool = False
    noise_reason: str | None = None
