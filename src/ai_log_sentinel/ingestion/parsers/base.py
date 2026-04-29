"""Abstract log parser interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ai_log_sentinel.models.log_entry import LogEntry


class LogParser(ABC):
    @abstractmethod
    def parse(self, line: str, source_label: str) -> LogEntry | None: ...

    @abstractmethod
    def can_parse(self, line: str) -> bool: ...
