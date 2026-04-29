"""Syslog RFC3164/5424 parser."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ai_log_sentinel.models.log_entry import LogEntry

from .base import LogParser

_SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$"
)

_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

_ACTION_MAP: dict[str, str] = {
    "failed password": "FAILED",
    "accepted password": "ACCEPTED",
    "accepted publickey": "ACCEPTED",
    "session opened": "SESSION_OPENED",
    "session closed": "SESSION_CLOSED",
    "invalid user": "INVALID_USER",
    "disconnected": "DISCONNECTED",
    "connection closed": "CONNECTION_CLOSED",
    "authentication failure": "AUTH_FAILED",
}


class SyslogParser(LogParser):
    _PATTERN = _SYSLOG_RE

    def parse(self, line: str, source_label: str) -> LogEntry | None:
        match = self._PATTERN.match(line)
        if not match:
            return None

        ts_str, _hostname, app, _pid, message = match.groups()

        try:
            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            ts = ts.replace(year=datetime.now(tz=timezone.utc).year, tzinfo=timezone.utc)
        except ValueError:
            return None

        source_ip = ""
        ip_match = _IP_RE.search(message)
        if ip_match:
            source_ip = ip_match.group()

        method = self._extract_action(message)

        return LogEntry(
            timestamp=ts,
            source_ip=source_ip,
            method=method,
            path=app,
            status_code=0,
            response_size=0,
            user_agent="",
            referer="",
            raw_line=line,
            source_label=source_label,
        )

    def can_parse(self, line: str) -> bool:
        return bool(self._PATTERN.match(line))

    @staticmethod
    def _extract_action(message: str) -> str:
        lower = message.lower()
        for pattern, action in _ACTION_MAP.items():
            if pattern in lower:
                return action
        first = message.split()[0] if message else "UNKNOWN"
        return first.upper()
