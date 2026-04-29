"""Nginx combined log format parser."""

from __future__ import annotations

import re
from datetime import datetime

from ai_log_sentinel.models.log_entry import LogEntry

from .base import LogParser

_NGINX_RE = re.compile(
    r'^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"$'
)


class NginxParser(LogParser):
    _PATTERN = _NGINX_RE

    def parse(self, line: str, source_label: str) -> LogEntry | None:
        match = self._PATTERN.match(line)
        if not match:
            return None

        remote_addr, _user, time_local, method, path, _, status, size, referer, ua = match.groups()

        try:
            ts = datetime.strptime(time_local, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None

        return LogEntry(
            timestamp=ts,
            source_ip=remote_addr,
            method=method,
            path=path,
            status_code=int(status),
            response_size=int(size),
            user_agent=ua,
            referer=referer,
            raw_line=line,
            source_label=source_label,
        )

    def can_parse(self, line: str) -> bool:
        return bool(self._PATTERN.match(line))
