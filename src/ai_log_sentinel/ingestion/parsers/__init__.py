"""Log parser factory."""

from __future__ import annotations

from ai_log_sentinel.ingestion.parsers.apache import ApacheParser
from ai_log_sentinel.ingestion.parsers.base import LogParser
from ai_log_sentinel.ingestion.parsers.nginx import NginxParser
from ai_log_sentinel.ingestion.parsers.syslog import SyslogParser


def build_parsers() -> dict[str, LogParser]:
    return {
        "nginx": NginxParser(),
        "apache": ApacheParser(),
        "syslog": SyslogParser(),
    }
