"""Shared test fixtures."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_sentinel.config.settings import Settings
from ai_log_sentinel.models.log_entry import LogEntry


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def sample_nginx_line() -> str:
    return (
        "192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "
        '"GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"'
    )


@pytest.fixture
def sample_log_entry() -> LogEntry:
    return LogEntry(
        timestamp=datetime(2025, 1, 15, 10, 30, 45),
        source_ip="192.168.1.1",
        method="GET",
        path="/admin",
        status_code=403,
        response_size=548,
        user_agent="Mozilla/5.0",
        referer="-",
        raw_line=(
            "192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "
            '"GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"'
        ),
        source_label="nginx-main",
    )
