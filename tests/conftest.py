"""Shared test fixtures."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_sentinel.config.settings import Settings
from ai_log_sentinel.models.alert import Alert
from ai_log_sentinel.models.log_entry import LogEntry
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)


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


@pytest.fixture
def sample_threat_assessment() -> ThreatAssessment:
    return ThreatAssessment(
        category=ThreatCategory.BRUTEFORCE,
        severity=Severity.HIGH,
        confidence=0.92,
        summary="23 failed login attempts from 192.168.1.100 in 2 minutes",
        indicators=[
            "Multiple POST /login 401",
            "Rapid successive attempts",
            "Common username patterns",
        ],
        recommended_action=RecommendedAction.BLOCK_IP,
        action_details={"ip": "192.168.1.100", "ips": ["192.168.1.100"]},
        mitre_ttps=["T1110"],
        analyzed_by="flash",
        timestamp=datetime(2025, 1, 15, 10, 30, 45),
    )


@pytest.fixture
def sample_alert(sample_threat_assessment: ThreatAssessment) -> Alert:
    return Alert(
        threat=sample_threat_assessment,
        mitigation_rules=[
            {
                "rule_type": "ufw",
                "command": "sudo ufw deny from 192.168.1.100",
                "description": "Block IP via UFW",
                "critical": True,
                "rollback_command": "sudo ufw delete deny from 192.168.1.100",
            }
        ],
    )


@pytest.fixture
def sample_low_threat() -> ThreatAssessment:
    return ThreatAssessment(
        category=ThreatCategory.SUSPICIOUS,
        severity=Severity.LOW,
        confidence=0.45,
        summary="Unusual user-agent detected",
        indicators=["Unknown bot user-agent"],
        recommended_action=RecommendedAction.ALERT_ONLY,
        action_details={},
        analyzed_by="flash",
        timestamp=datetime(2025, 1, 15, 11, 0, 0),
    )
