from __future__ import annotations

from datetime import datetime

from ai_log_sentinel.models import (
    Alert,
    AlertStatus,
    AnonymizedEntry,
    LogEntry,
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)
from ai_log_sentinel.models.log_entry import LogEntry as DirectLogEntry


def test_log_entry_creation(sample_log_entry: LogEntry) -> None:
    assert sample_log_entry.timestamp == datetime(2025, 1, 15, 10, 30, 45)
    assert sample_log_entry.source_ip == "192.168.1.1"
    assert sample_log_entry.method == "GET"
    assert sample_log_entry.path == "/admin"
    assert sample_log_entry.status_code == 403
    assert sample_log_entry.response_size == 548
    assert sample_log_entry.user_agent == "Mozilla/5.0"
    assert sample_log_entry.referer == "-"
    assert sample_log_entry.source_label == "nginx-main"


def test_log_entry_from_dict() -> None:
    data = {
        "timestamp": datetime(2025, 1, 15, 10, 30, 45),
        "source_ip": "10.0.0.1",
        "method": "POST",
        "path": "/login",
        "status_code": 200,
        "response_size": 1024,
        "user_agent": "curl/8.0",
        "referer": "",
        "raw_line": "test raw line",
        "source_label": "test",
    }
    entry = LogEntry(**data)
    assert entry.source_ip == "10.0.0.1"
    assert entry.status_code == 200


def test_anonymized_entry_defaults(sample_log_entry: LogEntry) -> None:
    entry = AnonymizedEntry(original=sample_log_entry, sanitized_line="sanitized")
    assert entry.is_noise is False
    assert entry.tokens == {}
    assert entry.noise_reason is None


def test_anonymized_entry_with_tokens(sample_log_entry: LogEntry) -> None:
    tokens = {"IP_001": "192.168.1.1", "UA_001": "Mozilla/5.0"}
    entry = AnonymizedEntry(
        original=sample_log_entry,
        sanitized_line="sanitized",
        tokens=tokens,
        is_noise=True,
        noise_reason="static_asset",
    )
    assert entry.tokens["IP_001"] == "192.168.1.1"
    assert entry.is_noise is True
    assert entry.noise_reason == "static_asset"


def test_threat_category_values() -> None:
    assert ThreatCategory.NORMAL == "normal"
    assert ThreatCategory.SUSPICIOUS == "suspicious"
    assert ThreatCategory.MALICIOUS == "malicious"
    assert ThreatCategory.SCAN == "scan"
    assert ThreatCategory.BRUTEFORCE == "bruteforce"
    assert ThreatCategory.EXPLOIT_ATTEMPT == "exploit_attempt"


def test_severity_ordering() -> None:
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL > Severity.LOW
    assert Severity.MEDIUM <= Severity.MEDIUM
    assert Severity.HIGH >= Severity.HIGH


def test_alert_id_auto_generated() -> None:
    threat = ThreatAssessment(
        category=ThreatCategory.SUSPICIOUS,
        severity=Severity.MEDIUM,
        confidence=0.8,
        summary="test",
    )
    alert = Alert(threat=threat)
    assert alert.id != ""
    assert len(alert.id) == 36


def test_alert_default_status() -> None:
    threat = ThreatAssessment(
        category=ThreatCategory.NORMAL,
        severity=Severity.LOW,
        confidence=0.9,
        summary="ok",
    )
    alert = Alert(threat=threat)
    assert alert.status == AlertStatus.PENDING


def test_models_importable() -> None:
    assert LogEntry is DirectLogEntry
    assert AnonymizedEntry is not None
    assert ThreatAssessment is not None
    assert Alert is not None
    assert ThreatCategory is not None
    assert Severity is not None
    assert RecommendedAction is not None
    assert AlertStatus is not None
