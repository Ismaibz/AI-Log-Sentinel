"""Tests for alert formatters."""

from __future__ import annotations

import re

from ai_log_sentinel.alerting.formatters import (
    _escape_markdown_v2,
    format_console,
    format_telegram,
    severity_icon,
)
from ai_log_sentinel.models.alert import Alert, AlertStatus
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _make_alert(
    severity=Severity.HIGH,
    category=ThreatCategory.BRUTEFORCE,
    summary="Test threat",
    indicators=None,
    rules=None,
    status=AlertStatus.PENDING,
):
    threat = ThreatAssessment(
        category=category,
        severity=severity,
        confidence=0.9,
        summary=summary,
        indicators=indicators or ["test indicator"],
        recommended_action=RecommendedAction.BLOCK_IP,
        action_details={"ip": "1.2.3.4"},
    )
    if rules is None:
        rules = [
            {
                "rule_type": "ufw",
                "command": "sudo ufw deny from 1.2.3.4",
                "description": "Block",
                "critical": True,
                "rollback_command": "sudo ufw delete deny from 1.2.3.4",
            }
        ]
    return Alert(threat=threat, mitigation_rules=rules, status=status)


def test_format_console_contains_severity(sample_alert):
    output = _strip_ansi(format_console(sample_alert))
    assert "HIGH" in output


def test_format_console_contains_summary(sample_alert):
    output = _strip_ansi(format_console(sample_alert))
    assert "23 failed login attempts" in output


def test_format_console_contains_indicators(sample_alert):
    output = _strip_ansi(format_console(sample_alert))
    for indicator in sample_alert.threat.indicators:
        assert _strip_ansi(indicator) in output


def test_format_console_contains_mitigation(sample_alert):
    output = _strip_ansi(format_console(sample_alert))
    assert "sudo ufw deny from 192.168.1.100" in output


def test_format_console_contains_status(sample_alert):
    output = _strip_ansi(format_console(sample_alert))
    assert "PENDING" in output


def test_format_telegram_no_unescaped_special_chars():
    alert = _make_alert(summary="Alert: 1.2.3.4 tried login!")
    output = format_telegram(alert)
    escaped = _escape_markdown_v2("Alert: 1.2.3.4 tried login!")
    assert escaped in output
    assert "\\." in output
    assert "\\!" in output


def test_format_telegram_contains_category(sample_alert):
    output = format_telegram(sample_alert)
    assert "Brute Force" in output


def test_format_telegram_contains_mitigation(sample_alert):
    output = format_telegram(sample_alert)
    assert "sudo ufw deny from 192" in output


def test_severity_icon_returns_emoji():
    assert severity_icon(Severity.CRITICAL) != ""
    assert severity_icon(Severity.LOW) != ""


def test_escape_markdown_v2_escapes_dots():
    assert _escape_markdown_v2("1.2.3") == "1\\.2\\.3"


def test_escape_markdown_v2_escapes_hyphens():
    assert "\\-" in _escape_markdown_v2("2025-01-15")


def test_format_console_no_rules_no_mitigation_section():
    alert = _make_alert(rules=[])
    output = _strip_ansi(format_console(alert))
    assert "Mitigation" not in output
