"""Tests for mitigation executor."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ai_log_sentinel.mitigation.executor import CommandResult, ExecutionRecord, MitigationExecutor
from ai_log_sentinel.models.alert import Alert, AlertStatus
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)


def _make_config(**overrides):
    config = {
        "dry_run": True,
        "rollback_on_failure": True,
        "ufw_cmd": "sudo ufw",
        "nginx_config_dir": "/tmp/test_nginx",
        "nginx_reload_cmd": "echo reload",
    }
    config.update(overrides)
    return config


def _make_alert(status=AlertStatus.APPROVED, rules=None):
    threat = ThreatAssessment(
        category=ThreatCategory.BRUTEFORCE,
        severity=Severity.HIGH,
        confidence=0.9,
        summary="test",
        recommended_action=RecommendedAction.BLOCK_IP,
        action_details={"ip": "1.2.3.4"},
    )
    if rules is None:
        rules = [
            {
                "rule_type": "ufw",
                "command": "sudo ufw deny from 1.2.3.4",
                "description": "test",
                "critical": True,
                "rollback_command": "sudo ufw delete deny from 1.2.3.4",
            }
        ]
    return Alert(threat=threat, mitigation_rules=rules, status=status)


@pytest.fixture
def executor(tmp_path):
    with patch("ai_log_sentinel.mitigation.executor._LOG_PATH", tmp_path / "execution_log.json"):
        ex = MitigationExecutor(_make_config())
        yield ex


async def test_dry_run_mode_logs_without_executing(executor):
    alert = _make_alert()
    result = await executor.execute(alert)

    assert result.success is True
    assert result.dry_run is True
    assert result.results[0].output.startswith("[DRY RUN]")
    assert alert.status == AlertStatus.EXECUTED


async def test_execute_non_approved_alert_fails(executor):
    alert = _make_alert(status=AlertStatus.PENDING)
    result = await executor.execute(alert)

    assert result.success is False
    assert result.results == []


async def test_execute_empty_rules_succeeds(executor):
    alert = _make_alert(rules=[])
    result = await executor.execute(alert)

    assert result.success is True
    assert alert.status == AlertStatus.EXECUTED


async def test_execution_record_stored_in_log(executor):
    alert = _make_alert()
    await executor.execute(alert)

    assert len(executor.execution_log) == 1
    assert alert.id in executor._alert_records


async def test_rollback_returns_none_for_unknown_alert(executor):
    result = await executor.rollback("nonexistent")
    assert result is None


async def test_rollback_in_dry_run_mode(executor):
    alert = _make_alert()
    await executor.execute(alert)

    record = await executor.rollback(alert.id)
    assert record is not None
    assert record.dry_run is True
    assert len(record.results) == 1
    assert record.results[0].output.startswith("[DRY RUN]")


def test_command_result_to_dict_roundtrip():
    cr = CommandResult(
        rule_type="ufw",
        command="sudo ufw deny from 1.2.3.4",
        success=True,
        output="Rule added",
        rollback_command="sudo ufw delete deny from 1.2.3.4",
    )
    d = cr.__dict__.copy()
    assert d["rule_type"] == "ufw"
    assert d["command"] == "sudo ufw deny from 1.2.3.4"
    assert d["success"] is True

    from datetime import datetime

    er = ExecutionRecord(
        alert_id="test-id",
        results=[cr],
        success=True,
        executed_at=datetime(2025, 1, 15, 10, 30, 0),
        dry_run=True,
    )
    serialized = er.to_dict()
    restored = ExecutionRecord.from_dict(serialized)
    assert restored.alert_id == er.alert_id
    assert restored.success == er.success
    assert restored.dry_run == er.dry_run
    assert len(restored.results) == 1
    assert restored.results[0].command == cr.command
    assert restored.results[0].success == cr.success
    assert restored.results[0].output == cr.output
