"""Integration test — full alerting + mitigation flow."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

import pytest

from ai_log_sentinel.alerting.dispatcher import AlertDispatcher
from ai_log_sentinel.anonymizer.token_store import TokenStore
from ai_log_sentinel.mitigation.executor import MitigationExecutor
from ai_log_sentinel.mitigation.hitl import HITLGate
from ai_log_sentinel.mitigation.rule_generator import MitigationRule, RuleGenerator
from ai_log_sentinel.models.alert import Alert, AlertStatus
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)


class MockDispatcher(AlertDispatcher):
    def __init__(self):
        self.sent: list[Alert] = []
        self.responses: list[tuple[str, bool]] = []

    async def send(self, alert: Alert) -> bool:
        self.sent.append(alert)
        return True

    async def handle_response(self, alert_id: str, approved: bool) -> None:
        self.responses.append((alert_id, approved))


def _make_config(**overrides: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "mitigation": {
            "executor": {
                "dry_run": True,
                "ufw_cmd": "sudo ufw",
                "nginx_config_dir": "/tmp/test_nginx",
                "nginx_reload_cmd": "echo reload",
                "rollback_on_failure": True,
            },
            "auto_approve_severity": [],
            "hitl": {"timeout": 300},
        }
    }
    for key, val in overrides.items():
        parts = key.split(".")
        target = cfg
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = val
    return cfg


def _rules_to_dicts(rules: list[MitigationRule]) -> list[dict[str, Any]]:
    return [asdict(r) for r in rules]


def _make_threat(
    action: RecommendedAction = RecommendedAction.BLOCK_IP,
    severity: Severity = Severity.HIGH,
    action_details: dict[str, Any] | None = None,
    category: ThreatCategory = ThreatCategory.BRUTEFORCE,
) -> ThreatAssessment:
    return ThreatAssessment(
        category=category,
        severity=severity,
        confidence=0.9,
        summary="Test threat",
        indicators=["test indicator"],
        recommended_action=action,
        action_details=action_details or {},
        analyzed_by="flash",
        timestamp=datetime(2025, 1, 15, 10, 30, 45),
    )


@pytest.mark.asyncio
async def test_full_flow_threat_to_dry_run_execution():
    config = _make_config()
    token_store = TokenStore()
    generator = RuleGenerator(config, token_store)
    hitl = HITLGate(config["mitigation"])
    executor = MitigationExecutor(config["mitigation"]["executor"])
    dispatcher = MockDispatcher()

    threat = _make_threat(
        action=RecommendedAction.BLOCK_IP,
        severity=Severity.HIGH,
        action_details={"ip": "1.2.3.4"},
    )

    rules = generator.generate(threat)
    assert len(rules) >= 2

    alert = Alert(threat=threat, mitigation_rules=_rules_to_dicts(rules))
    assert alert.status == AlertStatus.PENDING

    await dispatcher.send(alert)
    status = await hitl.submit(alert)
    assert status == AlertStatus.PENDING

    await hitl.approve(alert.id)
    assert alert.status == AlertStatus.APPROVED

    record = await executor.execute(alert)
    assert alert.status == AlertStatus.EXECUTED
    assert record.dry_run is True
    assert all("[DRY RUN]" in r.output for r in record.results)
    assert alert.id in executor._alert_records

    assert len(dispatcher.sent) == 1
    assert dispatcher.sent[0].id == alert.id


@pytest.mark.asyncio
async def test_rejected_alert_does_not_execute():
    config = _make_config()
    token_store = TokenStore()
    generator = RuleGenerator(config, token_store)
    hitl = HITLGate(config["mitigation"])
    executor = MitigationExecutor(config["mitigation"]["executor"])
    dispatcher = MockDispatcher()

    threat = _make_threat(
        action=RecommendedAction.BLOCK_IP,
        severity=Severity.HIGH,
        action_details={"ip": "5.6.7.8"},
    )

    rules = generator.generate(threat)
    alert = Alert(threat=threat, mitigation_rules=_rules_to_dicts(rules))

    await dispatcher.send(alert)
    await hitl.submit(alert)
    assert alert.status == AlertStatus.PENDING

    await hitl.reject(alert.id)
    assert alert.status == AlertStatus.REJECTED

    record = await executor.execute(alert)
    assert record.success is False
    assert len(record.results) == 0
    assert alert.id not in executor._alert_records

    assert len(dispatcher.sent) == 1


@pytest.mark.asyncio
async def test_auto_approved_low_severity_executes():
    config = _make_config(**{"mitigation.auto_approve_severity": ["low"]})
    token_store = TokenStore()
    generator = RuleGenerator(config, token_store)
    hitl = HITLGate(config["mitigation"])
    executor = MitigationExecutor(config["mitigation"]["executor"])
    dispatcher = MockDispatcher()

    threat = _make_threat(
        action=RecommendedAction.RATE_LIMIT,
        severity=Severity.LOW,
        action_details={"zone_name": "low_limit", "rate": "5r/m"},
        category=ThreatCategory.SUSPICIOUS,
    )

    rules = generator.generate(threat)
    assert len(rules) >= 1

    alert = Alert(threat=threat, mitigation_rules=_rules_to_dicts(rules))

    await dispatcher.send(alert)
    status = await hitl.submit(alert)
    assert status == AlertStatus.APPROVED
    assert alert.auto_action is True

    record = await executor.execute(alert)
    assert record.success is True
    assert alert.status == AlertStatus.EXECUTED


@pytest.mark.asyncio
async def test_block_path_generates_and_executes_nginx_rule():
    config = _make_config()
    token_store = TokenStore()
    generator = RuleGenerator(config, token_store)
    hitl = HITLGate(config["mitigation"])
    executor = MitigationExecutor(config["mitigation"]["executor"])
    dispatcher = MockDispatcher()

    threat = _make_threat(
        action=RecommendedAction.BLOCK_PATH,
        severity=Severity.HIGH,
        action_details={"path": "/admin"},
        category=ThreatCategory.EXPLOIT_ATTEMPT,
    )

    rules = generator.generate(threat)
    nginx_rules = [r for r in rules if r.rule_type == "nginx_deny"]
    assert len(nginx_rules) >= 1
    assert "deny all" in nginx_rules[0].command
    assert "/admin" in nginx_rules[0].command

    alert = Alert(threat=threat, mitigation_rules=_rules_to_dicts(rules))

    await dispatcher.send(alert)
    await hitl.submit(alert)
    await hitl.approve(alert.id)
    assert alert.status == AlertStatus.APPROVED

    record = await executor.execute(alert)
    assert record.success is True
    assert alert.status == AlertStatus.EXECUTED
    nginx_results = [r for r in record.results if r.rule_type == "nginx_deny"]
    assert len(nginx_results) >= 1
    assert "[DRY RUN]" in nginx_results[0].output


@pytest.mark.asyncio
async def test_rate_limit_not_critical_auto_approved():
    config = _make_config(**{"mitigation.auto_approve_severity": ["medium"]})
    token_store = TokenStore()
    generator = RuleGenerator(config, token_store)
    hitl = HITLGate(config["mitigation"])
    executor = MitigationExecutor(config["mitigation"]["executor"])
    dispatcher = MockDispatcher()

    threat = _make_threat(
        action=RecommendedAction.RATE_LIMIT,
        severity=Severity.MEDIUM,
        action_details={"zone_name": "api_limit", "rate": "10r/m"},
        category=ThreatCategory.SUSPICIOUS,
    )

    rules = generator.generate(threat)
    assert len(rules) >= 1
    assert all(r.critical is False for r in rules)

    alert = Alert(threat=threat, mitigation_rules=_rules_to_dicts(rules))

    assert not hitl.is_critical(alert)

    await dispatcher.send(alert)
    status = await hitl.submit(alert)
    assert status == AlertStatus.APPROVED
    assert alert.auto_action is True

    record = await executor.execute(alert)
    assert record.success is True
    assert alert.status == AlertStatus.EXECUTED
    assert any("rate_limit" in r.rule_type for r in record.results)
