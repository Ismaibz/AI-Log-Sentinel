"""Tests for HITL approval gate."""

from __future__ import annotations

import asyncio

import pytest

from ai_log_sentinel.mitigation.hitl import HITLGate
from ai_log_sentinel.models.alert import Alert, AlertStatus
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)


def _make_threat(
    severity: Severity = Severity.HIGH,
    action: RecommendedAction = RecommendedAction.BLOCK_IP,
) -> ThreatAssessment:
    return ThreatAssessment(
        category=ThreatCategory.MALICIOUS,
        severity=severity,
        confidence=0.9,
        summary="test threat",
        recommended_action=action,
        action_details={"ip": "1.2.3.4"},
    )


def _make_alert(
    threat: ThreatAssessment | None = None,
    rules: list[dict] | None = None,
) -> Alert:
    if threat is None:
        threat = _make_threat()
    return Alert(
        threat=threat,
        mitigation_rules=rules if rules is not None else [],
    )


class TestHITLGate:
    @pytest.mark.asyncio
    async def test_submit_critical_alert_is_pending(self):
        gate = HITLGate({"auto_approve_severity": []})
        threat = _make_threat(Severity.HIGH)
        rules = [{"rule_type": "ufw", "command": "sudo ufw deny from 1.2.3.4"}]
        alert = _make_alert(threat, rules)

        status = await gate.submit(alert)

        assert status == AlertStatus.PENDING
        assert alert.status == AlertStatus.PENDING
        assert alert.id in gate.pending

    @pytest.mark.asyncio
    async def test_auto_approve_low_severity(self):
        gate = HITLGate({"auto_approve_severity": ["low"]})
        threat = _make_threat(Severity.LOW, RecommendedAction.ALERT_ONLY)
        alert = _make_alert(threat, rules=[])

        status = await gate.submit(alert)

        assert status == AlertStatus.APPROVED
        assert alert.auto_action is True
        assert alert.id not in gate.pending

    @pytest.mark.asyncio
    async def test_auto_approve_does_not_apply_to_critical_rules(self):
        gate = HITLGate({"auto_approve_severity": ["low"]})
        threat = _make_threat(Severity.LOW)
        rules = [{"rule_type": "ufw", "command": "sudo ufw deny from 1.2.3.4"}]
        alert = _make_alert(threat, rules)

        status = await gate.submit(alert)

        assert status == AlertStatus.PENDING
        assert alert.id in gate.pending

    @pytest.mark.asyncio
    async def test_approve_removes_from_pending(self):
        gate = HITLGate({"auto_approve_severity": []})
        threat = _make_threat(Severity.HIGH)
        alert = _make_alert(threat)

        await gate.submit(alert)
        assert alert.id in gate.pending

        await gate.approve(alert.id)

        assert alert.status == AlertStatus.APPROVED
        assert alert.id not in gate.pending
        assert alert.resolved_at is not None

    @pytest.mark.asyncio
    async def test_reject_removes_from_pending(self):
        gate = HITLGate({"auto_approve_severity": []})
        threat = _make_threat(Severity.HIGH)
        alert = _make_alert(threat)

        await gate.submit(alert)
        await gate.reject(alert.id)

        assert alert.status == AlertStatus.REJECTED
        assert alert.id not in gate.pending
        assert alert.resolved_at is not None

    @pytest.mark.asyncio
    async def test_approve_unknown_alert_is_noop(self):
        gate = HITLGate({"auto_approve_severity": []})
        await gate.approve("nonexistent-id")

    @pytest.mark.asyncio
    async def test_reject_unknown_alert_is_noop(self):
        gate = HITLGate({"auto_approve_severity": []})
        await gate.reject("nonexistent-id")

    @pytest.mark.asyncio
    async def test_timeout_expires_pending_alert(self):
        config = {"hitl": {"timeout": 1}, "auto_approve_severity": []}
        gate = HITLGate(config)
        threat = _make_threat(Severity.HIGH)
        alert = _make_alert(threat)

        await gate.start_timeout_watcher()
        await gate.submit(alert)
        assert alert.status == AlertStatus.PENDING

        await asyncio.sleep(12)

        assert alert.status == AlertStatus.EXPIRED
        assert alert.id not in gate.pending
        gate.stop_timeout_watcher()

    def test_is_critical_high_severity(self):
        gate = HITLGate({})
        threat = _make_threat(Severity.HIGH)
        alert = _make_alert(threat, rules=[])

        assert gate.is_critical(alert) is True

    def test_is_critical_ufw_rule(self):
        gate = HITLGate({})
        threat = _make_threat(Severity.LOW)
        rules = [{"rule_type": "ufw", "command": "sudo ufw deny from 1.2.3.4"}]
        alert = _make_alert(threat, rules)

        assert gate.is_critical(alert) is True

    def test_is_not_critical_low_severity_no_rules(self):
        gate = HITLGate({})
        threat = _make_threat(Severity.LOW, RecommendedAction.ALERT_ONLY)
        alert = _make_alert(threat, rules=[])

        assert gate.is_critical(alert) is False

    @pytest.mark.asyncio
    async def test_on_approved_callback_called(self):
        gate = HITLGate({"auto_approve_severity": []})
        threat = _make_threat(Severity.HIGH)
        alert = _make_alert(threat)

        called_with: Alert | None = None

        async def on_approved(a: Alert) -> None:
            nonlocal called_with
            called_with = a

        gate.on_approved(on_approved)
        await gate.submit(alert)
        await gate.approve(alert.id)

        assert called_with is alert
