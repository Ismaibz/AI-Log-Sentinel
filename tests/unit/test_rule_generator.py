"""Tests for rule generator."""

from __future__ import annotations

from ai_log_sentinel.anonymizer.token_store import TokenStore
from ai_log_sentinel.mitigation.rule_generator import RuleGenerator
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)


def _make_threat(
    action: RecommendedAction = RecommendedAction.BLOCK_IP,
    severity: Severity = Severity.HIGH,
    action_details: dict | None = None,
) -> ThreatAssessment:
    return ThreatAssessment(
        category=ThreatCategory.MALICIOUS,
        severity=severity,
        confidence=0.9,
        summary="test threat",
        recommended_action=action,
        action_details=action_details or {},
    )


def _make_generator(
    config: dict | None = None, token_store: TokenStore | None = None
) -> RuleGenerator:
    return RuleGenerator(
        config=config or {},
        token_store=token_store or TokenStore(),
    )


class TestRuleGenerator:
    def test_block_ip_generates_ufw_and_nginx_rules(self):
        gen = _make_generator()
        threat = _make_threat(
            action=RecommendedAction.BLOCK_IP,
            action_details={"ip": "1.2.3.4"},
        )
        rules = gen.generate(threat)

        assert len(rules) == 2
        assert rules[0].rule_type == "ufw"
        assert rules[0].command == "sudo ufw deny from 1.2.3.4"
        assert rules[0].critical is True
        assert rules[0].rollback_command == "sudo ufw delete deny from 1.2.3.4"

        assert rules[1].rule_type == "nginx_deny"
        assert rules[1].command == "deny 1.2.3.4;"
        assert rules[1].critical is True

    def test_block_ip_multiple_ips(self):
        gen = _make_generator()
        threat = _make_threat(
            action=RecommendedAction.BLOCK_IP,
            action_details={"ips": ["1.2.3.4", "5.6.7.8"]},
        )
        rules = gen.generate(threat)

        assert len(rules) == 4
        assert rules[0].rule_type == "ufw"
        assert "1.2.3.4" in rules[0].command
        assert rules[1].rule_type == "nginx_deny"
        assert "1.2.3.4" in rules[1].command
        assert rules[2].rule_type == "ufw"
        assert "5.6.7.8" in rules[2].command
        assert rules[3].rule_type == "nginx_deny"
        assert "5.6.7.8" in rules[3].command

    def test_block_path_generates_nginx_deny(self):
        gen = _make_generator()
        threat = _make_threat(
            action=RecommendedAction.BLOCK_PATH,
            action_details={"path": "/admin"},
        )
        rules = gen.generate(threat)

        assert len(rules) == 1
        assert rules[0].rule_type == "nginx_deny"
        assert "location /admin { deny all; }" in rules[0].command

    def test_rate_limit_generates_zone_rule(self):
        gen = _make_generator()
        threat = _make_threat(
            action=RecommendedAction.RATE_LIMIT,
            action_details={"zone_name": "test", "rate": "10r/m"},
        )
        rules = gen.generate(threat)

        assert len(rules) >= 1
        assert rules[0].rule_type == "rate_limit"
        assert rules[0].critical is False
        assert "zone=test" in rules[0].command
        assert "rate=10r/m" in rules[0].command

    def test_rate_limit_with_path_generates_apply_rule(self):
        gen = _make_generator()
        threat = _make_threat(
            action=RecommendedAction.RATE_LIMIT,
            action_details={"zone_name": "test", "rate": "10r/m", "path": "/login"},
        )
        rules = gen.generate(threat)

        assert len(rules) == 2
        assert rules[0].rule_type == "rate_limit"
        assert rules[1].rule_type == "rate_limit"
        assert "/login" in rules[1].description

    def test_alert_only_generates_no_rules(self):
        gen = _make_generator()
        threat = _make_threat(action=RecommendedAction.ALERT_ONLY)
        assert gen.generate(threat) == []

    def test_investigate_generates_no_rules(self):
        gen = _make_generator()
        threat = _make_threat(action=RecommendedAction.INVESTIGATE)
        assert gen.generate(threat) == []

    def test_anonymized_ip_resolved_via_token_store(self):
        ts = TokenStore()
        ts.add("10.0.0.1", "[IP_001]")
        gen = _make_generator(token_store=ts)
        threat = _make_threat(
            action=RecommendedAction.BLOCK_IP,
            action_details={"ip": "[IP_001]"},
        )
        rules = gen.generate(threat)

        assert len(rules) == 2
        assert "10.0.0.1" in rules[0].command
        assert "10.0.0.1" in rules[1].command

    def test_unresolvable_ip_token_uses_token_as_is(self):
        gen = _make_generator()
        threat = _make_threat(
            action=RecommendedAction.BLOCK_IP,
            action_details={"ip": "[IP_999]"},
        )
        rules = gen.generate(threat)

        assert len(rules) == 2
        assert "[IP_999]" in rules[0].command
        assert "[IP_999]" in rules[1].command

    def test_rollback_commands_are_inverse(self):
        gen = _make_generator()
        threat = _make_threat(
            action=RecommendedAction.BLOCK_IP,
            action_details={"ip": "1.2.3.4"},
        )
        rules = gen.generate(threat)

        ufw_rule = rules[0]
        assert ufw_rule.rollback_command.startswith("sudo ufw delete deny from")

        nginx_rule = rules[1]
        assert "# remove:" in nginx_rule.rollback_command
