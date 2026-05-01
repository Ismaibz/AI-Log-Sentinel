"""Unit tests for L1 local rules engine."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.log_entry import LogEntry
from ai_log_sentinel.models.threat import RecommendedAction, Severity, ThreatCategory
from ai_log_sentinel.reasoning.local_rules import LocalRuleEngine

BASIC_CONFIG = {"reasoning": {"rules": {"enabled": True}}}


def _make_entry(
    ip: str = "10.0.0.1",
    method: str = "GET",
    path: str = "/",
    status: int = 200,
    ua: str = "Mozilla/5.0",
    is_noise: bool = False,
) -> AnonymizedEntry:
    return AnonymizedEntry(
        original=LogEntry(
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            source_ip=ip,
            method=method,
            path=path,
            status_code=status,
            response_size=100,
            user_agent=ua,
            referer="",
            raw_line=(
                f"{ip} - - [01/Jan/2026:12:00:00 +0000] "
                f'"{method} {path} HTTP/1.1" {status} 100 "-" "{ua}"'
            ),
            source_label="test",
        ),
        sanitized_line=f'{ip} - - "{method} {path} HTTP/1.1" {status}',
        is_noise=is_noise,
    )


@pytest.mark.unit
class TestSQLiDetection:
    def test_union_select(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(path="/search?q=UNION SELECT * FROM users", status=200)]
        results, _ = engine.evaluate(entries)
        assert len(results) == 1
        assert results[0].category == ThreatCategory.EXPLOIT_ATTEMPT
        assert results[0].severity == Severity.CRITICAL
        assert results[0].recommended_action == RecommendedAction.BLOCK_IP
        assert results[0].analyzed_by == "local_rules"

    def test_or_one_equals_one(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(path="/login?user=admin&pass=' OR 1=1--", status=200)]
        results, _ = engine.evaluate(entries)
        assert len(results) == 1
        assert results[0].category == ThreatCategory.EXPLOIT_ATTEMPT

    def test_url_encoded_sqli(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(path="/search?q=%27OR+1%3D1", status=200)]
        results, _ = engine.evaluate(entries)
        assert len(results) >= 1

    def test_normal_path_no_match(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(path="/search?q=hello", status=200)]
        assert engine.evaluate(entries) == ([], [])


@pytest.mark.unit
class TestTraversalDetection:
    def test_dotdot_slash(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(path="/../../../etc/passwd", status=200)]
        results, _ = engine.evaluate(entries)
        assert len(results) == 1
        assert results[0].category == ThreatCategory.EXPLOIT_ATTEMPT
        assert results[0].severity == Severity.HIGH

    def test_encoded_traversal(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(path="/..%2f..%2fetc/passwd", status=200)]
        results, _ = engine.evaluate(entries)
        assert len(results) >= 1

    def test_normal_path_no_traversal(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(path="/api/v1/users", status=200)]
        assert engine.evaluate(entries) == ([], [])


@pytest.mark.unit
class TestBruteforceDetection:
    def test_five_failed_logins(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(ip="10.0.0.1", method="POST", path="/login", status=401) for _ in range(5)
        ]
        results, _ = engine.evaluate(entries)
        assert len(results) == 1
        assert results[0].category == ThreatCategory.BRUTEFORCE
        assert results[0].severity == Severity.HIGH
        assert results[0].recommended_action == RecommendedAction.BLOCK_IP
        assert "10.0.0.1" in results[0].action_details.get("ips", [])

    def test_four_failed_no_match(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(ip="10.0.0.1", method="POST", path="/login", status=401) for _ in range(4)
        ]
        assert engine.evaluate(entries) == ([], [])

    def test_successful_login_no_match(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(ip="10.0.0.1", method="POST", path="/login", status=200) for _ in range(10)
        ]
        assert engine.evaluate(entries) == ([], [])

    def test_different_ips_no_match(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(ip=f"10.0.0.{i}", method="POST", path="/login", status=401)
            for i in range(5)
        ]
        assert engine.evaluate(entries) == ([], [])

    def test_custom_threshold(self):
        config = {"reasoning": {"rules": {"enabled": True, "brute_force_threshold": 3}}}
        engine = LocalRuleEngine(config)
        entries = [
            _make_entry(ip="10.0.0.1", method="POST", path="/login", status=401) for _ in range(3)
        ]
        results, _ = engine.evaluate(entries)
        assert len(results) == 1
        assert results[0].category == ThreatCategory.BRUTEFORCE


@pytest.mark.unit
class TestScannerDetection:
    def test_nikto_user_agent(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(ip="10.0.0.1", path="/admin", status=403, ua="Nikto/2.1.6"),
            _make_entry(ip="10.0.0.1", path="/etc/passwd", status=404, ua="Nikto/2.1.6"),
        ]
        results, _ = engine.evaluate(entries)
        assert len(results) >= 1
        assert results[0].category == ThreatCategory.SCAN
        assert results[0].severity == Severity.HIGH

    def test_sqlmap_user_agent(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(ip="10.0.0.1", path="/search", ua="sqlmap/1.7")]
        results, _ = engine.evaluate(entries)
        assert len(results) >= 1
        assert "sqlmap" in results[0].summary.lower()

    def test_normal_ua_no_match(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(ip="10.0.0.1", path="/", ua="Mozilla/5.0")]
        assert engine.evaluate(entries) == ([], [])


@pytest.mark.unit
class TestPathFuzzing:
    def test_five_distinct_404s(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(ip="10.0.0.1", path=f"/path{i}", status=404) for i in range(5)]
        results, _ = engine.evaluate(entries)
        assert len(results) == 1
        assert results[0].category == ThreatCategory.SCAN
        assert results[0].severity == Severity.MEDIUM
        assert results[0].recommended_action == RecommendedAction.RATE_LIMIT

    def test_four_distinct_no_match(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(ip="10.0.0.1", path=f"/path{i}", status=404) for i in range(4)]
        assert engine.evaluate(entries) == ([], [])


@pytest.mark.unit
class TestMultipleMatches:
    def test_sqli_plus_bruteforce(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(ip="10.0.0.1", path="/search?q=UNION SELECT *", status=200),
            *[
                _make_entry(ip="10.0.0.2", method="POST", path="/login", status=401)
                for _ in range(5)
            ],
        ]
        results, _ = engine.evaluate(entries)
        assert len(results) == 2
        categories = {r.category for r in results}
        assert ThreatCategory.EXPLOIT_ATTEMPT in categories
        assert ThreatCategory.BRUTEFORCE in categories

    def test_bruteforce_plus_scanner(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            *[
                _make_entry(ip="10.0.0.1", method="POST", path="/login", status=401)
                for _ in range(5)
            ],
            _make_entry(ip="10.0.0.2", path="/admin", status=403, ua="Nikto/2.1.6"),
        ]
        results, _ = engine.evaluate(entries)
        assert len(results) == 2
        categories = {r.category for r in results}
        assert ThreatCategory.BRUTEFORCE in categories
        assert ThreatCategory.SCAN in categories


@pytest.mark.unit
class TestRulePrecedence:
    def test_sqli_over_bruteforce(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(
                ip="10.0.0.1",
                method="POST",
                path="/login?q=UNION SELECT",
                status=401,
            ),
        ]
        results, _ = engine.evaluate(entries)
        assert results[0].category == ThreatCategory.EXPLOIT_ATTEMPT

    def test_traversal_over_scanner(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [
            _make_entry(
                ip="10.0.0.1",
                path="/../../etc/passwd",
                ua="Nikto/2.1.6",
            ),
        ]
        results, _ = engine.evaluate(entries)
        assert results[0].category == ThreatCategory.EXPLOIT_ATTEMPT


@pytest.mark.unit
class TestDisabledRules:
    def test_disabled_returns_empty(self):
        config = {"reasoning": {"rules": {"enabled": False}}}
        engine = LocalRuleEngine(config)
        entries = [
            _make_entry(ip="10.0.0.1", method="POST", path="/login", status=401) for _ in range(10)
        ]
        assert engine.evaluate(entries) == ([], [])


@pytest.mark.unit
class TestNoiseHandling:
    def test_noise_entries_ignored(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        entries = [_make_entry(is_noise=True) for _ in range(10)]
        assert engine.evaluate(entries) == ([], [])

    def test_empty_entries(self):
        engine = LocalRuleEngine(BASIC_CONFIG)
        assert engine.evaluate([]) == ([], [])
