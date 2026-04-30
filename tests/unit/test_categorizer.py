"""Tests for threat categorizer and escalation logic."""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.log_entry import LogEntry
from ai_log_sentinel.models.threat import (
    Severity,
    ThreatCategory,
)
from ai_log_sentinel.reasoning.categorizer import ThreatCategorizer
from ai_log_sentinel.reasoning.escalation import should_escalate

FLASH_JSON = json.dumps(
    {
        "category": "suspicious",
        "severity": "medium",
        "confidence": 0.8,
        "summary": "Suspicious activity detected",
        "indicators": ["/admin", "403"],
    }
)

PRO_JSON = json.dumps(
    {
        "threat_type": "directory_traversal",
        "severity": "high",
        "confidence": 0.9,
        "attack_pattern": "path traversal attempt",
        "mitre_ttps": ["T1190"],
        "recommended_action": "block_ip",
        "action_details": "Block source IP",
        "summary": "Directory traversal attack detected",
    }
)


def _make_entry(sanitized: str, is_noise: bool = False) -> AnonymizedEntry:
    return AnonymizedEntry(
        original=LogEntry(
            timestamp=datetime(2025, 1, 15, 10, 30, 45),
            source_ip="1.2.3.4",
            method="GET",
            path="/test",
            status_code=200,
            response_size=100,
            user_agent="test",
            referer="",
            raw_line="test",
            source_label="test",
        ),
        sanitized_line=sanitized,
        is_noise=is_noise,
    )


class MockGeminiClient:
    def __init__(self, flash_response: str = "", pro_response: str = ""):
        self.flash_response = flash_response
        self.pro_response = pro_response
        self.flash_calls = 0
        self.pro_calls = 0

    async def analyze_flash(self, prompt, log_batch):
        self.flash_calls += 1
        return self.flash_response

    async def analyze_pro(self, prompt, log_batch):
        self.pro_calls += 1
        return self.pro_response


@pytest.fixture
def escalation_config():
    return {
        "reasoning": {
            "escalation_confidence": 0.6,
            "escalation": {
                "always_escalate": ["exploit_attempt", "bruteforce"],
                "always_escalate_severity": ["high", "critical"],
            },
        }
    }


@pytest.fixture
def categorizer_config():
    return {
        "reasoning": {
            "batch_size": 10,
            "escalation_confidence": 0.6,
            "escalation": {
                "always_escalate": ["exploit_attempt", "bruteforce"],
                "always_escalate_severity": ["high", "critical"],
            },
        }
    }


@pytest.mark.unit
class TestShouldEscalate:
    def test_high_confidence_no_escalate(self, escalation_config):
        result = {"category": "normal", "confidence": 0.9, "severity": "low"}
        assert should_escalate(result, escalation_config) is False

    def test_low_confidence_escalate(self, escalation_config):
        result = {"category": "suspicious", "confidence": 0.3, "severity": "low"}
        assert should_escalate(result, escalation_config) is True

    def test_exploit_attempt_high_conf_no_escalate(self, escalation_config):
        result = {"category": "exploit_attempt", "confidence": 0.9, "severity": "low"}
        assert should_escalate(result, escalation_config) is False

    def test_bruteforce_high_conf_no_escalate(self, escalation_config):
        result = {"category": "bruteforce", "confidence": 0.9, "severity": "low"}
        assert should_escalate(result, escalation_config) is False

    def test_high_severity_high_conf_no_escalate(self, escalation_config):
        result = {"category": "suspicious", "confidence": 0.9, "severity": "high"}
        assert should_escalate(result, escalation_config) is False

    def test_critical_severity_high_conf_no_escalate(self, escalation_config):
        result = {"category": "suspicious", "confidence": 0.9, "severity": "critical"}
        assert should_escalate(result, escalation_config) is False

    def test_suspicious_medium_conf_escalate(self, escalation_config):
        result = {"category": "suspicious", "confidence": 0.5, "severity": "medium"}
        assert should_escalate(result, escalation_config) is True

    def test_scan_medium_conf_escalate(self, escalation_config):
        result = {"category": "scan", "confidence": 0.7, "severity": "medium"}
        assert should_escalate(result, escalation_config) is True

    def test_normal_no_escalate(self, escalation_config):
        result = {"category": "normal", "confidence": 0.8, "severity": "low"}
        assert should_escalate(result, escalation_config) is False


@pytest.mark.unit
class TestThreatCategorizer:
    async def _make_categorizer(
        self, config, flash_response="", pro_response=""
    ) -> tuple[ThreatCategorizer, MockGeminiClient]:
        mock = MockGeminiClient(flash_response=flash_response, pro_response=pro_response)
        cat = ThreatCategorizer(client=mock, config=config)
        return cat, mock

    async def test_all_noise_returns_empty(self, categorizer_config):
        cat, mock = await self._make_categorizer(categorizer_config)
        entries = [_make_entry("noise", is_noise=True) for _ in range(3)]
        results = await cat.categorize(entries)
        assert results == []
        assert mock.flash_calls == 0

    async def test_high_confidence_flash_passes_through(self, categorizer_config):
        cat, mock = await self._make_categorizer(categorizer_config, flash_response=FLASH_JSON)
        entries = [_make_entry("GET /admin HTTP/1.1 403")]
        results = await cat.categorize(entries)
        assert len(results) == 1
        assert results[0].analyzed_by == "flash"
        assert results[0].category == ThreatCategory.SUSPICIOUS
        assert results[0].severity == Severity.MEDIUM
        assert results[0].confidence == 0.8
        assert mock.pro_calls == 0

    async def test_low_confidence_triggers_pro(self, categorizer_config):
        low_flash = json.dumps(
            {
                "category": "suspicious",
                "severity": "medium",
                "confidence": 0.3,
                "summary": "Uncertain",
                "indicators": [],
            }
        )
        cat, mock = await self._make_categorizer(
            categorizer_config, flash_response=low_flash, pro_response=PRO_JSON
        )
        entries = [_make_entry("GET /admin HTTP/1.1 403")]
        results = await cat.categorize(entries)
        assert len(results) == 1
        assert results[0].analyzed_by == "pro"
        assert mock.flash_calls == 1
        assert mock.pro_calls == 1

    async def test_exploit_attempt_stays_flash(self, categorizer_config):
        exploit_flash = json.dumps(
            {
                "category": "exploit_attempt",
                "severity": "critical",
                "confidence": 0.9,
                "summary": "Exploit detected",
                "indicators": ["../../etc/passwd"],
            }
        )
        cat, mock = await self._make_categorizer(
            categorizer_config, flash_response=exploit_flash, pro_response=PRO_JSON
        )
        entries = [_make_entry("GET /../../etc/passwd HTTP/1.1 200")]
        results = await cat.categorize(entries)
        assert len(results) == 1
        assert results[0].analyzed_by == "flash"
        assert mock.pro_calls == 0

    async def test_malformed_json_response(self, categorizer_config):
        cat, _mock = await self._make_categorizer(categorizer_config, flash_response="not json")
        entries = [_make_entry("GET /something HTTP/1.1 200")]
        results = await cat.categorize(entries)
        assert len(results) == 1
        assert results[0].category == ThreatCategory.NORMAL
        assert results[0].confidence == 0.0
        assert results[0].severity == Severity.LOW

    async def test_pro_parse_failure_keeps_flash(self, categorizer_config):
        low_flash = json.dumps(
            {
                "category": "suspicious",
                "severity": "medium",
                "confidence": 0.3,
                "summary": "Uncertain",
                "indicators": [],
            }
        )
        cat, _mock = await self._make_categorizer(
            categorizer_config, flash_response=low_flash, pro_response="garbage{"
        )
        entries = [_make_entry("GET /admin HTTP/1.1 403")]
        results = await cat.categorize(entries)
        assert len(results) == 1
        assert results[0].analyzed_by == "flash"
        assert results[0].category == ThreatCategory.SUSPICIOUS
        assert results[0].confidence == 0.3

    async def test_batch_size_respected(self, categorizer_config):
        small_batch_config = {
            "reasoning": {
                "batch_size": 2,
                "escalation_confidence": 0.6,
                "escalation": {
                    "always_escalate": ["exploit_attempt", "bruteforce"],
                    "always_escalate_severity": ["high", "critical"],
                },
            }
        }
        cat, mock = await self._make_categorizer(small_batch_config, flash_response=FLASH_JSON)
        entries = [_make_entry(f"GET /page{i} HTTP/1.1 200") for i in range(5)]
        results = await cat.categorize(entries)
        assert len(results) == 3
        assert mock.flash_calls == 3
