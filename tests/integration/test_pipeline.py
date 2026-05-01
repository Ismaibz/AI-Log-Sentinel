"""Integration test — full pipeline E2E."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from ai_log_sentinel.anonymizer.engine import AnonymizationEngine
from ai_log_sentinel.ingestion.log_source import LogSource
from ai_log_sentinel.ingestion.parsers import build_parsers
from ai_log_sentinel.ingestion.tailer import LogTailer
from ai_log_sentinel.models.log_entry import LogEntry
from ai_log_sentinel.models.threat import (
    Severity,
    ThreatAssessment,
    ThreatCategory,
)
from ai_log_sentinel.reasoning.categorizer import ThreatCategorizer
from ai_log_sentinel.reasoning.providers.base import ReasoningProvider

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

MALICIOUS_FLASH = json.dumps(
    {
        "category": "exploit_attempt",
        "severity": "critical",
        "confidence": 0.9,
        "summary": "Directory traversal attempt",
        "indicators": ["../../etc/passwd"],
    }
)

SCAN_FLASH = json.dumps(
    {
        "category": "scan",
        "severity": "medium",
        "confidence": 0.85,
        "summary": "404 scan detected",
        "indicators": ["multiple 404s"],
    }
)

PRO_ANALYSIS = json.dumps(
    {
        "threat_type": "directory_traversal",
        "severity": "critical",
        "confidence": 0.95,
        "attack_pattern": "path traversal",
        "mitre_ttps": ["T1190"],
        "recommended_action": "block_ip",
        "action_details": "Block source IP immediately",
        "summary": "Confirmed directory traversal attack",
    }
)

BASIC_CONFIG: dict[str, Any] = {
    "anonymization": {"enabled": True, "token_ttl": 3600},
    "noise_filter": {"enabled": True},
    "pipeline": {"batch_size": 5, "batch_interval": 5, "max_queue_size": 100},
    "reasoning": {
        "batch_size": 5,
        "escalation_confidence": 0.6,
        "escalation": {
            "always_escalate": ["exploit_attempt", "bruteforce"],
            "always_escalate_severity": ["high", "critical"],
        },
    },
    "tailer": {"poll_interval": 0.1, "offset_dir": "/tmp/test_offsets"},
}


class MockProvider(ReasoningProvider):
    def __init__(self, responses: list[str] | None = None) -> None:
        self._responses = responses or [MALICIOUS_FLASH]
        self._call_idx = 0
        self.fast_calls = 0
        self.deep_calls = 0

    async def analyze_fast(self, prompt: str) -> str:
        self.fast_calls += 1
        idx = min(self._call_idx, len(self._responses) - 1)
        self._call_idx += 1
        return self._responses[idx]

    async def analyze_deep(self, prompt: str) -> str:
        self.deep_calls += 1
        return PRO_ANALYSIS

    async def close(self) -> None:
        pass


def _nginx_lines() -> list[str]:
    path = FIXTURES_DIR / "sample_nginx.log"
    return [line for line in path.read_text().splitlines() if line.strip()]


def _parse_all(lines: list[str], source_label: str) -> list[LogEntry]:
    parsers = build_parsers()
    parser = parsers["nginx"]
    entries: list[LogEntry] = []
    for line in lines:
        entry = parser.parse(line, source_label)
        if entry is not None:
            entries.append(entry)
    return entries


def _tailer_config(tmp_path: Path) -> dict[str, Any]:
    return {
        **BASIC_CONFIG,
        "tailer": {
            "poll_interval": 0.1,
            "offset_dir": str(tmp_path / "offsets"),
        },
    }


@pytest.mark.integration
class TestAnonymizationThroughPipeline:
    async def test_no_pii_in_gemini_payload(self) -> None:
        captured_prompts: list[str] = []

        class CapturingProvider(MockProvider):
            async def analyze_fast(self, prompt: str) -> str:
                captured_prompts.append(prompt)
                return await super().analyze_fast(prompt)

        entries = _parse_all(_nginx_lines(), "nginx-test")
        engine = AnonymizationEngine(BASIC_CONFIG)
        anonymized = [engine.anonymize(e) for e in entries]

        client = CapturingProvider(responses=[SCAN_FLASH])
        categorizer = ThreatCategorizer(provider=client, config=BASIC_CONFIG)
        await categorizer.categorize(anonymized)

        ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        for batch in captured_prompts:
            assert not ip_pattern.search(batch), f"PII (IP address) leaked in payload: {batch}"


@pytest.mark.integration
class TestParserToCategorizer:
    async def test_fixture_produces_assessments(self) -> None:
        entries = _parse_all(_nginx_lines(), "nginx-test")
        assert len(entries) > 0

        engine = AnonymizationEngine(BASIC_CONFIG)
        anonymized = [engine.anonymize(e) for e in entries]

        client = MockProvider(responses=[SCAN_FLASH])
        categorizer = ThreatCategorizer(provider=client, config=BASIC_CONFIG)
        results = await categorizer.categorize(anonymized)

        assert len(results) > 0
        for assessment in results:
            assert isinstance(assessment, ThreatAssessment)
            assert isinstance(assessment.category, ThreatCategory)
            assert isinstance(assessment.severity, Severity)
            assert 0.0 <= assessment.confidence <= 1.0

    async def test_exploit_stays_flash(self) -> None:
        entries = _parse_all(_nginx_lines(), "nginx-test")
        engine = AnonymizationEngine(BASIC_CONFIG)
        anonymized = [engine.anonymize(e) for e in entries]

        no_rules_config = {
            **BASIC_CONFIG,
            "reasoning": {
                **BASIC_CONFIG["reasoning"],
                "rules": {"enabled": False},
            },
        }
        client = MockProvider(responses=[MALICIOUS_FLASH])
        categorizer = ThreatCategorizer(provider=client, config=no_rules_config)
        results = await categorizer.categorize(anonymized)

        assert client.deep_calls == 0
        assert all(r.analyzed_by == "l2_fast" for r in results)


@pytest.mark.integration
class TestTailerIntegration:
    async def test_tailer_reads_and_parses(self, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        nginx_lines = _nginx_lines()
        log_file.write_text("\n".join(nginx_lines) + "\n")

        source = LogSource(
            name="test-nginx",
            path=log_file,
            format="nginx",
            enabled=True,
            tags=["test"],
        )
        parsers = build_parsers()
        queue: asyncio.Queue[LogEntry] = asyncio.Queue()
        config = _tailer_config(tmp_path)

        tailer = LogTailer(source, parsers["nginx"], queue, config)

        read_task = asyncio.create_task(tailer.start())
        await asyncio.sleep(1.0)
        await tailer.stop()
        read_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await read_task

        parsed: list[LogEntry] = []
        while not queue.empty():
            parsed.append(queue.get_nowait())

        assert len(parsed) > 0
        for entry in parsed:
            assert isinstance(entry, LogEntry)
            assert entry.source_label == "test-nginx"

    async def test_tailer_detects_new_lines(self, tmp_path: Path) -> None:
        log_file = tmp_path / "grow.log"
        log_file.write_text("")

        source = LogSource(
            name="grow-test",
            path=log_file,
            format="nginx",
            enabled=True,
            tags=["test"],
        )
        parsers = build_parsers()
        queue: asyncio.Queue[LogEntry] = asyncio.Queue()
        config = _tailer_config(tmp_path)

        tailer = LogTailer(source, parsers["nginx"], queue, config)

        read_task = asyncio.create_task(tailer.start())

        await asyncio.sleep(0.3)
        valid_line = (
            "192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "
            '"GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"'
        )
        with open(log_file, "a") as f:
            f.write(valid_line + "\n")

        await asyncio.sleep(0.5)
        await tailer.stop()
        read_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await read_task

        parsed: list[LogEntry] = []
        while not queue.empty():
            parsed.append(queue.get_nowait())

        assert len(parsed) == 1
        assert parsed[0].path == "/admin"
        assert parsed[0].status_code == 403
