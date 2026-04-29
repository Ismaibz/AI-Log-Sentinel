"""Integration tests — full anonymization pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from ai_log_sentinel.anonymizer.engine import AnonymizationEngine
from ai_log_sentinel.models.log_entry import LogEntry

DEFAULT_CONFIG: dict[str, Any] = {
    "anonymization": {
        "enabled": True,
        "token_ttl": 3600,
        "patterns": {
            "ipv4": True,
            "ipv6": True,
            "email": True,
            "url_sensitive": True,
            "path_ids": True,
        },
    },
    "noise_filter": {
        "enabled": True,
        "static_extensions": [".css", ".js", ".png"],
        "health_paths": ["/health"],
        "ignore_status_codes": [],
    },
}


def _make_entry(
    raw_line: str,
    path: str = "/index.html",
    status_code: int = 200,
    user_agent: str = "Mozilla/5.0",
    source_ip: str = "192.168.1.1",
) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2025, 1, 15, 10, 30, 45),
        source_ip=source_ip,
        method="GET",
        path=path,
        status_code=status_code,
        response_size=548,
        user_agent=user_agent,
        referer="-",
        raw_line=raw_line,
        source_label="nginx-main",
    )


@pytest.fixture
def engine() -> AnonymizationEngine:
    return AnonymizationEngine(DEFAULT_CONFIG)


@pytest.mark.integration
def test_anonymize_removes_ipv4(engine: AnonymizationEngine) -> None:
    raw = (
        "192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "
        '"GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"'
    )
    result = engine.anonymize(_make_entry(raw_line=raw, path="/admin", status_code=403))

    assert "192.168.1.1" not in result.sanitized_line
    assert "[IP_001]" in result.sanitized_line
    assert result.tokens["[IP_001]"] == "192.168.1.1"


@pytest.mark.integration
def test_anonymize_removes_email(engine: AnonymizationEngine) -> None:
    raw = "user@example.com accessed /api/data"
    result = engine.anonymize(_make_entry(raw_line=raw, path="/api/data"))

    assert "user@example.com" not in result.sanitized_line
    email_tokens = [k for k, v in result.tokens.items() if v == "user@example.com"]
    assert len(email_tokens) == 1


@pytest.mark.integration
def test_anonymize_removes_sensitive_url(engine: AnonymizationEngine) -> None:
    raw = "GET http://host/api?token=secret123&user=admin HTTP/1.1"
    result = engine.anonymize(
        _make_entry(raw_line=raw, path="/api?token=secret123&user=admin"),
    )

    assert "[URL_SENSITIVE_001]" in result.sanitized_line


@pytest.mark.integration
def test_anonymize_removes_path_ids(engine: AnonymizationEngine) -> None:
    raw = "GET /users/12345/profile HTTP/1.1"
    result = engine.anonymize(_make_entry(raw_line=raw, path="/users/12345/profile"))

    assert "12345" not in result.sanitized_line
    assert "[ID_001]" in result.sanitized_line


@pytest.mark.integration
def test_anonymize_noise_entry(engine: AnonymizationEngine) -> None:
    raw = "GET /style.css HTTP/1.1"
    result = engine.anonymize(
        _make_entry(raw_line=raw, path="/style.css", status_code=200),
    )

    assert result.is_noise is True
    assert result.noise_reason == "static_asset"


@pytest.mark.integration
def test_anonymize_security_entry_not_noise(engine: AnonymizationEngine) -> None:
    raw = (
        "192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "
        '"GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"'
    )
    result = engine.anonymize(_make_entry(raw_line=raw, path="/admin", status_code=403))

    assert result.is_noise is False
    assert "192.168.1.1" not in result.sanitized_line


@pytest.mark.integration
def test_deanonymize_restores_original(engine: AnonymizationEngine) -> None:
    raw = (
        "192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "
        '"GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"'
    )
    result = engine.anonymize(_make_entry(raw_line=raw, path="/admin", status_code=403))

    restored = engine.deanonymize(result.sanitized_line, result.tokens)
    assert restored == raw


@pytest.mark.integration
def test_multiple_ips_same_token(engine: AnonymizationEngine) -> None:
    raw_a = "10.0.0.1 accessed /foo"
    raw_b = "10.0.0.1 accessed /bar"

    result_a = engine.anonymize(
        _make_entry(raw_line=raw_a, path="/foo", source_ip="10.0.0.1"),
    )
    result_b = engine.anonymize(
        _make_entry(raw_line=raw_b, path="/bar", source_ip="10.0.0.1"),
    )

    token_a = next(k for k, v in result_a.tokens.items() if v == "10.0.0.1")
    token_b = next(k for k, v in result_b.tokens.items() if v == "10.0.0.1")
    assert token_a == token_b


@pytest.mark.integration
def test_multiple_pii_types(engine: AnonymizationEngine) -> None:
    raw = "admin@site.com accessed /users/12345 from 10.0.0.1"
    result = engine.anonymize(
        _make_entry(raw_line=raw, path="/users/12345", source_ip="10.0.0.1"),
    )

    ip_tokens = [k for k, v in result.tokens.items() if v == "10.0.0.1"]
    email_tokens = [k for k, v in result.tokens.items() if v == "admin@site.com"]
    id_tokens = [k for k, v in result.tokens.items() if v == "/12345"]

    assert len(ip_tokens) == 1
    assert len(email_tokens) == 1
    assert len(id_tokens) == 1


@pytest.mark.integration
def test_no_pii_preserved(engine: AnonymizationEngine) -> None:
    raw = "GET /index.html HTTP/1.1"
    result = engine.anonymize(_make_entry(raw_line=raw))

    assert result.sanitized_line == raw
    assert result.tokens == {}
