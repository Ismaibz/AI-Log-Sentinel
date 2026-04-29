from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ai_log_sentinel.ingestion.parsers import build_parsers
from ai_log_sentinel.ingestion.parsers.apache import ApacheParser
from ai_log_sentinel.ingestion.parsers.base import LogParser
from ai_log_sentinel.ingestion.parsers.nginx import NginxParser
from ai_log_sentinel.ingestion.parsers.syslog import SyslogParser
from ai_log_sentinel.models.log_entry import LogEntry

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

NGINX_BASIC = (
    '192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "GET /admin HTTP/1.1"'
    ' 403 548 "-" "Mozilla/5.0"'
)
NGINX_REFERER = (
    '10.0.0.5 - admin [15/Jan/2025:10:30:46 +0000] "POST /login HTTP/1.1"'
    ' 200 1234 "https://example.com" "curl/7.68.0"'
)
APACHE_LINE = (
    '10.0.0.5 - admin [15/Jan/2025:10:30:45 +0000] "POST /login HTTP/1.1"'
    ' 200 1234 "https://example.com" "curl/7.68.0"'
)
SYSLOG_SSHD_FAILED = (
    "Jan 15 10:30:45 server sshd[12345]: "
    "Failed password for root from 192.168.1.100 port 22 ssh2"
)
SYSLOG_SSHD_ACCEPTED = (
    "Jan 15 10:30:46 server sshd[12346]: " "Accepted password for user from 10.0.0.5 port 22 ssh2"
)


@pytest.mark.unit
class TestNginxParser:
    @pytest.fixture
    def parser(self) -> NginxParser:
        return NginxParser()

    def test_parse_valid_line(self, parser: NginxParser) -> None:
        entry = parser.parse(NGINX_BASIC, "nginx-test")
        assert entry is not None
        assert isinstance(entry, LogEntry)
        assert entry.timestamp == datetime(2025, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        assert entry.source_ip == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.path == "/admin"
        assert entry.status_code == 403
        assert entry.response_size == 548
        assert entry.user_agent == "Mozilla/5.0"
        assert entry.referer == "-"
        assert entry.raw_line == NGINX_BASIC
        assert entry.source_label == "nginx-test"

    def test_parse_with_referer(self, parser: NginxParser) -> None:
        entry = parser.parse(NGINX_REFERER, "nginx-test")
        assert entry is not None
        assert entry.referer == "https://example.com"

    def test_parse_with_user(self, parser: NginxParser) -> None:
        entry = parser.parse(NGINX_REFERER, "nginx-test")
        assert entry is not None
        assert entry.method == "POST"
        assert entry.path == "/login"

    def test_can_parse_valid(self, parser: NginxParser) -> None:
        assert parser.can_parse(NGINX_BASIC) is True

    def test_can_parse_invalid(self, parser: NginxParser) -> None:
        assert parser.can_parse("not a log line at all") is False
        assert parser.can_parse("") is False

    def test_parse_malformed(self, parser: NginxParser) -> None:
        assert parser.parse("garbage line", "nginx-test") is None
        assert parser.parse("", "nginx-test") is None

    def test_parse_fixture_file(self, parser: NginxParser) -> None:
        lines = (FIXTURES_DIR / "sample_nginx.log").read_text().splitlines()
        assert len(lines) == 12
        results = [parser.parse(line, "nginx-fixture") for line in lines]
        for i, entry in enumerate(results):
            if entry is not None:
                assert isinstance(entry, LogEntry)
                assert entry.raw_line == lines[i]
                assert entry.source_label == "nginx-fixture"


@pytest.mark.unit
class TestApacheParser:
    @pytest.fixture
    def parser(self) -> ApacheParser:
        return ApacheParser()

    def test_parse_valid_line(self, parser: ApacheParser) -> None:
        entry = parser.parse(APACHE_LINE, "apache-test")
        assert entry is not None
        assert isinstance(entry, LogEntry)
        assert entry.timestamp == datetime(2025, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        assert entry.source_ip == "10.0.0.5"
        assert entry.method == "POST"
        assert entry.path == "/login"
        assert entry.status_code == 200
        assert entry.response_size == 1234
        assert entry.user_agent == "curl/7.68.0"
        assert entry.referer == "https://example.com"
        assert entry.raw_line == APACHE_LINE
        assert entry.source_label == "apache-test"

    def test_can_parse_valid(self, parser: ApacheParser) -> None:
        assert parser.can_parse(APACHE_LINE) is True

    def test_can_parse_invalid(self, parser: ApacheParser) -> None:
        assert parser.can_parse("random garbage") is False
        assert parser.can_parse("") is False

    def test_parse_malformed(self, parser: ApacheParser) -> None:
        assert parser.parse("not a valid apache line", "apache-test") is None
        assert parser.parse("", "apache-test") is None

    def test_parse_fixture_file(self, parser: ApacheParser) -> None:
        lines = (FIXTURES_DIR / "sample_apache.log").read_text().splitlines()
        assert len(lines) == 4
        results = [parser.parse(line, "apache-fixture") for line in lines]
        for entry in results:
            assert isinstance(entry, LogEntry)


@pytest.mark.unit
class TestSyslogParser:
    @pytest.fixture
    def parser(self) -> SyslogParser:
        return SyslogParser()

    def test_parse_rfc3164(self, parser: SyslogParser) -> None:
        entry = parser.parse(SYSLOG_SSHD_FAILED, "syslog-test")
        assert entry is not None
        assert isinstance(entry, LogEntry)
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 15
        assert entry.timestamp.hour == 10
        assert entry.timestamp.minute == 30
        assert entry.timestamp.second == 45
        assert entry.raw_line == SYSLOG_SSHD_FAILED
        assert entry.source_label == "syslog-test"

    def test_parse_sshd_failed(self, parser: SyslogParser) -> None:
        entry = parser.parse(SYSLOG_SSHD_FAILED, "syslog-test")
        assert entry is not None
        assert entry.method == "FAILED"
        assert entry.source_ip == "192.168.1.100"
        assert entry.path == "sshd"

    def test_parse_sshd_accepted(self, parser: SyslogParser) -> None:
        entry = parser.parse(SYSLOG_SSHD_ACCEPTED, "syslog-test")
        assert entry is not None
        assert entry.method == "ACCEPTED"
        assert entry.source_ip == "10.0.0.5"
        assert entry.path == "sshd"

    def test_can_parse_valid(self, parser: SyslogParser) -> None:
        assert parser.can_parse(SYSLOG_SSHD_FAILED) is True

    def test_can_parse_invalid(self, parser: SyslogParser) -> None:
        assert parser.can_parse("not syslog") is False
        assert parser.can_parse("") is False

    def test_parse_malformed(self, parser: SyslogParser) -> None:
        assert parser.parse("random text", "syslog-test") is None
        assert parser.parse("", "syslog-test") is None

    def test_parse_fixture_file(self, parser: SyslogParser) -> None:
        lines = (FIXTURES_DIR / "sample_syslog.log").read_text().splitlines()
        assert len(lines) == 8
        results = [parser.parse(line, "syslog-fixture") for line in lines]
        for entry in results:
            if entry is not None:
                assert isinstance(entry, LogEntry)
                assert entry.source_label == "syslog-fixture"


@pytest.mark.unit
class TestBuildParsers:
    def test_returns_three_parsers(self) -> None:
        parsers = build_parsers()
        assert set(parsers.keys()) == {"nginx", "apache", "syslog"}

    def test_parser_types(self) -> None:
        parsers = build_parsers()
        assert isinstance(parsers["nginx"], NginxParser)
        assert isinstance(parsers["apache"], ApacheParser)
        assert isinstance(parsers["syslog"], SyslogParser)
        for p in parsers.values():
            assert isinstance(p, LogParser)
