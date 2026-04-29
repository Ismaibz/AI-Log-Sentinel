from __future__ import annotations

import re

import pytest

from ai_log_sentinel.anonymizer.pii_patterns import DEFAULT_PATTERNS, PIIPattern, load_patterns


@pytest.fixture
def ipv4_pattern():
    return next(p for p in DEFAULT_PATTERNS if p.name == "ipv4")


@pytest.fixture
def ipv6_pattern():
    return next(p for p in DEFAULT_PATTERNS if p.name == "ipv6")


@pytest.fixture
def email_pattern():
    return next(p for p in DEFAULT_PATTERNS if p.name == "email")


@pytest.fixture
def url_sensitive_pattern():
    return next(p for p in DEFAULT_PATTERNS if p.name == "url_sensitive")


@pytest.fixture
def path_ids_pattern():
    return next(p for p in DEFAULT_PATTERNS if p.name == "path_ids")


class TestPIIPatternDataclass:
    def test_pii_pattern_fields(self):
        pattern = PIIPattern(
            name="test",
            regex=re.compile(r"\d+"),
            token_prefix="[TEST_",
            description="test pattern",
        )
        assert pattern.name == "test"
        assert isinstance(pattern.regex, re.Pattern)
        assert pattern.token_prefix == "[TEST_"
        assert pattern.description == "test pattern"


class TestDefaultPatterns:
    def test_default_patterns_count(self):
        assert len(DEFAULT_PATTERNS) == 5

    def test_default_patterns_names(self):
        assert [p.name for p in DEFAULT_PATTERNS] == [
            "ipv4",
            "ipv6",
            "email",
            "url_sensitive",
            "path_ids",
        ]

    def test_default_patterns_compiled(self):
        for pattern in DEFAULT_PATTERNS:
            assert isinstance(pattern.regex, re.Pattern)


class TestIPv4Pattern:
    def test_ipv4_match(self, ipv4_pattern):
        assert ipv4_pattern.regex.search("192.168.1.1") is not None

    def test_ipv4_in_context(self, ipv4_pattern):
        match = ipv4_pattern.regex.search("GET /admin from 10.0.0.1 HTTP")
        assert match is not None
        assert match.group() == "10.0.0.1"

    def test_ipv4_no_match(self, ipv4_pattern):
        assert ipv4_pattern.regex.search("not.an.ip") is None


class TestIPv6Pattern:
    def test_ipv6_full_match(self, ipv6_pattern):
        assert ipv6_pattern.regex.search("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is not None

    def test_ipv6_compressed(self, ipv6_pattern):
        assert ipv6_pattern.regex.search("::1") is not None

    def test_ipv6_no_match(self, ipv6_pattern):
        assert ipv6_pattern.regex.search("hello world") is None


class TestEmailPattern:
    def test_email_match(self, email_pattern):
        assert email_pattern.regex.search("user@example.com") is not None

    def test_email_complex(self, email_pattern):
        assert email_pattern.regex.search("john.doe+tag@sub.example.co.uk") is not None

    def test_email_no_match(self, email_pattern):
        assert email_pattern.regex.search("notanemail") is None


class TestURLSensitivePattern:
    def test_url_sensitive_token(self, url_sensitive_pattern):
        assert url_sensitive_pattern.regex.search("http://example.com?token=abc123") is not None

    def test_url_sensitive_api_key(self, url_sensitive_pattern):
        url = "https://api.com/endpoint?api_key=secret"
        assert url_sensitive_pattern.regex.search(url) is not None

    def test_url_sensitive_session(self, url_sensitive_pattern):
        assert url_sensitive_pattern.regex.search("http://site.com?session=xyz&other=1") is not None

    def test_url_sensitive_no_match(self, url_sensitive_pattern):
        assert url_sensitive_pattern.regex.search("http://example.com?page=2") is None


class TestPathIDsPattern:
    def test_path_ids_match(self, path_ids_pattern):
        match = path_ids_pattern.regex.search("/users/12345/")
        assert match is not None
        assert match.group() == "/12345"

    def test_path_ids_match_end(self, path_ids_pattern):
        match = path_ids_pattern.regex.search("/api/999")
        assert match is not None
        assert match.group() == "/999"

    def test_path_ids_no_match_short(self, path_ids_pattern):
        assert path_ids_pattern.regex.search("/users/12/") is None

    def test_path_ids_no_match_no_slash(self, path_ids_pattern):
        assert path_ids_pattern.regex.search("12345") is None


class TestLoadPatterns:
    def test_load_patterns_all_enabled(self):
        config = {
            "anonymization": {
                "patterns": {
                    "ipv4": True,
                    "ipv6": True,
                    "email": True,
                    "url_sensitive": True,
                    "path_ids": True,
                }
            }
        }
        patterns = load_patterns(config)
        assert len(patterns) == 5

    def test_load_patterns_ipv4_disabled(self):
        config = {
            "anonymization": {
                "patterns": {
                    "ipv4": False,
                    "ipv6": True,
                    "email": True,
                    "url_sensitive": True,
                    "path_ids": True,
                }
            }
        }
        patterns = load_patterns(config)
        assert len(patterns) == 4
        assert all(p.name != "ipv4" for p in patterns)

    def test_load_patterns_defaults(self):
        patterns = load_patterns({})
        assert len(patterns) == 5

    def test_load_patterns_selective(self):
        config = {
            "anonymization": {
                "patterns": {
                    "ipv4": False,
                    "ipv6": False,
                    "email": True,
                    "url_sensitive": False,
                    "path_ids": False,
                }
            }
        }
        patterns = load_patterns(config)
        assert len(patterns) == 1
        assert patterns[0].name == "email"
