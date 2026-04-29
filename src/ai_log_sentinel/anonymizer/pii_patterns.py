"""PII detection patterns for anonymization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class PIIPattern:
    name: str
    regex: re.Pattern[str]
    token_prefix: str
    description: str


_IPV6 = (
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|::"
)

DEFAULT_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        name="ipv4",
        regex=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        token_prefix="[IP_",
        description="IPv4 addresses",
    ),
    PIIPattern(
        name="ipv6",
        regex=re.compile(_IPV6),
        token_prefix="[IPV6_",
        description="IPv6 addresses (full and compressed forms)",
    ),
    PIIPattern(
        name="email",
        regex=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        token_prefix="[EMAIL_",
        description="Email addresses",
    ),
    PIIPattern(
        name="url_sensitive",
        regex=re.compile(
            r"https?://\S*\?(?:\S*[&?])?"
            r"(?:token|session|key|password|secret|api_key|access_token)=\S*"
        ),
        token_prefix="[URL_SENSITIVE_",
        description="URLs with sensitive query parameters",
    ),
    PIIPattern(
        name="path_ids",
        regex=re.compile(r"/\d{3,}(?=/|$|\s)"),
        token_prefix="[ID_",
        description="Numeric IDs in URL paths",
    ),
]


def load_patterns(config: dict[str, Any]) -> list[PIIPattern]:
    patterns_config = config.get("anonymization", {}).get("patterns", {})
    result: list[PIIPattern] = []
    for pattern in DEFAULT_PATTERNS:
        if patterns_config.get(pattern.name, True):
            result.append(pattern)
    return result
