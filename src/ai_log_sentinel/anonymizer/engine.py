"""Anonymization engine — replaces PII with reversible tokens."""

from __future__ import annotations

from typing import Any

from ai_log_sentinel.anonymizer.noise_filter import NoiseFilter
from ai_log_sentinel.anonymizer.pii_patterns import load_patterns
from ai_log_sentinel.anonymizer.token_store import TokenStore
from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.log_entry import LogEntry


class AnonymizationEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.patterns = load_patterns(config)
        self.token_store = TokenStore(ttl=config.get("anonymization", {}).get("token_ttl", 3600))
        self.noise_filter = NoiseFilter(config)

    def anonymize(self, entry: LogEntry) -> AnonymizedEntry:
        is_noise, noise_reason = self.noise_filter.is_noise(entry)
        sanitized = entry.raw_line
        tokens: dict[str, str] = {}

        for pattern in self.patterns:
            matches = set(pattern.regex.findall(sanitized))
            for match_value in matches:
                token = self.token_store.resolve_token(match_value)
                if token is None:
                    token = self.token_store.next_token(pattern.token_prefix)
                    self.token_store.add(original=match_value, token=token)
                sanitized = sanitized.replace(match_value, token)
                tokens[token] = match_value

        return AnonymizedEntry(
            original=entry,
            sanitized_line=sanitized,
            tokens=tokens,
            is_noise=is_noise,
            noise_reason=noise_reason,
        )

    def deanonymize(self, sanitized: str, tokens: dict[str, str]) -> str:
        result = sanitized
        for token, original in tokens.items():
            result = result.replace(token, original)
        return result
