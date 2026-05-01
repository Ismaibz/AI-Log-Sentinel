"""L1 local rules engine — pattern-based threat detection without AI."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)

_IP_TOKEN_RE = re.compile(r"\[IP_\d+\]")
_REAL_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _extract_ip(entry: AnonymizedEntry) -> str:
    if entry.tokens:
        for token_key in entry.tokens:
            if _IP_TOKEN_RE.match(token_key):
                return token_key
    ip = entry.original.source_ip
    if ip:
        return ip
    for token in _IP_TOKEN_RE.findall(entry.sanitized_line):
        return token
    for ip in _REAL_IP_RE.findall(entry.sanitized_line):
        return ip
    return "unknown"


class LocalRuleEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        rules_cfg = config.get("reasoning", {}).get("rules", {})
        self.enabled = rules_cfg.get("enabled", True)
        self.brute_threshold = rules_cfg.get("brute_force_threshold", 5)
        self.fuzz_threshold = rules_cfg.get("path_fuzz_threshold", 5)
        self.brute_paths = set(
            rules_cfg.get(
                "brute_force_paths",
                ["/login", "/auth", "/signin", "/wp-login.php", "/api/login"],
            )
        )
        self.sqli_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in rules_cfg.get(
                "sqli_patterns",
                [
                    r"UNION\s+(ALL\s+)?SELECT",
                    r"OR\s+1\s*=\s*1",
                    r"'\s*--",
                    r"%27",
                    r"1\s*=\s*1",
                    r"SELECT\s+.*\s+FROM",
                ],
            )
        ]
        self.traversal_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in rules_cfg.get(
                "traversal_patterns",
                [r"\.\./", r"\.\.%2[fF]", r"\.\.\\"],
            )
        ]
        self.scanner_uas = [
            p.lower()
            for p in rules_cfg.get(
                "scanner_uas",
                ["nikto", "sqlmap", "nmap", "dirbuster", "gobuster", "masscan", "wpscan"],
            )
        ]

    def evaluate(
        self, entries: list[AnonymizedEntry]
    ) -> tuple[list[ThreatAssessment], list[AnonymizedEntry]]:
        if not self.enabled or not entries:
            return [], []

        non_noise = [e for e in entries if not e.is_noise]
        if not non_noise:
            return [], []

        results: list[ThreatAssessment] = []
        all_consumed: list[AnonymizedEntry] = []
        remaining = list(non_noise)

        for checker in (
            self._check_sqli,
            self._check_traversal,
            self._check_bruteforce,
            self._check_scanner,
        ):
            if not remaining:
                break
            result, consumed = checker(remaining)
            if result:
                results.append(result)
                if consumed:
                    all_consumed.extend(consumed)
                    remaining = [e for e in remaining if e not in consumed]

        return results, all_consumed

    def _check_sqli(
        self, entries: list[AnonymizedEntry]
    ) -> tuple[ThreatAssessment | None, list[AnonymizedEntry]]:
        matched: list[AnonymizedEntry] = []
        for entry in entries:
            path = entry.original.path or ""
            for pattern in self.sqli_patterns:
                if pattern.search(path):
                    matched.append(entry)
                    break

        if not matched:
            return None, []

        first_path = matched[0].original.path or ""
        return (
            self._make_assessment(
                entries=entries,
                category=ThreatCategory.EXPLOIT_ATTEMPT,
                severity=Severity.CRITICAL,
                summary=f"SQL injection attempt detected: {first_path[:80]}",
                action=RecommendedAction.BLOCK_IP,
                indicators=[f"sqli_pattern_in_{first_path[:50]}"],
            ),
            matched,
        )

    def _check_traversal(
        self, entries: list[AnonymizedEntry]
    ) -> tuple[ThreatAssessment | None, list[AnonymizedEntry]]:
        matched: list[AnonymizedEntry] = []
        for entry in entries:
            path = entry.original.path or ""
            for pattern in self.traversal_patterns:
                if pattern.search(path):
                    matched.append(entry)
                    break

        if not matched:
            return None, []

        first_path = matched[0].original.path or ""
        return (
            self._make_assessment(
                entries=entries,
                category=ThreatCategory.EXPLOIT_ATTEMPT,
                severity=Severity.HIGH,
                summary=f"Directory traversal attempt: {first_path[:80]}",
                action=RecommendedAction.BLOCK_IP,
                indicators=[f"traversal_in_{first_path[:50]}"],
            ),
            matched,
        )

    def _check_bruteforce(
        self, entries: list[AnonymizedEntry]
    ) -> tuple[ThreatAssessment | None, list[AnonymizedEntry]]:
        ip_attempts: dict[str, list[AnonymizedEntry]] = {}
        for entry in entries:
            if entry.original.status_code not in (401, 403):
                continue
            path = entry.original.path or ""
            if path.rstrip("/") not in self.brute_paths:
                continue
            method = (entry.original.method or "").upper()
            if method not in ("POST", "PUT"):
                continue
            ip = _extract_ip(entry)
            ip_attempts.setdefault(ip, []).append(entry)

        for ip, attempts in ip_attempts.items():
            if len(attempts) >= self.brute_threshold:
                path = attempts[0].original.path or "/login"
                return (
                    self._make_assessment(
                        entries=entries,
                        category=ThreatCategory.BRUTEFORCE,
                        severity=Severity.HIGH,
                        summary=f"Brute force: {len(attempts)} failed logins from {ip} to {path}",
                        action=RecommendedAction.BLOCK_IP,
                        indicators=[
                            f"{len(attempts)}x_401_from_{ip}",
                            f"path={path}",
                        ],
                        override_ip=ip,
                    ),
                    attempts,
                )
        return None, []

    def _check_scanner(
        self, entries: list[AnonymizedEntry]
    ) -> tuple[ThreatAssessment | None, list[AnonymizedEntry]]:
        scanner_entries: list[AnonymizedEntry] = []
        for entry in entries:
            ua = (entry.original.user_agent or "").lower()
            if any(s in ua for s in self.scanner_uas):
                scanner_entries.append(entry)

        if scanner_entries:
            ip = _extract_ip(scanner_entries[0])
            return (
                self._make_assessment(
                    entries=entries,
                    category=ThreatCategory.SCAN,
                    severity=Severity.HIGH,
                    summary=(
                        f"Known scanner detected from {ip}: "
                        f"{scanner_entries[0].original.user_agent}"
                    ),
                    action=RecommendedAction.RATE_LIMIT,
                    indicators=[f"scanner_ua={scanner_entries[0].original.user_agent}"],
                    override_ip=ip,
                ),
                scanner_entries,
            )

        return self._check_path_fuzzing(entries)

    def _check_path_fuzzing(
        self, entries: list[AnonymizedEntry]
    ) -> tuple[ThreatAssessment | None, list[AnonymizedEntry]]:
        ip_paths: dict[str, set[str]] = {}
        ip_entries: dict[str, list[AnonymizedEntry]] = {}
        for entry in entries:
            if entry.original.status_code not in (403, 404):
                continue
            ip = _extract_ip(entry)
            path = entry.original.path or ""
            ip_paths.setdefault(ip, set()).add(path)
            ip_entries.setdefault(ip, []).append(entry)

        for ip, paths in ip_paths.items():
            if len(paths) >= self.fuzz_threshold:
                return (
                    self._make_assessment(
                        entries=entries,
                        category=ThreatCategory.SCAN,
                        severity=Severity.MEDIUM,
                        summary=f"Path fuzzing: {len(paths)} distinct 404/403 paths from {ip}",
                        action=RecommendedAction.RATE_LIMIT,
                        indicators=[f"{len(paths)}x_unique_paths_from_{ip}"],
                        override_ip=ip,
                    ),
                    ip_entries[ip],
                )
        return None, []

    @staticmethod
    def _make_assessment(
        entries: list[AnonymizedEntry],
        category: ThreatCategory,
        severity: Severity,
        summary: str,
        action: RecommendedAction,
        indicators: list[str],
        override_ip: str | None = None,
    ) -> ThreatAssessment:
        ips: list[str] = []
        if override_ip:
            ips = [override_ip]
        else:
            seen = set()
            for e in entries:
                ip = _extract_ip(e)
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)

        paths: list[str] = []
        seen_paths: set[str] = set()
        for e in entries:
            p = e.original.path or ""
            if p and p not in seen_paths:
                seen_paths.add(p)
                paths.append(p)

        return ThreatAssessment(
            category=category,
            severity=severity,
            confidence=0.95,
            summary=summary,
            indicators=indicators,
            recommended_action=action,
            action_details={
                "ip": ips[0] if ips else None,
                "ips": ips,
                "path": paths[0] if paths else None,
                "paths": paths,
            },
            mitre_ttps=[],
            analyzed_by="local_rules",
            timestamp=datetime.now(timezone.utc),
        )
