"""Pre-analysis statistics for log batches — enriches prompts with context."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry

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


@dataclass
class IPStats:
    request_count: int = 0
    status_codes: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    user_agents: set[str] = field(default_factory=set)


@dataclass
class PathStats:
    request_count: int = 0
    status_codes: Counter = field(default_factory=Counter)
    ips: set[str] = field(default_factory=set)


@dataclass
class BatchStats:
    total_entries: int = 0
    time_start: str = ""
    time_end: str = ""
    ip_stats: dict[str, IPStats] = field(default_factory=dict)
    path_stats: dict[str, PathStats] = field(default_factory=dict)

    @classmethod
    def compute(cls, entries: list[AnonymizedEntry]) -> BatchStats:
        stats = cls(total_entries=len(entries))
        if not entries:
            return stats

        timestamps = []
        for entry in entries:
            if entry.is_noise:
                continue

            orig = entry.original
            ip = _extract_ip(entry)
            path = orig.path or ""
            method = orig.method or ""
            status = orig.status_code
            ua = orig.user_agent or ""

            timestamps.append(orig.timestamp)

            if ip not in stats.ip_stats:
                stats.ip_stats[ip] = IPStats()
            ips = stats.ip_stats[ip]
            ips.request_count += 1
            ips.status_codes[status] += 1
            ips.paths[path] += 1
            ips.methods[method] += 1
            if ua:
                ips.user_agents.add(ua)

            if path:
                if path not in stats.path_stats:
                    stats.path_stats[path] = PathStats()
                ps = stats.path_stats[path]
                ps.request_count += 1
                ps.status_codes[status] += 1
                ps.ips.add(ip)

        if timestamps:
            stats.time_start = min(timestamps).strftime("%H:%M:%S")
            stats.time_end = max(timestamps).strftime("%H:%M:%S")

        return stats

    def to_summary_text(self) -> str:
        if self.total_entries == 0:
            return ""

        lines: list[str] = []
        lines.append(f"Total entries: {self.total_entries}")
        if self.time_start:
            lines.append(f"Time window: {self.time_start} - {self.time_end}")
        lines.append("")

        for ip, ips in sorted(
            self.ip_stats.items(), key=lambda x: x[1].request_count, reverse=True
        ):
            lines.append(f"IP {ip}: {ips.request_count} requests")
            for path, count in ips.paths.most_common(5):
                status_summary = self._format_statuses(ips.status_codes, path)
                method = ips.methods.most_common(1)[0][0] if ips.methods else "?"
                lines.append(f"  {method} {path} -> {count}x{status_summary}")
            if ips.user_agents:
                ua_list = list(ips.user_agents)[:3]
                lines.append(f"  User-Agent: {', '.join(ua_list)}")
            lines.append("")

        suspicious_paths = [
            (p, ps)
            for p, ps in self.path_stats.items()
            if ps.request_count >= 3 or len(ps.ips) >= 2
        ]
        if suspicious_paths:
            lines.append("Frequent paths:")
            for path, ps in sorted(
                suspicious_paths,
                key=lambda x: x[1].request_count,
                reverse=True,
            ):
                lines.append(f"  {path}: {ps.request_count} hits from {len(ps.ips)} IPs")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _format_statuses(status_codes: Counter, path: str = "") -> str:
        if not status_codes:
            return ""
        parts = [f"{code}:{count}" for code, count in status_codes.most_common()]
        return f" (status {', '.join(parts)})"
