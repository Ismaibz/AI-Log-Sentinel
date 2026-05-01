"""Unit tests for BatchStats pre-analysis."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.log_entry import LogEntry
from ai_log_sentinel.reasoning.batch_stats import BatchStats


def _make_entry(
    sanitized: str = "test",
    ip: str = "1.2.3.4",
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
            raw_line=sanitized,
            source_label="test",
        ),
        sanitized_line=sanitized,
        is_noise=is_noise,
    )


@pytest.mark.unit
class TestBatchStatsCompute:
    def test_empty_batch(self):
        stats = BatchStats.compute([])
        assert stats.total_entries == 0
        assert stats.to_summary_text() == ""

    def test_single_entry(self):
        entries = [_make_entry(ip="10.0.0.1", path="/login", status=200)]
        stats = BatchStats.compute(entries)
        assert stats.total_entries == 1
        assert "10.0.0.1" in stats.ip_stats
        assert stats.ip_stats["10.0.0.1"].request_count == 1

    def test_noise_entries_excluded(self):
        entries = [
            _make_entry(is_noise=True),
            _make_entry(ip="10.0.0.1", path="/"),
        ]
        stats = BatchStats.compute(entries)
        assert stats.total_entries == 2
        assert len(stats.ip_stats) == 1

    def test_multiple_ips(self):
        entries = [
            _make_entry(ip="10.0.0.1", path="/"),
            _make_entry(ip="10.0.0.2", path="/"),
            _make_entry(ip="10.0.0.1", path="/about"),
        ]
        stats = BatchStats.compute(entries)
        assert len(stats.ip_stats) == 2
        assert stats.ip_stats["10.0.0.1"].request_count == 2
        assert stats.ip_stats["10.0.0.2"].request_count == 1

    def test_bruteforce_pattern(self):
        entries = [
            _make_entry(ip="10.0.0.1", method="POST", path="/login", status=401, ua="curl/7.88")
            for _ in range(10)
        ]
        stats = BatchStats.compute(entries)
        ip_stats = stats.ip_stats["10.0.0.1"]
        assert ip_stats.request_count == 10
        assert ip_stats.status_codes[401] == 10
        assert ip_stats.paths["/login"] == 10
        assert ip_stats.methods["POST"] == 10
        assert "curl/7.88" in ip_stats.user_agents

    def test_scan_pattern(self):
        entries = [
            _make_entry(ip="10.0.0.1", path="/admin", status=403),
            _make_entry(ip="10.0.0.1", path="/etc/passwd", status=404),
            _make_entry(ip="10.0.0.1", path="/wp-admin", status=404),
            _make_entry(ip="10.0.0.1", path="/.env", status=404),
        ]
        stats = BatchStats.compute(entries)
        assert len(stats.path_stats) == 4
        assert stats.ip_stats["10.0.0.1"].request_count == 4

    def test_time_window(self):
        entries = [
            _make_entry(ip="10.0.0.1"),
        ]
        entries[0].original.timestamp = datetime(2026, 1, 1, 10, 0, 0)
        entries.append(_make_entry(ip="10.0.0.1"))
        entries[1].original.timestamp = datetime(2026, 1, 1, 10, 5, 30)

        stats = BatchStats.compute(entries)
        assert stats.time_start == "10:00:00"
        assert stats.time_end == "10:05:30"


@pytest.mark.unit
class TestBatchStatsSummary:
    def test_summary_contains_ip_info(self):
        entries = [
            _make_entry(ip="10.0.0.1", method="POST", path="/login", status=401) for _ in range(5)
        ]
        stats = BatchStats.compute(entries)
        summary = stats.to_summary_text()
        assert "10.0.0.1" in summary
        assert "5 requests" in summary
        assert "/login" in summary

    def test_summary_shows_frequent_paths(self):
        entries = [
            _make_entry(ip="10.0.0.1", path="/admin", status=403),
            _make_entry(ip="10.0.0.1", path="/admin", status=403),
            _make_entry(ip="10.0.0.1", path="/admin", status=403),
        ]
        stats = BatchStats.compute(entries)
        summary = stats.to_summary_text()
        assert "Frequent paths" in summary

    def test_summary_empty_for_no_entries(self):
        stats = BatchStats.compute([])
        assert stats.to_summary_text() == ""

    def test_summary_shows_user_agents(self):
        entries = [
            _make_entry(ip="10.0.0.1", ua="sqlmap/1.7"),
            _make_entry(ip="10.0.0.1", ua="sqlmap/1.7"),
        ]
        stats = BatchStats.compute(entries)
        summary = stats.to_summary_text()
        assert "sqlmap" in summary
