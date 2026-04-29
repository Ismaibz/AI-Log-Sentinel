"""Tests for noise filter."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_sentinel.anonymizer.noise_filter import NoiseFilter
from ai_log_sentinel.models.log_entry import LogEntry

DEFAULT_CONFIG: dict = {
    "noise_filter": {
        "enabled": True,
        "static_extensions": [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg"],
        "health_paths": ["/health", "/healthz", "/ping"],
        "ignore_status_codes": [],
    }
}


def _make_entry(
    path: str = "/index.html",
    status_code: int = 200,
    user_agent: str = "Mozilla/5.0",
    method: str = "GET",
) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2025, 1, 15, 10, 30, 45),
        source_ip="192.168.1.1",
        method=method,
        path=path,
        status_code=status_code,
        response_size=548,
        user_agent=user_agent,
        referer="-",
        raw_line=(
            f"192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "
            f'"GET {path} HTTP/1.1" {status_code} 548 "-" "{user_agent}"'
        ),
        source_label="nginx-main",
    )


class TestStaticAssets:
    @pytest.fixture()
    def filter(self) -> NoiseFilter:
        return NoiseFilter(DEFAULT_CONFIG)

    def test_static_css(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/style.css")
        assert filter.is_noise(entry) == (True, "static_asset")

    def test_static_js(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/app.js")
        assert filter.is_noise(entry) == (True, "static_asset")

    def test_static_png(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/logo.png")
        assert filter.is_noise(entry) == (True, "static_asset")

    def test_static_with_query(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/style.css?v=1.0")
        assert filter.is_noise(entry) == (True, "static_asset")

    def test_not_static_html(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/page.html")
        assert filter.is_noise(entry) == (False, None)


class TestHealthChecks:
    @pytest.fixture()
    def filter(self) -> NoiseFilter:
        return NoiseFilter(DEFAULT_CONFIG)

    def test_health_check(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/health")
        assert filter.is_noise(entry) == (True, "health_check")

    def test_healthz(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/healthz")
        assert filter.is_noise(entry) == (True, "health_check")

    def test_ping(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/ping")
        assert filter.is_noise(entry) == (True, "health_check")

    def test_not_health(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/api/status")
        assert filter.is_noise(entry) == (False, None)


class TestKnownBots:
    @pytest.fixture()
    def filter(self) -> NoiseFilter:
        return NoiseFilter(DEFAULT_CONFIG)

    def test_googlebot(self, filter: NoiseFilter) -> None:
        entry = _make_entry(user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)")
        assert filter.is_noise(entry) == (True, "known_bot")

    def test_bingbot(self, filter: NoiseFilter) -> None:
        entry = _make_entry(user_agent="Mozilla/5.0 (compatible; Bingbot/2.0)")
        assert filter.is_noise(entry) == (True, "known_bot")

    def test_not_bot(self, filter: NoiseFilter) -> None:
        entry = _make_entry(user_agent="curl/8.0")
        assert filter.is_noise(entry) == (False, None)


class TestSuspiciousPaths:
    @pytest.fixture()
    def filter(self) -> NoiseFilter:
        return NoiseFilter(DEFAULT_CONFIG)

    def test_admin_403_not_noise(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/admin", status_code=403)
        assert filter.is_noise(entry) == (False, None)

    def test_etc_passwd_404_not_noise(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/etc/passwd", status_code=404)
        assert filter.is_noise(entry) == (False, None)

    def test_wp_admin_403_not_noise(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/wp-admin", status_code=403)
        assert filter.is_noise(entry) == (False, None)

    def test_dotenv_500_not_noise(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/.env", status_code=500)
        assert filter.is_noise(entry) == (False, None)

    def test_admin_200_is_noise_if_static(self, filter: NoiseFilter) -> None:
        entry = _make_entry(path="/admin.css", status_code=200)
        assert filter.is_noise(entry) == (True, "static_asset")


class TestIgnoredStatusCodes:
    def test_ignored_status(self) -> None:
        cfg: dict = {
            "noise_filter": {
                "enabled": True,
                "static_extensions": [],
                "health_paths": [],
                "ignore_status_codes": [301],
            }
        }
        f = NoiseFilter(cfg)
        entry = _make_entry(path="/old-page", status_code=301)
        assert f.is_noise(entry) == (True, "ignored_status")

    def test_non_ignored_status(self) -> None:
        cfg: dict = {
            "noise_filter": {
                "enabled": True,
                "static_extensions": [],
                "health_paths": [],
                "ignore_status_codes": [301],
            }
        }
        f = NoiseFilter(cfg)
        entry = _make_entry(path="/page", status_code=200)
        assert f.is_noise(entry) == (False, None)


class TestDisabledFilter:
    def test_disabled_filter(self) -> None:
        cfg: dict = {"noise_filter": {"enabled": False}}
        f = NoiseFilter(cfg)
        entry = _make_entry(path="/style.css")
        assert f.is_noise(entry) == (False, None)
