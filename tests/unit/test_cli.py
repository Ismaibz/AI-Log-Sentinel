from __future__ import annotations

from click.testing import CliRunner

from ai_log_sentinel.__main__ import cli


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "AI-Log-Sentinel" in result.output


def test_cli_run_exists() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "--help"])
    assert result.exit_code == 0
    assert "Start the monitoring pipeline" in result.output


def test_cli_test_config_exists() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["test-config", "--help"])
    assert result.exit_code == 0
    assert "Validate configuration" in result.output
