"""CLI entrypoint — `python -m ai_log_sentinel`."""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path

import click

from ai_log_sentinel.config.settings import Settings
from ai_log_sentinel.utils.logger import setup_logging


@click.group()
def cli() -> None:
    """AI-Log-Sentinel — Autonomous log threat hunter."""
    pass


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config.toml")
@click.option("--verbose", "-v", is_flag=True, help="DEBUG log level")
def run(config: str | None, verbose: bool) -> None:
    """Start the monitoring pipeline."""
    level = "DEBUG" if verbose else "INFO"
    setup_logging(level)
    settings = Settings(config_path=config)

    async def _start() -> None:
        api_key = await settings.get_secret("GEMINI_API_KEY")

        telegram_secret_key = settings.get("alerting.telegram.bot_token_secret", "")
        if telegram_secret_key:
            with contextlib.suppress(Exception):
                settings.raw.setdefault("alerting", {}).setdefault("telegram", {})["bot_token"] = (
                    await settings.get_secret(telegram_secret_key)
                )

        from ai_log_sentinel.pipeline.orchestrator import PipelineOrchestrator

        orchestrator = PipelineOrchestrator(config=settings.raw, api_key=api_key)
        click.echo(
            f"Pipeline starting "
            f"(model={settings.get('reasoning.flash_model')}, "
            f"sources={len(orchestrator.sources)})"
        )
        await orchestrator.run()

    asyncio.run(_start())


@cli.command("test-config")
def test_config() -> None:
    """Validate configuration and API connectivity."""
    setup_logging("INFO")

    results: list[tuple[str, bool, str]] = []

    try:
        settings = Settings()
        results.append(("config loaded", True, ""))
    except Exception as exc:
        results.append(("config loaded", False, str(exc)))
        _print_results(results)
        return

    async def _check_secrets() -> tuple[bool, str]:
        try:
            await settings.get_secret("GEMINI_API_KEY")
            return True, ""
        except Exception as exc:
            return False, str(exc)

    secrets_ok, secrets_err = asyncio.run(_check_secrets())
    results.append(("secrets accessible", secrets_ok, secrets_err))

    import os

    log_sources = settings.get("pipeline.log_sources", [])
    if isinstance(log_sources, list):
        for src in log_sources:
            path = src.get("path", "") if isinstance(src, dict) else str(src)
            readable = os.path.isfile(path) and os.access(path, os.R_OK)
            results.append((f"log source: {path}", readable, ""))

    _print_results(results)


def _print_results(results: list[tuple[str, bool, str]]) -> None:
    for label, ok, err in results:
        icon = "\u2713" if ok else "\u2717"
        color = "green" if ok else "red"
        msg = click.style(f" {icon} {label}", fg=color)
        if err:
            msg += click.style(f" — {err}", fg="red")
        click.echo(msg)


@cli.command("list-rules")
def list_rules() -> None:
    """List all executed mitigation rules."""
    log_path = Path("data/execution_log.json")
    if not log_path.exists():
        click.echo("No execution log found.")
        return

    try:
        records = json.loads(log_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        click.echo(f"Error reading execution log: {exc}")
        return

    if not records:
        click.echo("No rules executed yet.")
        return

    for record in records:
        alert_id = record.get("alert_id", "unknown")
        dry_run = record.get("dry_run", True)
        success = record.get("success", False)
        executed_at = record.get("executed_at", "unknown")

        status_icon = "\u2713" if success else "\u2717"
        mode = "DRY-RUN" if dry_run else "LIVE"
        click.echo(f"\n{status_icon} Alert {alert_id[:8]}... [{mode}] at {executed_at}")

        for result in record.get("results", []):
            cmd = result.get("command", "")
            rule_type = result.get("rule_type", "")
            ok = result.get("success", False)
            icon = "\u2713" if ok else "\u2717"
            click.echo(f"  {icon} [{rule_type}] {cmd}")


@cli.command()
@click.argument("alert_id")
def rollback(alert_id: str) -> None:
    """Rollback mitigation rules for a specific alert."""
    setup_logging("INFO")
    settings = Settings()
    mitigation_cfg = settings.raw.get("mitigation", {})
    executor_cfg = mitigation_cfg.get("executor", {})

    from ai_log_sentinel.mitigation.executor import MitigationExecutor

    executor = MitigationExecutor(executor_cfg)

    async def _rollback() -> None:
        record = await executor.rollback(alert_id)
        if record is None:
            click.echo(f"No execution record found for alert {alert_id}")
            return

        if record.success:
            click.echo(f"\u2713 Rollback completed for alert {alert_id[:8]}...")
            for result in record.results:
                click.echo(f"  {result.command}")
        else:
            click.echo(f"\u2717 Rollback partially failed for alert {alert_id[:8]}...")
            for result in record.results:
                icon = "\u2713" if result.success else "\u2717"
                click.echo(f"  {icon} {result.command}")

    asyncio.run(_rollback())


if __name__ == "__main__":
    cli()
