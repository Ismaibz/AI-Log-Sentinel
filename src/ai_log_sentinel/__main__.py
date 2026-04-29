"""CLI entrypoint — `python -m ai_log_sentinel`."""

from __future__ import annotations

import asyncio

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


if __name__ == "__main__":
    cli()
