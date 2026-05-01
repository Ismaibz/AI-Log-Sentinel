"""Structured logging setup."""

import logging

from rich.logging import RichHandler


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[RichHandler(show_time=False, show_path=False, rich_tracebacks=True)],
        force=True,
    )

    for noisy in ("telegram", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
