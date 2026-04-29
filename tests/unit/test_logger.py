from __future__ import annotations

import logging

from ai_log_sentinel.utils.logger import setup_logging


def test_setup_logging_sets_level() -> None:
    setup_logging("WARNING")
    root = logging.getLogger()
    assert root.level == logging.WARNING


def test_setup_logging_default() -> None:
    setup_logging("INFO")
    root = logging.getLogger()
    assert root.level == logging.INFO
