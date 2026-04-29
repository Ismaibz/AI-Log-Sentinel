"""Async tail-based log file watcher."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import aiofiles

from ai_log_sentinel.ingestion.log_source import LogSource
from ai_log_sentinel.ingestion.parsers.base import LogParser
from ai_log_sentinel.models.log_entry import LogEntry

logger = logging.getLogger(__name__)


class LogTailer:

    def __init__(
        self,
        source: LogSource,
        parser: LogParser,
        queue: asyncio.Queue[LogEntry],
        config: dict[str, Any],
    ) -> None:
        self.source = source
        self.parser = parser
        self.queue = queue
        self._poll_interval = config.get("tailer", {}).get("poll_interval", 0.5)
        offset_dir = config.get("tailer", {}).get("offset_dir", ".offsets")
        self._offset_file = Path(offset_dir) / f".tailer_offset_{source.name}"
        self._running = False
        self._last_inode: int | None = None
        self._last_size: int = 0

    async def start(self) -> None:
        self._running = True
        self._offset_file.parent.mkdir(parents=True, exist_ok=True)
        offset = self._load_offset()

        try:
            stat = self.source.path.stat()
            self._last_inode = stat.st_ino
            self._last_size = stat.st_size
        except FileNotFoundError:
            logger.warning("Log file not found at startup: %s", self.source.path)

        while self._running:
            try:
                offset = await self._read_cycle(offset)
            except FileNotFoundError:
                logger.warning("Log file not found: %s", self.source.path)
                await asyncio.sleep(self._poll_interval)
                continue
            except Exception:
                logger.exception("Unexpected error tailing %s", self.source.path)
                await asyncio.sleep(self._poll_interval)
                continue

            self._save_offset(offset)
            await asyncio.sleep(self._poll_interval)

    async def stop(self) -> None:
        self._running = False

    def _load_offset(self) -> int:
        try:
            return int(self._offset_file.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_offset(self, offset: int) -> None:
        self._offset_file.write_text(str(offset))

    async def _read_cycle(self, offset: int) -> int:
        stat = self.source.path.stat()

        if self._last_inode is not None and stat.st_ino != self._last_inode:
            logger.info("Log rotation detected (inode changed) for %s", self.source.path)
            offset = 0

        if stat.st_size < offset:
            logger.info("Log rotation detected (truncation) for %s", self.source.path)
            offset = 0

        self._last_inode = stat.st_ino
        self._last_size = stat.st_size

        if stat.st_size == offset:
            return offset

        async with aiofiles.open(self.source.path) as f:
            await f.seek(offset)
            content = await f.read()

        if not content:
            return offset

        new_offset = offset + len(content.encode("utf-8"))

        for line in content.splitlines():
            if not line:
                continue
            entry = self.parser.parse(line, self.source.name)
            if entry is not None:
                await self.queue.put(entry)

        return new_offset
