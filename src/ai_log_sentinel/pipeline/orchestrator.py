"""Main pipeline orchestrator — ingest → anonymize → reason → alert."""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from typing import Any

from ai_log_sentinel.anonymizer.engine import AnonymizationEngine
from ai_log_sentinel.ingestion.log_source import LogSource, load_sources
from ai_log_sentinel.ingestion.parsers import build_parsers
from ai_log_sentinel.ingestion.tailer import LogTailer
from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.log_entry import LogEntry
from ai_log_sentinel.reasoning.categorizer import ThreatCategorizer
from ai_log_sentinel.reasoning.gemini_client import GeminiClient

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    def __init__(self, config: dict[str, Any], api_key: str) -> None:
        self.config = config
        pipeline_cfg = config.get("pipeline", {})
        self.sources = load_sources(config)
        self.parsers = build_parsers()
        self.anonymizer = AnonymizationEngine(config)
        self.client = GeminiClient(api_key=api_key, config=config)
        self.categorizer = ThreatCategorizer(client=self.client, config=config)
        self.queue: asyncio.Queue[LogEntry] = asyncio.Queue(
            maxsize=pipeline_cfg.get("max_queue_size", 1000)
        )
        self.batch_size = pipeline_cfg.get("batch_size", 10)
        self.batch_interval = pipeline_cfg.get("batch_interval", 30)
        self._tailers: list[LogTailer] = []
        self._running = False
        self._assessment_map: dict[str, list[AnonymizedEntry]] = {}

    async def run(self) -> None:
        self._running = True
        loop = asyncio.get_running_loop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_signal)

        for source in self.sources:
            if source.enabled:
                await self._start_tailer(source)

        tasks = [t.start() for t in self._tailers]
        tasks.append(self._batch_processor())

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            for tailer in self._tailers:
                await tailer.stop()

    def _handle_signal(self) -> None:
        logger.info("Received shutdown signal")
        self._running = False
        self._shutdown_tasks = [asyncio.ensure_future(tailer.stop()) for tailer in self._tailers]

    async def _start_tailer(self, source: LogSource) -> None:
        parser = self.parsers.get(source.format)
        if parser is None:
            logger.warning(
                "No parser for format '%s' (source: %s)",
                source.format,
                source.name,
            )
            return
        tailer = LogTailer(source, parser, self.queue, self.config)
        self._tailers.append(tailer)
        logger.info("Configured tailer for source '%s' (%s)", source.name, source.path)

    async def _batch_processor(self) -> None:
        buffer: list[LogEntry] = []
        last_flush = time.monotonic()

        while self._running:
            timeout = max(0.1, self.batch_interval - (time.monotonic() - last_flush))
            try:
                entry = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                buffer.append(entry)
            except asyncio.TimeoutError:
                pass

            elapsed = time.monotonic() - last_flush >= self.batch_interval
            if buffer and elapsed:
                for i in range(0, len(buffer), self.batch_size):
                    await self._process_batch(buffer[i : i + self.batch_size])
                buffer = []
                last_flush = time.monotonic()

        if buffer:
            for i in range(0, len(buffer), self.batch_size):
                await self._process_batch(buffer[i : i + self.batch_size])

    async def _process_batch(self, batch: list[LogEntry]) -> None:
        anonymized_entries: list[AnonymizedEntry] = []
        for entry in batch:
            anonymized = self.anonymizer.anonymize(entry)
            anonymized_entries.append(anonymized)

        if not anonymized_entries:
            return

        assessments = await self.categorizer.categorize(anonymized_entries)

        for idx, assessment in enumerate(assessments):
            key = f"{assessment.category.value}_{idx}"
            self._assessment_map[key] = anonymized_entries
            logger.info(
                "Assessment: category=%s severity=%s confidence=%.2f summary=%s",
                assessment.category.value,
                assessment.severity.value,
                assessment.confidence,
                assessment.summary,
            )
