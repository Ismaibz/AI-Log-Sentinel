"""Main pipeline orchestrator — ingest → anonymize → reason → alert."""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from typing import Any

from ai_log_sentinel.alerting.dispatcher import AlertDispatcher, ConsoleDispatcher
from ai_log_sentinel.anonymizer.engine import AnonymizationEngine
from ai_log_sentinel.ingestion.log_source import LogSource, load_sources
from ai_log_sentinel.ingestion.parsers import build_parsers
from ai_log_sentinel.ingestion.tailer import LogTailer
from ai_log_sentinel.mitigation.executor import MitigationExecutor
from ai_log_sentinel.mitigation.hitl import HITLGate
from ai_log_sentinel.mitigation.rule_generator import RuleGenerator
from ai_log_sentinel.models.alert import Alert, AlertStatus
from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.log_entry import LogEntry
from ai_log_sentinel.models.threat import Severity, ThreatCategory
from ai_log_sentinel.reasoning.categorizer import ThreatCategorizer
from ai_log_sentinel.reasoning.providers import create_deep_provider, create_provider

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    def __init__(self, config: dict[str, Any], api_key: str = "") -> None:
        self.config = config
        pipeline_cfg = config.get("pipeline", {})
        self.sources = load_sources(config)
        self.parsers = build_parsers()
        self.anonymizer = AnonymizationEngine(config)
        self._anonymization_enabled = config.get("anonymization", {}).get("enabled", True)
        self.provider = create_provider(config, api_key)
        deep_provider = create_deep_provider(config, api_key)
        self.categorizer = ThreatCategorizer(
            provider=self.provider,
            config=config,
            deep_provider=deep_provider,
        )
        self.queue: asyncio.Queue[LogEntry] = asyncio.Queue(
            maxsize=pipeline_cfg.get("max_queue_size", 1000)
        )
        self.batch_size = pipeline_cfg.get("batch_size", 10)
        self.batch_interval = pipeline_cfg.get("batch_interval", 30)
        self._tailers: list[LogTailer] = []
        self._running = False
        self._assessment_map: dict[str, list[AnonymizedEntry]] = {}

        alerting_cfg = config.get("alerting", {})
        mitigation_cfg = config.get("mitigation", {})

        self.alerting_enabled = alerting_cfg.get("enabled", True)
        self.mitigation_enabled = mitigation_cfg.get("enabled", True)
        self.min_severity = Severity(alerting_cfg.get("min_severity", "medium"))

        self.rule_generator = RuleGenerator(config, self.anonymizer.token_store)
        self.hitl = HITLGate(mitigation_cfg)
        self.executor = MitigationExecutor(mitigation_cfg.get("executor", {}))

        self.dispatchers: list[AlertDispatcher] = []
        self._setup_dispatchers(alerting_cfg)

        self.hitl.on_approved(self._on_alert_approved)

    async def run(self) -> None:
        self._running = True
        loop = asyncio.get_running_loop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_signal)

        await self.hitl.start_timeout_watcher()

        for source in self.sources:
            if source.enabled:
                await self._start_tailer(source)

        tasks = [t.start() for t in self._tailers]
        tasks.append(self._batch_processor())

        for dispatcher in self.dispatchers:
            if hasattr(dispatcher, "start_polling"):
                tasks.append(dispatcher.start_polling())

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            self.hitl.stop_timeout_watcher()
            for dispatcher in self.dispatchers:
                if hasattr(dispatcher, "stop_polling"):
                    await dispatcher.stop_polling()
            for tailer in self._tailers:
                await tailer.stop()

    def _handle_signal(self) -> None:
        logger.info("Received shutdown signal")
        self._running = False
        self._shutdown_tasks = [asyncio.ensure_future(tailer.stop()) for tailer in self._tailers]

    def _setup_dispatchers(self, alerting_cfg: dict[str, Any]) -> None:
        channels = alerting_cfg.get("channels", ["console"])

        if "console" in channels:
            self.dispatchers.append(ConsoleDispatcher(hitl=self.hitl, interactive=True))

        if "telegram" in channels:
            telegram_cfg = alerting_cfg.get("telegram", {})
            chat_id = telegram_cfg.get("chat_id", "")
            bot_token = telegram_cfg.get("bot_token", "")
            if chat_id and bot_token:
                from ai_log_sentinel.alerting.telegram_bot import TelegramDispatcher

                self.dispatchers.append(
                    TelegramDispatcher(bot_token=bot_token, chat_id=chat_id, hitl=self.hitl)
                )

    async def _on_alert_approved(self, alert: Alert) -> None:
        if self.mitigation_enabled and alert.mitigation_rules:
            record = await self.executor.execute(alert)
            logger.info(
                "Executed mitigation for alert %s: success=%s dry_run=%s",
                alert.id,
                record.success,
                record.dry_run,
            )

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
        if self._anonymization_enabled:
            anonymized_entries: list[AnonymizedEntry] = []
            for entry in batch:
                anonymized = self.anonymizer.anonymize(entry)
                anonymized_entries.append(anonymized)
        else:
            anonymized_entries = [
                AnonymizedEntry(
                    original=entry,
                    sanitized_line=entry.raw_line,
                    is_noise=False,
                )
                for entry in batch
            ]

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

            if not self.alerting_enabled:
                continue

            if assessment.category == ThreatCategory.NORMAL:
                continue

            if assessment.severity < self.min_severity:
                continue

            rules = self.rule_generator.generate(assessment) if self.mitigation_enabled else []

            alert = Alert(
                threat=assessment,
                mitigation_rules=[
                    {
                        "rule_type": r.rule_type,
                        "command": r.command,
                        "description": r.description,
                        "critical": r.critical,
                        "rollback_command": r.rollback_command,
                    }
                    for r in rules
                ],
                source_label=assessment.source_label,
            )

            status = await self.hitl.submit(alert)

            if status == AlertStatus.APPROVED and alert.auto_action and self.mitigation_enabled:
                record = await self.executor.execute(alert)
                logger.info(
                    "Auto-executed mitigation for alert %s: success=%s",
                    alert.id,
                    record.success,
                )

            for dispatcher in self.dispatchers:
                try:
                    await dispatcher.send(alert)
                except Exception:
                    logger.exception(
                        "Failed to dispatch alert %s via %s",
                        alert.id,
                        type(dispatcher).__name__,
                    )
