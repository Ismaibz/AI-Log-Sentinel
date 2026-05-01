"""Threat categorizer — L1 rules, L2 fast AI, L2 deep AI."""

from __future__ import annotations

import json
import logging
import re
from collections import deque
from datetime import datetime, timezone
from typing import Any

from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)
from ai_log_sentinel.reasoning.batch_stats import BatchStats
from ai_log_sentinel.reasoning.escalation import should_escalate
from ai_log_sentinel.reasoning.local_rules import LocalRuleEngine
from ai_log_sentinel.reasoning.prompts import build_flash_prompt, build_pro_prompt
from ai_log_sentinel.reasoning.providers.base import ReasoningProvider

logger = logging.getLogger(__name__)


class ThreatCategorizer:
    def __init__(
        self,
        provider: ReasoningProvider,
        config: dict[str, Any],
        deep_provider: ReasoningProvider | None = None,
    ) -> None:
        self.provider = provider
        self.deep_provider = deep_provider
        self.config = config
        reasoning = config.get("reasoning", {})
        self.batch_size = reasoning.get("batch_size", 5)
        context_window = reasoning.get("context_window", 30)
        self._recent: deque[AnonymizedEntry] = deque(maxlen=context_window)
        self._local_rules = LocalRuleEngine(config)

    async def categorize(self, entries: list[AnonymizedEntry]) -> list[ThreatAssessment]:
        non_noise = [e for e in entries if not e.is_noise]
        if not non_noise:
            return []

        assessments: list[ThreatAssessment] = []

        for i in range(0, len(non_noise), self.batch_size):
            batch = non_noise[i : i + self.batch_size]
            self._update_recent(batch)

            source_label = self._resolve_source_label(batch)

            context_entries = list(self._recent)
            l1_results, consumed = self._local_rules.evaluate(context_entries)
            if l1_results:
                for r in l1_results:
                    logger.info(
                        "L1 match: category=%s severity=%s summary=%s",
                        r.category.value,
                        r.severity.value,
                        r.summary,
                    )
                if consumed:
                    consumed_ids = {id(e) for e in consumed}
                    self._recent = deque(
                        (e for e in self._recent if id(e) not in consumed_ids),
                        maxlen=self._recent.maxlen,
                    )
                assessments.extend(l1_results)
                continue

            batch_str = "\n".join(e.sanitized_line for e in batch)
            stats = BatchStats.compute(context_entries)
            context_summary = stats.to_summary_text()

            prompt = build_flash_prompt(
                batch_str, source_label=source_label, context_summary=context_summary
            )
            raw = await self.provider.analyze_fast(prompt)

            try:
                result = json.loads(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                logger.warning("L2 fast JSON parse failed for batch starting at index %d", i)
                assessments.append(self._make_parse_error_assessment(source_label))
                continue

            assessment = self._build_assessment(result, source_label)
            self._enrich_assessment(assessment, batch_str)

            if should_escalate(result, self.config):
                assessment = await self._escalate_to_deep(
                    batch_str, result, assessment, context_summary
                )
                self._enrich_assessment(assessment, batch_str)

            assessments.append(assessment)

        return assessments

    def _update_recent(self, batch: list[AnonymizedEntry]) -> None:
        for entry in batch:
            self._recent.append(entry)

    def _build_assessment(self, result: dict[str, Any], source_label: str = "") -> ThreatAssessment:
        try:
            category = ThreatCategory(result.get("category", "normal"))
        except (ValueError, KeyError):
            category = ThreatCategory.NORMAL

        try:
            severity = Severity(result.get("severity", "low"))
        except (ValueError, KeyError):
            severity = Severity.LOW

        try:
            confidence = float(result.get("confidence", 0.0))
        except (ValueError, TypeError):
            confidence = 0.0

        return ThreatAssessment(
            category=category,
            severity=severity,
            confidence=confidence,
            summary=result.get("summary", ""),
            indicators=result.get("indicators", []),
            recommended_action=self._parse_action(result.get("recommended_action", "alert_only")),
            action_details=self._extract_action_details(result.get("action_details", {})),
            mitre_ttps=result.get("mitre_ttps", []),
            analyzed_by="l2_fast",
            timestamp=datetime.now(timezone.utc),
            source_label=source_label,
        )

    async def _escalate_to_deep(
        self,
        batch_str: str,
        flash_result: dict[str, Any],
        flash_assessment: ThreatAssessment,
        context_summary: str = "",
    ) -> ThreatAssessment:
        if self.deep_provider is None:
            return flash_assessment

        pro_prompt = build_pro_prompt(
            batch_str,
            flash_result.get("category", "normal"),
            float(flash_result.get("confidence", 0.0)),
            batch_str,
            source_label=flash_assessment.source_label,
            context_summary=context_summary,
        )
        raw = await self.deep_provider.analyze_deep(pro_prompt)

        try:
            pro_result = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.warning("L2 deep JSON parse failed, keeping fast result")
            return flash_assessment

        return self._build_deep_assessment(pro_result, flash_assessment)

    def _build_deep_assessment(
        self,
        result: dict[str, Any],
        fast_assessment: ThreatAssessment,
    ) -> ThreatAssessment:
        try:
            severity = Severity(result.get("severity", fast_assessment.severity.value))
        except (ValueError, KeyError):
            severity = fast_assessment.severity

        try:
            confidence = float(result.get("confidence", fast_assessment.confidence))
        except (ValueError, TypeError):
            confidence = fast_assessment.confidence

        try:
            recommended_action = RecommendedAction(result.get("recommended_action", "alert_only"))
        except (ValueError, KeyError):
            recommended_action = RecommendedAction.ALERT_ONLY

        summary = result.get("summary", result.get("threat_type", fast_assessment.summary))

        return ThreatAssessment(
            category=fast_assessment.category,
            severity=severity,
            confidence=confidence,
            summary=summary if isinstance(summary, str) else fast_assessment.summary,
            indicators=[],
            recommended_action=recommended_action,
            action_details=self._extract_action_details(result.get("action_details", {})),
            mitre_ttps=result.get("mitre_ttps", []),
            analyzed_by="l2_deep",
            timestamp=datetime.now(timezone.utc),
            source_label=fast_assessment.source_label,
        )

    @staticmethod
    def _make_parse_error_assessment(source_label: str = "") -> ThreatAssessment:
        return ThreatAssessment(
            category=ThreatCategory.NORMAL,
            severity=Severity.LOW,
            confidence=0.0,
            summary="parse error",
            analyzed_by="l2_fast",
            timestamp=datetime.now(timezone.utc),
            source_label=source_label,
        )

    @staticmethod
    def _resolve_source_label(batch: list[AnonymizedEntry]) -> str:
        counts: dict[str, int] = {}
        for entry in batch:
            label = entry.source_label
            counts[label] = counts.get(label, 0) + 1
        if not counts:
            return ""
        return max(counts, key=counts.get)  # type: ignore[arg-type]

    @staticmethod
    def _parse_action(value: Any) -> RecommendedAction:
        try:
            return RecommendedAction(value)
        except (ValueError, KeyError):
            return RecommendedAction.ALERT_ONLY

    @staticmethod
    def _extract_action_details(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            return {"details": value}
        return {}

    @staticmethod
    def _extract_from_batch(batch_str: str) -> dict[str, Any]:
        ip_token_re = re.compile(r"\[IP_\d+\]")
        real_ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        path_re = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD) ([^ ]+) HTTP')

        ips = ip_token_re.findall(batch_str)
        if not ips:
            ips = real_ip_re.findall(batch_str)
        ips = list(dict.fromkeys(ips))

        paths = list(dict.fromkeys(path_re.findall(batch_str)))
        details: dict[str, Any] = {}
        if ips:
            details["ip"] = ips[0]
            details["ips"] = ips
        if paths:
            details["path"] = paths[0]
            details["paths"] = paths
        return details

    def _enrich_assessment(self, assessment: ThreatAssessment, batch_str: str) -> None:
        if not assessment.action_details:
            assessment.action_details = self._extract_from_batch(batch_str)

        if assessment.recommended_action not in (
            RecommendedAction.ALERT_ONLY,
            RecommendedAction.INVESTIGATE,
        ):
            return

        if assessment.category == ThreatCategory.NORMAL:
            return

        if assessment.category in (
            ThreatCategory.BRUTEFORCE,
            ThreatCategory.EXPLOIT_ATTEMPT,
            ThreatCategory.MALICIOUS,
        ):
            assessment.recommended_action = RecommendedAction.BLOCK_IP
        elif assessment.category in (
            ThreatCategory.SCAN,
            ThreatCategory.SUSPICIOUS,
        ) and assessment.action_details.get("ips"):
            assessment.recommended_action = RecommendedAction.RATE_LIMIT
