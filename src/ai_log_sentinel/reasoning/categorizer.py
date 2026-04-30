"""Threat categorizer — Flash first, escalate to Pro."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from ai_log_sentinel.models.anonymized_entry import AnonymizedEntry
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)
from ai_log_sentinel.reasoning.escalation import should_escalate
from ai_log_sentinel.reasoning.gemini_client import GeminiClient
from ai_log_sentinel.reasoning.prompts import build_flash_prompt, build_pro_prompt

logger = logging.getLogger(__name__)


class ThreatCategorizer:
    def __init__(self, client: GeminiClient, config: dict[str, Any]) -> None:
        self.client = client
        self.config = config
        reasoning = config.get("reasoning", {})
        self.batch_size = reasoning.get("batch_size", 10)

    async def categorize(self, entries: list[AnonymizedEntry]) -> list[ThreatAssessment]:
        non_noise = [e for e in entries if not e.is_noise]
        if not non_noise:
            return []

        assessments: list[ThreatAssessment] = []

        for i in range(0, len(non_noise), self.batch_size):
            batch = non_noise[i : i + self.batch_size]
            batch_str = "\n".join(e.sanitized_line for e in batch)

            prompt = build_flash_prompt(batch_str)
            raw = await self.client.analyze_flash(prompt, batch_str)

            try:
                result = json.loads(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                logger.warning("Flash JSON parse failed for batch starting at index %d", i)
                assessments.append(
                    ThreatAssessment(
                        category=ThreatCategory.NORMAL,
                        severity=Severity.LOW,
                        confidence=0.0,
                        summary="parse error",
                        analyzed_by="flash",
                        timestamp=datetime.now(timezone.utc),
                    )
                )
                continue

            flash_assessment = self._build_flash_assessment(result)

            if should_escalate(result, self.config):
                flash_assessment = await self._escalate_to_pro(batch_str, result, flash_assessment)

            assessments.append(flash_assessment)

        return assessments

    def _build_flash_assessment(self, result: dict[str, Any]) -> ThreatAssessment:
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
            mitre_ttps=[],
            analyzed_by="flash",
            timestamp=datetime.now(timezone.utc),
        )

    async def _escalate_to_pro(
        self,
        batch_str: str,
        flash_result: dict[str, Any],
        flash_assessment: ThreatAssessment,
    ) -> ThreatAssessment:
        pro_prompt = build_pro_prompt(
            batch_str,
            flash_result.get("category", "normal"),
            float(flash_result.get("confidence", 0.0)),
            batch_str,
        )
        raw = await self.client.analyze_pro(pro_prompt, batch_str)

        try:
            pro_result = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.warning("Pro JSON parse failed, keeping flash result")
            return flash_assessment

        return self._build_pro_assessment(pro_result, flash_assessment)

    def _build_pro_assessment(
        self,
        result: dict[str, Any],
        flash_assessment: ThreatAssessment,
    ) -> ThreatAssessment:
        try:
            severity = Severity(result.get("severity", flash_assessment.severity.value))
        except (ValueError, KeyError):
            severity = flash_assessment.severity

        try:
            confidence = float(result.get("confidence", flash_assessment.confidence))
        except (ValueError, TypeError):
            confidence = flash_assessment.confidence

        try:
            recommended_action = RecommendedAction(result.get("recommended_action", "alert_only"))
        except (ValueError, KeyError):
            recommended_action = RecommendedAction.ALERT_ONLY

        summary = result.get("summary", result.get("threat_type", "Pro analysis"))

        return ThreatAssessment(
            category=flash_assessment.category,
            severity=severity,
            confidence=confidence,
            summary=summary if isinstance(summary, str) else "Pro analysis",
            indicators=[],
            recommended_action=recommended_action,
            action_details=self._extract_action_details(result.get("action_details", {})),
            mitre_ttps=result.get("mitre_ttps", []),
            analyzed_by="pro",
            timestamp=datetime.now(timezone.utc),
        )

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
