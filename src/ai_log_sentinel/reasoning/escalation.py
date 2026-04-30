"""Escalation criteria and thresholds."""

from __future__ import annotations


def should_escalate(flash_result: dict, config: dict) -> bool:
    reasoning = config.get("reasoning", {})
    esc = reasoning.get("escalation", {})
    threshold = reasoning.get("escalation_confidence", esc.get("threshold", 0.6))

    if flash_result.get("confidence", 1.0) < threshold:
        return True

    return bool(
        flash_result.get("category") in ("suspicious", "scan")
        and flash_result.get("confidence", 1.0) < 0.8
    )
