"""Escalation criteria and thresholds."""

from __future__ import annotations


def should_escalate(flash_result: dict, config: dict) -> bool:
    reasoning = config.get("reasoning", {})
    esc = reasoning.get("escalation", {})
    threshold = reasoning.get("escalation_confidence", esc.get("threshold", 0.6))
    always_escalate = esc.get("always_escalate", ["exploit_attempt", "bruteforce"])
    always_escalate_severity = esc.get("always_escalate_severity", ["high", "critical"])

    if flash_result.get("confidence", 1.0) < threshold:
        return True
    if flash_result.get("category") in always_escalate:
        return True
    return flash_result.get("severity") in always_escalate_severity
