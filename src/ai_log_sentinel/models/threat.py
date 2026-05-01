from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ThreatCategory(str, Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SCAN = "scan"
    BRUTEFORCE = "bruteforce"
    EXPLOIT_ATTEMPT = "exploit_attempt"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self > other


class RecommendedAction(str, Enum):
    ALERT_ONLY = "alert_only"
    BLOCK_IP = "block_ip"
    BLOCK_PATH = "block_path"
    RATE_LIMIT = "rate_limit"
    INVESTIGATE = "investigate"


@dataclass
class ThreatAssessment:
    category: ThreatCategory
    severity: Severity
    confidence: float
    summary: str
    indicators: list[str] = field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.ALERT_ONLY
    action_details: dict[str, Any] = field(default_factory=dict)
    mitre_ttps: list[str] = field(default_factory=list)
    analyzed_by: str = ""
    timestamp: datetime | None = None
    source_label: str = ""
