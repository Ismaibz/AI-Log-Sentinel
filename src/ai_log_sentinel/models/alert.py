from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ai_log_sentinel.models.threat import ThreatAssessment


class AlertStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass
class Alert:
    threat: ThreatAssessment
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mitigation_rules: list[dict[str, Any]] = field(default_factory=list)
    status: AlertStatus = AlertStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    resolved_at: datetime | None = None
    auto_action: bool = False
    source_label: str = ""
