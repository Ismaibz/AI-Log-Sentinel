from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

from ai_log_sentinel.alerting.formatters import format_console
from ai_log_sentinel.mitigation.hitl import HITLGate
from ai_log_sentinel.models.alert import Alert, AlertStatus

logger = logging.getLogger(__name__)


class AlertDispatcher(ABC):
    @abstractmethod
    async def send(self, alert: Alert) -> bool: ...

    @abstractmethod
    async def handle_response(self, alert_id: str, approved: bool) -> None: ...


class ConsoleDispatcher(AlertDispatcher):
    def __init__(self, hitl: HITLGate | None = None, interactive: bool = True) -> None:
        self.hitl = hitl
        self.interactive = interactive

    async def send(self, alert: Alert) -> bool:
        formatted = format_console(alert)
        print(formatted)
        if not self.interactive:
            return True
        if alert.status != AlertStatus.PENDING:
            return True
        if self.hitl is None:
            return True
        answer = await asyncio.to_thread(input, "[A]pprove / [R]eject / [S]kip: ")
        normalized = answer.strip().lower()
        if normalized in ("a", "approve"):
            await self.hitl.approve(alert.id)
        elif normalized in ("r", "reject"):
            await self.hitl.reject(alert.id)
        return True

    async def handle_response(self, alert_id: str, approved: bool) -> None:
        if self.hitl is None:
            logger.warning("Cannot handle response for %s: no HITLGate configured", alert_id)
            return
        if approved:
            await self.hitl.approve(alert_id)
        else:
            await self.hitl.reject(alert_id)
