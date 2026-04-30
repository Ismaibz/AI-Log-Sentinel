from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

from ai_log_sentinel.models.alert import Alert, AlertStatus
from ai_log_sentinel.models.threat import Severity

logger = logging.getLogger(__name__)

_CRITICAL_RULE_TYPES = frozenset({"ufw", "nginx_deny"})
_CRITICAL_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})


class HITLGate:
    def __init__(self, config: dict[str, Any]) -> None:
        self.pending: dict[str, Alert] = {}
        self.timeout: int = config.get("hitl", {}).get("timeout", 300)
        self.auto_approve_severity: list[str] = config.get("auto_approve_severity", [])
        self._approved_callbacks: list[Callable[[Alert], Awaitable[None]]] = []
        self._rejected_callbacks: list[Callable[[Alert], Awaitable[None]]] = []
        self._timeout_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def submit(self, alert: Alert) -> AlertStatus:
        can_auto = (
            alert.threat.severity.value in self.auto_approve_severity
            and not self.is_critical(alert)
        )
        if can_auto:
            alert.auto_action = True
            alert.status = AlertStatus.APPROVED
            alert.resolved_at = datetime.now()
            logger.info(
                "Auto-approved alert %s (severity=%s)",
                alert.id,
                alert.threat.severity.value,
            )
            await self._dispatch_approved(alert)
            return alert.status

        async with self._lock:
            alert.status = AlertStatus.PENDING
            self.pending[alert.id] = alert
        logger.info(
            "Alert %s queued for approval (severity=%s)",
            alert.id,
            alert.threat.severity.value,
        )
        return alert.status

    async def approve(self, alert_id: str) -> None:
        async with self._lock:
            alert = self.pending.pop(alert_id, None)
        if alert is None:
            logger.warning("Approve called for unknown/expired alert %s", alert_id)
            return
        alert.status = AlertStatus.APPROVED
        alert.resolved_at = datetime.now()
        logger.info("Alert %s approved", alert_id)
        await self._dispatch_approved(alert)

    async def reject(self, alert_id: str) -> None:
        async with self._lock:
            alert = self.pending.pop(alert_id, None)
        if alert is None:
            logger.warning("Reject called for unknown/expired alert %s", alert_id)
            return
        alert.status = AlertStatus.REJECTED
        alert.resolved_at = datetime.now()
        logger.info("Alert %s rejected", alert_id)
        await self._dispatch_rejected(alert)

    async def start_timeout_watcher(self) -> None:
        self._timeout_task = asyncio.create_task(self._timeout_loop())

    async def _timeout_loop(self) -> None:
        while True:
            await asyncio.sleep(10)
            now = datetime.now()
            expired_ids: list[str] = []
            async with self._lock:
                for alert_id, alert in list(self.pending.items()):
                    elapsed = (now - alert.created_at).total_seconds()
                    if elapsed > self.timeout:
                        expired_ids.append(alert_id)
                for alert_id in expired_ids:
                    alert = self.pending.pop(alert_id)
                    alert.status = AlertStatus.EXPIRED
                    alert.resolved_at = now
                    logger.warning(
                        "Alert %s expired after %ds (timeout=%d)",
                        alert_id,
                        int(elapsed),
                        self.timeout,
                    )

    def stop_timeout_watcher(self) -> None:
        if self._timeout_task is not None:
            self._timeout_task.cancel()
            self._timeout_task = None

    def is_critical(self, alert: Alert) -> bool:
        if alert.threat.severity in _CRITICAL_SEVERITIES:
            return True
        return any(rule.get("rule_type") in _CRITICAL_RULE_TYPES for rule in alert.mitigation_rules)

    def on_approved(self, callback: Callable[[Alert], Awaitable[None]]) -> None:
        self._approved_callbacks.append(callback)

    def on_rejected(self, callback: Callable[[Alert], Awaitable[None]]) -> None:
        self._rejected_callbacks.append(callback)

    async def _dispatch_approved(self, alert: Alert) -> None:
        for cb in self._approved_callbacks:
            try:
                await cb(alert)
            except Exception:
                logger.exception("Error in approved callback for alert %s", alert.id)

    async def _dispatch_rejected(self, alert: Alert) -> None:
        for cb in self._rejected_callbacks:
            try:
                await cb(alert)
            except Exception:
                logger.exception("Error in rejected callback for alert %s", alert.id)
