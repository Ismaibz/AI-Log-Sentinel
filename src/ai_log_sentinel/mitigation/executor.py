from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ai_log_sentinel.models.alert import Alert, AlertStatus

logger = logging.getLogger(__name__)

_LOG_PATH = Path("data/execution_log.json")


@dataclass
class CommandResult:
    rule_type: str
    command: str
    success: bool
    output: str
    rollback_command: str


@dataclass
class ExecutionRecord:
    alert_id: str
    results: list[CommandResult]
    success: bool
    executed_at: datetime
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["executed_at"] = self.executed_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ExecutionRecord:
        d["executed_at"] = datetime.fromisoformat(d["executed_at"])
        d["results"] = [CommandResult(**r) for r in d["results"]]
        return cls(**d)


class MitigationExecutor:
    def __init__(self, config: dict[str, Any]) -> None:
        self.dry_run: bool = config.get("dry_run", True)
        self.rollback_on_failure: bool = config.get("rollback_on_failure", True)
        self.ufw_cmd: str = config.get("ufw_cmd", "sudo ufw")
        self.nginx_config_dir: str = config.get("nginx_config_dir", "/etc/nginx/conf.d")
        self.nginx_reload_cmd: str = config.get("nginx_reload_cmd", "sudo nginx -s reload")
        self.execution_log: list[ExecutionRecord] = []
        self._alert_records: dict[str, ExecutionRecord] = {}
        self._load_log()

    async def execute(self, alert: Alert) -> ExecutionRecord:
        if alert.status != AlertStatus.APPROVED:
            logger.warning("Alert %s not approved (status=%s)", alert.id, alert.status)
            return ExecutionRecord(
                alert_id=alert.id,
                results=[],
                success=False,
                executed_at=datetime.now(),
                dry_run=self.dry_run,
            )

        results: list[CommandResult] = []
        for rule in alert.mitigation_rules:
            result = await self._run_command(rule, alert.id)
            results.append(result)
            if not result.success:
                rule_type = rule.get("rule_type", "")
                if rule_type.startswith("nginx") and self.rollback_on_failure:
                    await self._rollback_results(results[:-1])
                break

        success = all(r.success for r in results)
        record = ExecutionRecord(
            alert_id=alert.id,
            results=results,
            success=success,
            executed_at=datetime.now(),
            dry_run=self.dry_run,
        )
        self._store_record(record)
        if success:
            alert.status = AlertStatus.EXECUTED
        else:
            alert.status = AlertStatus.FAILED
        return record

    async def rollback(self, alert_id: str) -> ExecutionRecord | None:
        original = self._alert_records.get(alert_id)
        if original is None:
            logger.warning("No execution record for alert %s", alert_id)
            return None

        results: list[CommandResult] = []
        for prev in reversed(original.results):
            if not prev.rollback_command:
                continue
            result = await self._run_raw_command(prev.rollback_command, prev.rule_type)
            results.append(result)

        record = ExecutionRecord(
            alert_id=alert_id,
            results=results,
            success=all(r.success for r in results),
            executed_at=datetime.now(),
            dry_run=self.dry_run,
        )
        self._store_record(record)
        return record

    async def _run_command(self, rule_dict: dict[str, Any], alert_id: str = "") -> CommandResult:
        rule_type = rule_dict.get("rule_type", "unknown")
        command = rule_dict.get("command", "")
        rollback_command = rule_dict.get("rollback_command", "")

        if self.dry_run:
            output = f"[DRY RUN] {command}"
            logger.info("DRY RUN: %s", command)
            return CommandResult(
                rule_type=rule_type,
                command=command,
                success=True,
                output=output,
                rollback_command=rollback_command,
            )

        if rule_type.startswith("nginx"):
            return await self._run_nginx_command(rule_dict, alert_id)

        return await self._run_raw_command(command, rule_type, rollback_command)

    async def _run_nginx_command(self, rule_dict: dict[str, Any], alert_id: str) -> CommandResult:
        rule_type = rule_dict.get("rule_type", "nginx")
        command = rule_dict.get("command", "")
        rollback_command = rule_dict.get("rollback_command", "")
        config_content = rule_dict.get("config_content", command)

        short_id = alert_id[:8] if alert_id else "unknown"
        conf_file = Path(self.nginx_config_dir) / f"sentinel_block_{short_id}.conf"

        try:
            conf_file.parent.mkdir(parents=True, exist_ok=True)
            conf_file.write_text(config_content + "\n")
            logger.info("Wrote nginx config: %s", conf_file)
        except OSError as exc:
            return CommandResult(
                rule_type=rule_type,
                command=command,
                success=False,
                output=str(exc),
                rollback_command=rollback_command,
            )

        test_proc = await asyncio.create_subprocess_exec(
            *("sudo", "nginx", "-t"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await test_proc.communicate()
        if test_proc.returncode != 0:
            conf_file.unlink(missing_ok=True)
            output = stderr.decode().strip()
            logger.error("nginx -t failed: %s", output)
            return CommandResult(
                rule_type=rule_type,
                command=command,
                success=False,
                output=output,
                rollback_command=rollback_command,
            )

        reload_proc = await asyncio.create_subprocess_exec(
            *self.nginx_reload_cmd.split(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await reload_proc.communicate()
        output = stderr.decode().strip() if reload_proc.returncode != 0 else conf_file.as_posix()
        success = reload_proc.returncode == 0

        effective_rollback = rollback_command or f"rm -f {conf_file} && {self.nginx_reload_cmd}"

        return CommandResult(
            rule_type=rule_type,
            command=command,
            success=success,
            output=output,
            rollback_command=effective_rollback,
        )

    async def _run_raw_command(
        self,
        command: str,
        rule_type: str,
        rollback_command: str = "",
    ) -> CommandResult:
        if self.dry_run:
            output = f"[DRY RUN] {command}"
            logger.info("DRY RUN: %s", command)
            return CommandResult(
                rule_type=rule_type,
                command=command,
                success=True,
                output=output,
                rollback_command=rollback_command,
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *command.split(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = (stdout or stderr).decode().strip()
            return CommandResult(
                rule_type=rule_type,
                command=command,
                success=proc.returncode == 0,
                output=output,
                rollback_command=rollback_command,
            )
        except asyncio.TimeoutError:
            return CommandResult(
                rule_type=rule_type,
                command=command,
                success=False,
                output="Command timed out after 30s",
                rollback_command=rollback_command,
            )
        except Exception as exc:
            return CommandResult(
                rule_type=rule_type,
                command=command,
                success=False,
                output=str(exc),
                rollback_command=rollback_command,
            )

    async def _rollback_results(self, results: list[CommandResult]) -> None:
        for result in reversed(results):
            if result.rollback_command:
                await self._run_raw_command(result.rollback_command, result.rule_type)

    def _store_record(self, record: ExecutionRecord) -> None:
        self.execution_log.append(record)
        self._alert_records[record.alert_id] = record
        self._save_log()

    def _save_log(self) -> None:
        try:
            _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            data = [r.to_dict() for r in self.execution_log]
            _LOG_PATH.write_text(json.dumps(data, indent=2))
        except OSError as exc:
            logger.error("Failed to save execution log: %s", exc)

    def _load_log(self) -> None:
        if not _LOG_PATH.exists():
            return
        try:
            data = json.loads(_LOG_PATH.read_text())
            self.execution_log = [ExecutionRecord.from_dict(d) for d in data]
            for record in self.execution_log:
                self._alert_records[record.alert_id] = record
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("Failed to load execution log: %s", exc)
