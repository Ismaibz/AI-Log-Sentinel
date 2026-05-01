from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from ai_log_sentinel.anonymizer.token_store import TokenStore
from ai_log_sentinel.models.threat import (
    RecommendedAction,
    Severity,
    ThreatAssessment,
    ThreatCategory,
)

logger = logging.getLogger(__name__)

_IP_TOKEN_RE = re.compile(r"^\[IP_\d+\]$")


@dataclass
class MitigationRule:
    rule_type: str
    command: str
    description: str
    critical: bool
    rollback_command: str


class RuleGenerator:
    def __init__(self, config: dict[str, Any], token_store: TokenStore) -> None:
        self._ufw_cmd = config.get("mitigation", {}).get("executor", {}).get("ufw_cmd", "sudo ufw")
        self._nginx_dir = (
            config.get("mitigation", {})
            .get("executor", {})
            .get("nginx_config_dir", "/etc/nginx/conf.d")
        )
        self._token_store = token_store

    def generate(self, threat: ThreatAssessment) -> list[MitigationRule]:
        action = threat.recommended_action
        details = threat.action_details
        source_label = threat.source_label

        if action == RecommendedAction.INVESTIGATE:
            action = self._infer_action(threat)
            if action in (RecommendedAction.ALERT_ONLY, RecommendedAction.INVESTIGATE):
                return []

        if action == RecommendedAction.ALERT_ONLY:
            action = self._infer_action(threat)
            if action in (RecommendedAction.ALERT_ONLY, RecommendedAction.INVESTIGATE):
                return []

        if action == RecommendedAction.BLOCK_IP:
            return self._block_ip_rules(details, source_label)

        if action == RecommendedAction.BLOCK_PATH:
            return self._block_path_rules(details, source_label)

        if action == RecommendedAction.RATE_LIMIT:
            return self._rate_limit_rules(details, source_label)

        return []

    def _infer_action(self, threat: ThreatAssessment) -> RecommendedAction:
        if threat.severity not in (Severity.HIGH, Severity.CRITICAL):
            return RecommendedAction.ALERT_ONLY

        if threat.category in (
            ThreatCategory.BRUTEFORCE,
            ThreatCategory.EXPLOIT_ATTEMPT,
            ThreatCategory.MALICIOUS,
        ):
            return RecommendedAction.BLOCK_IP

        if threat.category == ThreatCategory.SCAN:
            return RecommendedAction.RATE_LIMIT

        if threat.category == ThreatCategory.SUSPICIOUS:
            return RecommendedAction.RATE_LIMIT

        return RecommendedAction.ALERT_ONLY

    def _resolve_ip(self, value: str) -> str:
        if _IP_TOKEN_RE.match(value):
            resolved = self._token_store.resolve(value)
            if resolved is not None:
                return resolved
            logger.warning("Failed to resolve anonymized IP token: %s", value)
        return value

    def _block_ip_rules(
        self, details: dict[str, Any], source_label: str = ""
    ) -> list[MitigationRule]:
        ips = details.get("ips", [])
        if not ips:
            ips = [details.get("ip")] if details.get("ip") else []

        site_ctx = f" (detected on {source_label})" if source_label else ""
        rules: list[MitigationRule] = []
        for raw_ip in ips:
            ip = self._resolve_ip(str(raw_ip))
            rules.append(
                MitigationRule(
                    rule_type="nginx_deny",
                    command=f"deny {ip};",
                    description=f"Deny IP {ip} in Nginx{site_ctx}",
                    critical=True,
                    rollback_command=f"# remove: deny {ip};",
                )
            )
            rules.append(
                MitigationRule(
                    rule_type="ufw",
                    command=f"{self._ufw_cmd} deny from {ip}",
                    description=f"Block IP {ip} via UFW firewall{site_ctx}",
                    critical=True,
                    rollback_command=f"{self._ufw_cmd} delete deny from {ip}",
                )
            )
        return rules

    def _block_path_rules(
        self, details: dict[str, Any], source_label: str = ""
    ) -> list[MitigationRule]:
        paths = details.get("paths", [])
        if not paths:
            paths = [details.get("path")] if details.get("path") else []

        site_ctx = f" (detected on {source_label})" if source_label else ""
        rules: list[MitigationRule] = []
        for path in paths:
            rules.append(
                MitigationRule(
                    rule_type="nginx_deny",
                    command=f"location {path} {{ deny all; }}",
                    description=f"Deny all access to path {path}{site_ctx}",
                    critical=True,
                    rollback_command=f"# remove: location {path} {{ deny all; }}",
                )
            )
        return rules

    def _rate_limit_rules(
        self, details: dict[str, Any], source_label: str = ""
    ) -> list[MitigationRule]:
        zone_name = details.get("zone_name") or "threat_limit"
        rate = details.get("rate") or "10r/m"

        site_ctx = f" (detected on {source_label})" if source_label else ""
        rules: list[MitigationRule] = []
        rules.append(
            MitigationRule(
                rule_type="rate_limit",
                command=f"limit_req_zone $binary_remote_addr zone={zone_name}:10m rate={rate};",
                description=f"Rate limit zone '{zone_name}' at {rate}{site_ctx}",
                critical=False,
                rollback_command=f"# remove: limit_req_zone ... zone={zone_name}:10m ...",
            )
        )

        path = details.get("path")
        if path:
            rules.append(
                MitigationRule(
                    rule_type="rate_limit",
                    command=f"limit_req zone={zone_name};",
                    description=f"Apply rate limit zone '{zone_name}' to {path}{site_ctx}",
                    critical=False,
                    rollback_command=f"# remove: limit_req zone={zone_name}; from {path}",
                )
            )

        return rules
