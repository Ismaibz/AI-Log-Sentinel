"""Prompt templates for threat analysis."""

from __future__ import annotations


def build_flash_prompt(batch: str, source_label: str = "", context_summary: str = "") -> str:
    parts: list[str] = []

    parts.append(
        "You are a security log analyzer. "
        "Examine the following log entries and categorize the activity.\n\n"
        "Return ONLY valid JSON — no markdown fences, no explanation, no extra text.\n\n"
        "JSON schema:\n"
        "{\n"
        '  "category": "normal" | "suspicious" | "malicious" | "scan"'
        ' | "bruteforce" | "exploit_attempt",\n'
        '  "severity": "low" | "medium" | "high" | "critical",\n'
        '  "confidence": 0.0 to 1.0,\n'
        '  "summary": "one-line English summary of the observed activity",\n'
        '  "indicators":'
        ' ["list of specific observable strings that drove your decision"],\n'
        '  "recommended_action": "block_ip" | "block_path"'
        ' | "rate_limit" | "alert_only" | "investigate",\n'
        '  "action_details": {\n'
        '    "ip": "the attacker IP exactly as it appears in the logs, or null",\n'
        '    "ips": ["all attacker IPs from the logs"],\n'
        '    "path": "the targeted path exactly as in the logs, or null",\n'
        '    "paths": ["all targeted paths from the logs"]\n'
        "  }\n"
        "}\n\n"
        "CRITICAL: Extract IP addresses and paths EXACTLY as they appear in the logs. "
        "Do NOT invent or guess values. If the log shows [IP_001], return [IP_001]. "
        "If the log shows /admin, return /admin.\n"
    )

    if source_label:
        parts.append(f"\nLog source: {source_label}\n")

    if context_summary:
        parts.append(
            "\n=== PRE-ANALYSIS CONTEXT ===\n" f"{context_summary}\n" "=== END CONTEXT ===\n"
        )

    parts.append(f"\nLog entries:\n\n{batch}")
    return "".join(parts)


def build_pro_prompt(
    batch: str,
    flash_category: str,
    flash_confidence: float,
    context: str,
    source_label: str = "",
    context_summary: str = "",
) -> str:
    parts: list[str] = []

    parts.append(
        "You are a senior security analyst performing a deep threat investigation. "
        "Analyze the following log entries with full rigor.\n\n"
        "Consider multi-stage attack vectors, correlation between entries, "
        "attacker tactics/techniques/procedures (TTPs), and MITRE ATT&CK mapping.\n\n"
        f"Previous rapid-triage result:\n"
        f"- Category: {flash_category}\n"
        f"- Confidence: {flash_confidence}\n\n"
        f"Previous related entries (context window):\n\n"
        f"{context}\n\n"
        "Return ONLY valid JSON — no markdown fences, no explanation, no extra text.\n\n"
        "JSON schema:\n"
        "{\n"
        '  "threat_type": "descriptive threat label",\n'
        '  "severity": "low" | "medium" | "high" | "critical",\n'
        '  "confidence": 0.0 to 1.0,\n'
        '  "attack_pattern": "named attack pattern or null",\n'
        '  "mitre_ttps": ["T1190", "..."],\n'
        '  "recommended_action": "block_ip" | "block_path"'
        ' | "rate_limit" | "alert_only" | "investigate",\n'
        '  "action_details": {\n'
        '    "ip": "the attacker IP exactly as it appears in the logs, or null",\n'
        '    "ips": ["all attacker IPs from the logs"],\n'
        '    "path": "the targeted path exactly as in the logs, or null",\n'
        '    "paths": ["all targeted paths from the logs"],\n'
        '    "zone_name": "name for rate limit zone (if rate_limit)",\n'
        '    "rate": "rate limit string like 10r/m (if rate_limit)"\n'
        "  },\n"
        '  "summary": "detailed one-line English summary"\n'
        "}\n\n"
        "CRITICAL: Extract IP addresses and paths EXACTLY as they appear in the logs. "
        "Do NOT invent or guess values. If the log shows [IP_001], return [IP_001]. "
        "If the log shows /admin, return /admin.\n"
    )

    if source_label:
        parts.append(f"\nLog source: {source_label}\n")

    if context_summary:
        parts.append(
            "\n=== PRE-ANALYSIS CONTEXT ===\n" f"{context_summary}\n" "=== END CONTEXT ===\n"
        )

    parts.append(f"\nAnomalous log entries:\n\n{batch}")
    return "".join(parts)
