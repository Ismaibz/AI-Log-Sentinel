from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table

from ai_log_sentinel.models.alert import Alert, AlertStatus
from ai_log_sentinel.models.threat import Severity, ThreatCategory

_MD_V2_SPECIAL = r"_*[]()~`>#+-=|{}.!"


def severity_icon(severity: Severity) -> str:
    icons = {
        Severity.CRITICAL: "\U0001f534",
        Severity.HIGH: "\U0001f7e0",
        Severity.MEDIUM: "\U0001f7e1",
        Severity.LOW: "\U0001f7e2",
    }
    return icons[severity]


_CATEGORY_LABELS = {
    ThreatCategory.NORMAL: "Normal",
    ThreatCategory.SUSPICIOUS: "Suspicious",
    ThreatCategory.MALICIOUS: "Malicious",
    ThreatCategory.SCAN: "Scan",
    ThreatCategory.BRUTEFORCE: "Brute Force",
    ThreatCategory.EXPLOIT_ATTEMPT: "Exploit Attempt",
}


def _category_display(category: ThreatCategory) -> str:
    return _CATEGORY_LABELS[category]


def _severity_label(severity: Severity) -> str:
    return f"{severity_icon(severity)} {severity.name}"


def _format_time(dt) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _status_line(status: AlertStatus) -> str:
    labels = {
        AlertStatus.PENDING: "awaiting approval",
        AlertStatus.APPROVED: "approved",
        AlertStatus.REJECTED: "rejected",
        AlertStatus.EXPIRED: "expired",
        AlertStatus.EXECUTED: "executed",
        AlertStatus.FAILED: "failed",
    }
    return f"{status.name} ({labels[status]})"


def format_console(alert: Alert) -> str:
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=80, legacy_windows=False)
    t = alert.threat

    console.print()
    console.print(f"{severity_icon(t.severity)}  THREAT DETECTED", style="bold red")
    console.print("\u2501" * 40, style="red")

    info = Table(show_header=False, box=None, padding=0)
    info.add_column(style="bold cyan", width=13)
    info.add_column()
    if alert.source_label:
        info.add_row("Site:", alert.source_label)
    info.add_row("Category:", _category_display(t.category))
    info.add_row("Severity:", _severity_label(t.severity))
    info.add_row("Confidence:", f"{t.confidence:.2f}")
    source = t.action_details.get("source_ip") or t.action_details.get("ip") or "N/A"
    info.add_row("Source:", source)
    info.add_row("Time:", _format_time(t.timestamp or alert.created_at))
    console.print(info)

    if t.summary:
        console.print()
        console.print("Summary:", style="bold cyan")
        console.print(f"  {t.summary}")

    if t.indicators:
        console.print()
        console.print("Indicators:", style="bold cyan")
        for indicator in t.indicators:
            console.print(f"  \u2022 {indicator}")

    if alert.mitigation_rules:
        console.print()
        console.print("Suggested Mitigation:", style="bold cyan")
        for rule in alert.mitigation_rules:
            cmd = rule.get("command") or rule.get("rule") or str(rule)
            console.print(f"  {cmd}")

    console.print()
    console.print(f"Status: {_status_line(alert.status)}", style="bold yellow")
    console.print()

    return buf.getvalue()


def _escape_markdown_v2(text: str) -> str:
    escaped = []
    for ch in text:
        if ch in _MD_V2_SPECIAL:
            escaped.append("\\")
        escaped.append(ch)
    return "".join(escaped)


def format_telegram(alert: Alert) -> str:
    t = alert.threat
    lines: list[str] = []

    lines.append(f"\U0001f6a8 *{_escape_markdown_v2('THREAT DETECTED')}*")
    lines.append("")
    if alert.source_label:
        lines.append(f"*Site:* {_escape_markdown_v2(alert.source_label)}")
    lines.append(f"*Category:* {_escape_markdown_v2(_category_display(t.category))}")
    lines.append(f"*Severity:* {_escape_markdown_v2(t.severity.name)}")
    lines.append(f"*Confidence:* {_escape_markdown_v2(f'{t.confidence:.2f}')}")
    ts = _format_time(t.timestamp or alert.created_at)
    lines.append(f"*Time:* {_escape_markdown_v2(ts)}")

    if t.summary:
        lines.append("")
        lines.append(f"*Summary:* {_escape_markdown_v2(t.summary)}")

    if t.indicators:
        lines.append("")
        lines.append("*Indicators:*")
        for indicator in t.indicators:
            lines.append(f"\u2022 {_escape_markdown_v2(indicator)}")

    if alert.mitigation_rules:
        lines.append("")
        lines.append("*Mitigation suggestion:*")
        for rule in alert.mitigation_rules:
            cmd = rule.get("command") or rule.get("rule") or str(rule)
            lines.append(f"`{_escape_markdown_v2(cmd)}`")

    return "\n".join(lines)
