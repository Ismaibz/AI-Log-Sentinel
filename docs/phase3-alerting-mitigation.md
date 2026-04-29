# Phase 3 — Alerting & Mitigation

## Goal
Real-time threat notifications via Telegram/Slack + automated mitigation rule generation with human-in-the-loop approval.

## Prerequisites
- Phase 2 complete (pipeline produces `ThreatAssessment`)
- Telegram bot token or Slack webhook URL in `secrets.vibe`

## Scope

### 1. Alert Model (`src/ai_log_sentinel/models/alert.py`)

```python
class AlertStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"

@dataclass
class Alert:
    id: str                         # UUID
    threat: ThreatAssessment        # reference to the assessment
    mitigation_rules: list[str]     # generated UFW/Nginx rules
    status: AlertStatus = AlertStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None
    auto_action: bool = False       # true if action is non-critical and auto-approved
```

### 2. Alert Dispatcher (`src/ai_log_sentinel/alerting/dispatcher.py`)

```python
class AlertDispatcher(ABC):
    @abstractmethod
    async def send(self, alert: Alert) -> bool: ...

    @abstractmethod
    async def handle_response(self, alert_id: str, approved: bool) -> None: ...
```

### 3. Telegram Bot (`src/ai_log_sentinel/alerting/telegram_bot.py`)

```python
class TelegramDispatcher(AlertDispatcher):
    """Send alerts via Telegram with inline approve/reject buttons."""

    def __init__(self, bot_token: str, chat_id: str, hitl: HITLGate):
        self.bot = Bot(token=bot_token)
        self.chat_id = chat_id
        self.hitl = hitl

    async def send(self, alert: Alert) -> bool:
        """Send formatted alert with Approve/Reject inline keyboard."""

    async def start_polling(self) -> None:
        """Start listening for button callbacks."""
        # Callback data: "approve:{alert_id}" or "reject:{alert_id}"
```

Message format (MarkdownV2):
```
🚨 *THREAT DETECTED*

*Category:* Brute Force
*Severity:* HIGH
*Confidence:* 0.92
*Source:* nginx-main
*Time:* 2025-01-15 10:30:45 UTC

*Summary:* 23 failed login attempts from [IP_012] in 2 minutes

*Indicators:*
• Multiple POST /login 401
• Rapid successive attempts
• Common username patterns

*Mitigation suggestion:*
`ufw deny from [IP_012]`

[✅ Approve] [❌ Reject]
```

### 4. Slack Webhook (`src/ai_log_sentinel/alerting/slack_webhook.py`)

```python
class SlackDispatcher(AlertDispatcher):
    """Send alerts via Slack incoming webhook with action buttons."""

    def __init__(self, webhook_url: str, hitl: HITLGate):
        self.webhook_url = webhook_url
        self.hitl = hitl

    async def send(self, alert: Alert) -> bool:
        """Send Block Kit formatted alert."""
```

Uses Slack Block Kit with action buttons. Requires a companion endpoint (or Slack app) to receive button interactions.

### 5. Formatters (`src/ai_log_sentinel/alerting/formatters.py`)

```python
def format_telegram(alert: Alert) -> str:
    """MarkdownV2 formatted alert for Telegram."""

def format_slack(alert: Alert) -> dict:
    """Block Kit payload for Slack."""

def format_console(alert: Alert) -> str:
    """Rich-formatted output for terminal (using rich library)."""
```

### 6. Rule Generator (`src/ai_log_sentinel/mitigation/rule_generator.py`)

```python
class RuleGenerator:
    def generate(self, threat: ThreatAssessment) -> list[MitigationRule]:
        """Generate mitigation rules based on threat type and recommended action."""

@dataclass
class MitigationRule:
    rule_type: str           # "ufw" | "nginx_deny" | "rate_limit"
    command: str             # the actual command/directive
    description: str
    critical: bool           # requires HITL approval
    rollback_command: str    # command to undo this rule
```

Mapping logic:

| Recommended Action | Rule Type | Example |
|---|---|---|
| `block_ip` | UFW | `ufw deny from <ip>` |
| `block_ip` | Nginx | `deny <ip>;` in server block |
| `block_path` | Nginx | `location /path { deny all; }` |
| `rate_limit` | Nginx | `limit_req_zone` directive |
| `alert_only` | None | No rule generated, alert only |

For anonymized IPs: resolve from token store before generating rules.

### 7. Human-in-the-Loop Gate (`src/isma_log_sentinel/mitigation/hitl.py`)

```python
class HITLGate:
    """Manages approval workflow for critical mitigation actions."""

    def __init__(self, config: dict):
        self.pending: dict[str, Alert] = {}
        self.timeout = config.get("hitl_timeout", 300)  # 5 minutes
        self.auto_approve_severity = config.get("auto_approve_severity", ["low"])

    async def submit(self, alert: Alert) -> AlertStatus:
        """Submit alert for approval. Returns immediately.
        - If severity in auto_approve_severity → auto-approve
        - Otherwise → wait for human response or timeout"""

    async def approve(self, alert_id: str) -> None:
        """Mark alert as approved."""

    async def reject(self, alert_id: str) -> None:
        """Mark alert as rejected."""

    async def _timeout_watcher(self) -> None:
        """Background task: expire pending alerts after timeout."""

    def is_critical(self, alert: Alert) -> bool:
        """Determine if this alert requires human approval."""
        # Critical if:
        # - severity is high or critical
        # - rule blocks an entire IP (not just a path)
        # - any UFW rule (firewall change)
```

### 8. Executor (`src/isma_log_sentinel/mitigation/executor.py`)

```python
class MitigationExecutor:
    """Execute approved mitigation rules on the host system."""

    def __init__(self, config: dict):
        self.dry_run = config.get("dry_run", True)  # safe default
        self.execution_log: list[ExecutionRecord] = []

    async def execute(self, alert: Alert) -> ExecutionRecord:
        """Execute all approved rules for an alert."""

    async def rollback(self, alert_id: str) -> None:
        """Rollback all rules executed for an alert."""

    async def _run_command(self, rule: MitigationRule) -> CommandResult:
        """Execute a single rule command via subprocess."""
        # For UFW: subprocess.run(["sudo", "ufw", ...])
        # For Nginx: write conf file + subprocess.run(["sudo", "nginx", "-s", "reload"])
```

Safety measures:
- **Dry run mode** (default): log commands without executing
- Pre-execution validation: syntax check rules before applying
- Rollback on failure: if one rule in a batch fails, rollback all
- Execution log: persistent record of all actions taken
- Nginx config test (`nginx -t`) before reload

### 9. Pipeline Extension (`src/ai_log_sentinel/pipeline/orchestrator.py`)

Extend `_process_batch` from Phase 2:

```python
async def _process_batch(self, batch: list[AnonymizedEntry]) -> None:
    # ... Phase 2: anonymize, filter, categorize ...

    for assessment in assessments:
        if assessment.category == ThreatCategory.NORMAL:
            continue

        # Generate mitigation rules
        rules = self.rule_generator.generate(assessment)

        # Create alert
        alert = Alert(
            threat=assessment,
            mitigation_rules=[r.command for r in rules],
        )

        # Submit through HITL gate
        status = await self.hitl.submit(alert)

        # Dispatch notification
        await self.dispatcher.send(alert)
```

### 10. Configuration additions to `defaults.toml`

```toml
[alerting]
enabled = true
channels = ["console"]  # ["console", "telegram", "slack"]
min_severity = "medium"  # don't alert on low-severity

[alerting.telegram]
chat_id = ""  # from secrets.vibe

[alerting.slack]
webhook_url = ""  # from secrets.vibe

[mitigation]
enabled = true
dry_run = true  # ALWAYS start with dry_run=true
auto_approve_severity = []  # empty = nothing auto-approved

[mitigation.hitl]
timeout = 300  # seconds before auto-reject

[mitigation.executor]
nginx_config_dir = "/etc/nginx/conf.d"
nginx_reload_cmd = "sudo nginx -s reload"
ufw_cmd = "sudo ufw"
rollback_on_failure = true
```

### 11. Tests

#### Unit (`tests/unit/`)
- `test_formatters.py` — verify output format for each channel
  - Telegram: valid MarkdownV2 (no unescaped special chars)
  - Slack: valid Block Kit JSON structure
  - Console: readable output
- `test_rule_generator.py` — each recommended action produces correct rules:
  - `block_ip` → UFW command + Nginx deny directive
  - `block_path` → Nginx location block
  - `rate_limit` → Nginx limit_req_zone
  - Rollback commands are inverse of forward commands
- `test_hitl.py` — approval flow:
  - Critical alerts require approval
  - Low severity auto-approves (if configured)
  - Timeout → auto-reject
- `test_executor.py` — dry run mode:
  - Commands logged but not executed
  - Rollback generates correct inverse commands

#### Integration (`tests/integration/`)
- `test_alerting.py` — full flow with mock dispatcher:
  - Threat → alert created → dispatched → approved → executed (dry run)
  - Verify execution log records
  - Verify reject flow does not execute

### 12. CLI additions

```python
@cli.command()
def list_rules():
    """List all executed mitigation rules."""

@cli.command()
@click.argument("alert_id")
def rollback(alert_id):
    """Rollback mitigation rules for a specific alert."""
```

## Acceptance Criteria

1. Simulated attack → Telegram/Slack alert received in <30 seconds
2. Alert contains all relevant information (category, severity, indicators, suggested fix)
3. Approve button → mitigation rule executed (dry run mode default)
4. Reject button → no action taken, alert logged
5. Critical actions NEVER execute without human approval
6. Dry run mode logs all commands without executing any
7. Rollback works for every rule type
8. All tests pass with `pytest`

## Dependencies
- `python-telegram-bot>=20.0` (optional, `[telegram]` extra)
- `slack-sdk>=3.0` (optional, `[slack]` extra)
