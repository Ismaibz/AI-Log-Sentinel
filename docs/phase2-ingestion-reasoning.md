# Phase 2 — Ingestion Layer + Gemini Reasoning

## Goal
End-to-end pipeline: tail log files → parse → anonymize → categorize with Gemini. Working autonomous monitoring loop.

## Prerequisites
- Phase 1 complete (anonymization engine + noise filter)
- Gemini API key configured in `secrets.vibe`

## Scope

### 1. Log Source Configuration (`src/ai_log_sentinel/ingestion/log_source.py`)

```python
@dataclass
class LogSource:
    name: str              # human label: "nginx-main", "syslog-auth"
    path: Path             # /var/log/nginx/access.log
    format: str            # "nginx" | "apache" | "syslog"
    enabled: bool = True
    tags: list[str] = field(default_factory=list)  # ["web", "prod"]
```

Defined in TOML config:

```toml
[[sources]]
name = "nginx-main"
path = "/var/log/nginx/access.log"
format = "nginx"
enabled = true
tags = ["web", "production"]

[[sources]]
name = "syslog-auth"
path = "/var/log/auth.log"
format = "syslog"
enabled = true
tags = ["auth"]
```

### 2. Parser Interface & Implementations (`src/ai_log_sentinel/ingestion/parsers/`)

#### `base.py`

```python
class LogParser(ABC):
    @abstractmethod
    def parse(self, line: str, source_label: str) -> LogEntry | None: ...

    @abstractmethod
    def can_parse(self, line: str) -> bool: ...
```

#### `nginx.py`
Parse Nginx combined log format:
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```
- Extract: source_ip, method, path, status_code, response_size, user_agent, referer, timestamp
- Handle malformed lines gracefully (return None)

#### `apache.py`
Nearly identical to Nginx parser with Apache-specific format variations:
- `%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"`
- May include additional fields (%D, %T for response time)

#### `syslog.py`
Parse syslog formats:
- RFC 3164: `<priority>Mon DD HH:MM:SS hostname app[pid]: message`
- RFC 5424: `<priority>1 YYYY-MM-DDTHH:MM:SSZ hostname app pid msgid structured-data msg`
- For syslog, map parsed fields into LogEntry:
  - `source_ip` → extract from message if present
  - `path` → extract from message (ssh, su, etc.)
  - `status_code` → 0 (not applicable, or extract from message context)
  - `method` → syslog action keyword (LOGIN, FAILED, SESSION, etc.)

### 3. Async Tailer (`src/ai_log_sentinel/ingestion/tailer.py`)

```python
class LogTailer:
    """Async tail -f with position tracking."""

    def __init__(self, source: LogSource, parser: LogParser, queue: asyncio.Queue):
        self.source = source
        self.parser = parser
        self.queue = queue
        self._offset_file = f".tailer_offset_{source.name}"

    async def start(self) -> None:
        """Begin tailing. Resume from last known offset."""

    async def stop(self) -> None:
        """Graceful shutdown, persist offset."""

    def _load_offset(self) -> int:
        """Read saved file position. 0 if new."""

    def _save_offset(self, offset: int) -> None:
        """Persist current file position."""
```

Implementation details:
- Use `asyncio` with `aiofiles` for non-blocking file reads
- Poll interval: configurable (default 0.5s)
- Handle log rotation (file truncation / rename): detect via inode change or file size decrease
- Position persistence in `.tailer_offset_<source_name>` files
- Each parsed `LogEntry` pushed to `asyncio.Queue`

### 4. Gemini Client (`src/ai_log_sentinel/reasoning/gemini_client.py`)

```python
class GeminiClient:
    FLASH_MODEL = "gemini-1.5-flash"
    PRO_MODEL = "gemini-1.5-pro"

    def __init__(self, config: dict, secrets: dict):
        self.api_key = secrets["gemini_api_key"]  # from vibelock-python
        genai.configure(api_key=self.api_key)
        self.rate_limiter = RateLimiter(
            max_calls=config.get("rate_limit", 15),
            period=60
        )

    async def analyze_flash(self, prompt: str, log_batch: str) -> str:
        """Fast first-pass analysis with Flash model."""

    async def analyze_pro(self, prompt: str, log_batch: str) -> str:
        """Deep analysis with Pro model."""

    async def _call(self, model: str, prompt: str, content: str) -> str:
        """Core API call with rate limiting and error handling."""
```

Error handling:
- Rate limit (429) → exponential backoff, max 3 retries
- Server error (5xx) → retry with jitter
- Invalid response → log warning, return empty assessment
- Timeout (30s) → retry once, then skip batch

### 5. Prompt Templates (`src/ai_log_sentinel/reasoning/prompts.py`)

#### Flash prompt (fast categorization)
```
You are a security log analyzer. Categorize each log entry batch.

For each batch, return JSON:
{
  "category": "normal" | "suspicious" | "malicious" | "scan" | "bruteforce" | "exploit_attempt",
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": 0.0-1.0,
  "summary": "one line description",
  "indicators": ["list of suspicious indicators"]
}

Log entries (anonymized):
{batch}
```

#### Pro prompt (deep analysis)
```
You are a senior security analyst performing deep threat investigation.

Analyze the following anomalous log patterns. Consider multi-stage attack vectors,
correlation between entries, and attacker TTPs (MITRE ATT&CK).

Return JSON:
{
  "threat_type": "...",
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": 0.0-1.0,
  "attack_pattern": "description of the attack pattern",
  "mitre_ttps": ["T1190", "..."],
  "recommended_action": "block_ip" | "block_path" | "rate_limit" | "alert_only" | "investigate",
  "action_details": "specific recommendation",
  "summary": "detailed analysis"
}

Context: This batch was flagged as {flash_category} (confidence: {flash_confidence}).
Previous related entries: {context_window}

Anomalous entries (anonymized):
{batch}
```

### 6. Categorizer (`src/ai_log_sentinel/reasoning/categorizer.py`)

```python
class ThreatCategorizer:
    def __init__(self, client: GeminiClient, config: dict):
        self.client = client
        self.escalation_threshold = config.get("escalation_confidence", 0.6)
        self.batch_size = config.get("batch_size", 10)

    async def categorize(self, entries: list[AnonymizedEntry]) -> list[ThreatAssessment]:
        """Batch categorize entries. Escalate low-confidence to Pro."""

    def _should_escalate(self, flash_result: dict) -> bool:
        """Determine if Pro analysis is needed."""
        # Escalate if:
        # - confidence < threshold
        # - category is "exploit_attempt" or "bruteforce"
        # - severity is "high" or "critical"
```

### 7. Threat Models (`src/ai_log_sentinel/models/threat.py`)

```python
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

class RecommendedAction(str, Enum):
    ALERT_ONLY = "alert_only"
    BLOCK_IP = "block_ip"
    BLOCK_PATH = "block_path"
    RATE_LIMIT = "rate_limit"
    INVESTIGATE = "investigate"

@dataclass
class ThreatAssessment:
    # NOTE: entries are NOT stored in the model. The orchestrator maintains
    # the mapping assessment → list[AnonymizedEntry] externally for cleaner
    # serialization and logging.
    category: ThreatCategory
    severity: Severity
    confidence: float
    summary: str
    indicators: list[str] = field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.ALERT_ONLY
    action_details: dict[str, Any] = field(default_factory=dict)
    mitre_ttps: list[str] = field(default_factory=list)
    analyzed_by: str = ""  # "flash" or "pro"
    timestamp: datetime | None = None
```

### 8. Pipeline Orchestrator (`src/ai_log_sentinel/pipeline/orchestrator.py`)

```python
class PipelineOrchestrator:
    def __init__(self, config: dict):
        self.sources = load_sources(config)
        self.parsers = build_parsers()
        self.anonymizer = AnonymizationEngine(config)
        self.noise_filter = NoiseFilter(config)
        self.categorizer = ThreatCategorizer(client, config)
        self.queue: asyncio.Queue[LogEntry] = asyncio.Queue(maxsize=1000)
        self.batch_buffer: list[AnonymizedEntry] = []
        self.batch_interval = config.get("batch_interval", 30)  # seconds
        self.batch_size = config.get("batch_size", 10)

    async def run(self) -> None:
        """Main loop: start tailers, process batches."""
        tasks = [self._start_tailer(src) for src in self.sources if src.enabled]
        tasks.append(self._batch_processor())
        await asyncio.gather(*tasks)

    async def _start_tailer(self, source: LogSource) -> None:
        """Tail a source, parse, push to queue."""

    async def _batch_processor(self) -> None:
        """Collect entries, batch analyze on interval or size threshold."""

    async def _process_batch(self, batch: list[AnonymizedEntry]) -> None:
        """Anonymize → filter → categorize → (Phase 3: alert/mitigate)."""
```

### 9. Settings & Secrets (`src/ai_log_sentinel/config/settings.py`)

```python
from vibelock_python import VibelockClient  # or however the SDK works

class Settings:
    def __init__(self, config_path: str | None = None):
        self.config = self._load_toml(config_path)
        self.secrets = self._load_secrets()

    def _load_toml(self, path: str | None) -> dict:
        """Load defaults.toml, then overlay user config."""

    def _load_secrets(self) -> dict:
        """Load secrets from secrets.vibe via vibelock-python."""

    def get(self, key: str, default=None):
        """Dot-notation access: settings.get("pipeline.batch_size")"""
```

### 10. Configuration additions to `defaults.toml`

```toml
[pipeline]
batch_size = 10
batch_interval = 30
max_queue_size = 1000

[reasoning]
flash_model = "gemini-1.5-flash"
pro_model = "gemini-1.5-pro"
escalation_confidence = 0.6
rate_limit = 15
rate_limit_period = 60
request_timeout = 30
max_retries = 3

[reasoning.escalation]
# Always escalate these categories to Pro regardless of confidence
always_escalate = ["exploit_attempt", "bruteforce"]
always_escalate_severity = ["high", "critical"]

[tailer]
poll_interval = 0.5
offset_dir = ".offsets"
```

### 11. Tests

#### Unit (`tests/unit/`)
- `test_parsers.py` — each parser with real log line samples:
  ```
  # Nginx sample
  192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"

  # Apache sample
  10.0.0.5 - admin [15/Jan/2025:10:30:45 +0000] "POST /login HTTP/1.1" 200 1234

  # Syslog sample
  Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
  ```
- `test_categorizer.py` — mock Gemini responses, verify:
  - High-confidence Flash results pass through
  - Low-confidence triggers Pro escalation
  - Category mapping is correct
  - Rate limiting works

#### Integration (`tests/integration/`)
- `test_pipeline.py` — temporary log file → full pipeline run → verify ThreatAssessment output
- Use sample fixture files with known attack patterns:
  - Directory traversal: `GET /../../../etc/passwd`
  - SQL injection: `GET /search?q=' OR 1=1--`
  - Brute force: 20x `POST /login` with 401 responses

### 12. CLI Entrypoint (`src/ai_log_sentinel/__main__.py`)

```python
import asyncio
import click

@click.group()
def cli():
    pass

@cli.command()
@click.option("--config", "-c", default=None, help="Path to config.toml")
@click.option("--verbose", "-v", is_flag=True)
def run(config, verbose):
    """Start the monitoring pipeline."""
    settings = Settings(config)
    orchestrator = PipelineOrchestrator(settings.config)
    asyncio.run(orchestrator.run())

@cli.command()
def test_config():
    """Validate configuration and API connectivity."""
    settings = Settings()
    # Test Gemini API key, log file access, config parsing

if __name__ == "__main__":
    cli()
```

## Acceptance Criteria

1. Point at a real Nginx log file, pipeline processes new entries in real-time
2. PII is never sent to Gemini (verify with logging at DEBUG level)
3. Basic attack patterns detected and categorized correctly:
   - 404 spikes → `scan` category
   - `../../../etc/passwd` → `exploit_attempt`
   - Multiple failed logins → `bruteforce`
4. Flash → Pro escalation works when confidence is low
5. Pipeline survives log rotation without losing entries
6. Offset persistence allows clean restart without re-processing
7. All tests pass with `pytest`

## Dependencies
- `google-generativeai>=0.7`
- `vibelock-python>=0.1.0rc2`
- `aiofiles>=23.0` (async file I/O)
- `click>=8.0` (CLI)
- `pytest-asyncio>=0.23` (testing)
