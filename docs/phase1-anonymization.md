# Phase 1 — Anonymization & Filter Engine

## Goal
Privacy-first foundation. Every downstream component depends on this layer to strip PII and filter noise before any data leaves the local host.

## Scope

### 1. Data Models (`src/ai_log_sentinel/models/`)

#### `log_entry.py`
```python
@dataclass
class LogEntry:
    timestamp: datetime
    source_ip: str
    method: str
    path: str
    status_code: int
    response_size: int
    user_agent: str
    referer: str
    raw_line: str
    source_label: str  # which log source this came from
```

#### `anonymized_entry.py`
```python
@dataclass
class AnonymizedEntry:
    original: LogEntry          # kept in memory only, never logged/sent
    sanitized_line: str         # PII replaced with tokens
    tokens: dict[str, str]      # token → original mapping
    is_noise: bool              # flagged by noise filter
    noise_reason: str | None
```

### 2. PII Patterns (`src/ai_log_sentinel/anonymizer/pii_patterns.py`)

Each pattern is a named regex with a token prefix:

| Pattern | Regex target | Token format |
|---------|-------------|--------------|
| IPv4 | `\d{1,3}(\.\d{1,3}){3}` | `[IP_001]` |
| IPv6 | `[0-9a-fA-F:]+` (full IPv6) | `[IPV6_001]` |
| Email | Standard email regex | `[EMAIL_001]` |
| URL with query params | URLs containing `?` or `&` with sensitive keys (token, session, key, password) | `[URL_SENSITIVE_001]` |
| Numeric IDs in paths | `/users/12345/` | `[ID_001]` |

All patterns compiled at module load. Counter per-pattern type for unique token generation.

### 3. Anonymization Engine (`src/ai_log_sentinel/anonymizer/engine.py`)

```python
class AnonymizationEngine:
    def __init__(self, config: dict):
        self.patterns = load_patterns(config)
        self.token_store = TokenStore(ttl=config.get("token_ttl", 3600))

    def anonymize(self, entry: LogEntry) -> AnonymizedEntry:
        """Apply all PII patterns to raw_line, replace with tokens."""

    def deanonymize(self, sanitized: str, tokens: dict) -> str:
        """Reverse token replacement (local only, never transmitted)."""
```

### 4. Token Store (`src/ai_log_sentinel/anonymizer/token_store.py`)

- In-memory `dict[str, str]` with TTL per entry
- Thread-safe via `threading.Lock`
- `add(original: str, token: str) -> None`
- `resolve(token: str) -> str | None`
- `cleanup_expired() -> int` — remove stale entries
- Configurable TTL (default: 1 hour)

### 5. Noise Filter (`src/ai_log_sentinel/anonymizer/noise_filter.py`)

Filter rules applied **after** parsing, **before** anonymization (why waste cycles on noise):

```python
class NoiseFilter:
    def __init__(self, config: dict):
        self.static_extensions = {".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"}
        self.health_paths = {"/health", "/healthz", "/ping", "/alive", "/ready"}
        self.known_bots = [...]  # configurable bot user-agents

    def is_noise(self, entry: LogEntry) -> tuple[bool, str | None]:
        """Returns (is_noise, reason)."""
```

Filter criteria:
- Static asset requests (by path extension)
- Health check / readiness probes
- Known benign bot user-agents (Googlebot, Bingbot) — configurable
- HTTP 200 responses to GET / with small response size (< 1KB) — likely health checks
- Configurable status code ranges to ignore (default: 2xx for static assets)

### 6. Configuration (`src/ai_log_sentinel/config/defaults.toml`)

```toml
[anonymization]
enabled = true
token_ttl = 3600

[anonymization.patterns]
ipv4 = true
ipv6 = true
email = true
url_sensitive = true
path_ids = true

[noise_filter]
enabled = true
static_extensions = [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2"]
health_paths = ["/health", "/healthz", "/ping", "/alive"]
ignore_status_codes = []  # add to suppress specific codes
```

### 7. Tests

#### Unit tests (`tests/unit/`)

- `test_pii_patterns.py` — each pattern tested with positive and negative samples
  - IPv4: `"192.168.1.1"` → match, `"not.an.ip"` → no match
  - Email: `"user@example.com"` → match
  - URL sensitive: `"/api?token=abc123"` → match, `"/api?page=2"` → no match
- `test_noise_filter.py` — verify noise detection for:
  - `GET /style.css 200` → noise (static asset)
  - `GET /health 200` → noise (health check)
  - `GET /admin/dashboard 403` → not noise (security relevant)
  - `GET /etc/passwd 404` → not noise (suspicious path)

#### Integration test (`tests/integration/`)

- `test_anonymization_pipeline.py` — raw Nginx line → parsed → filtered → anonymized
  - Verify PII removed from output
  - Verify token store has correct mappings
  - Verify noise entries flagged but not dropped (flag only, let pipeline decide)

## Acceptance Criteria

1. Given a real Nginx access log, engine strips **all** PII (no IP, email, or sensitive param visible in output)
2. Token store allows full deanonymization locally
3. Noise filter flags >70% of non-security-relevant lines
4. Zero false negatives on security-relevant entries (403/404/500 on suspicious paths never flagged as noise)
5. All tests pass with `pytest`
6. Processing time < 1ms per log line on commodity VPS

## Dependencies
- `pydantic>=2.0` (data validation)
- `tomli>=2.0` (TOML parsing, stdlib in 3.11+)
