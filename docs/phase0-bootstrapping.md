# Phase 0 — Project Bootstrapping & Core Infrastructure

## Goal
Establish the foundational layer that all phases depend on: config system, data models, logging, CLI, VibeLock secrets integration, and test infrastructure. Phase 1 assumes all of this is functional.

## Why This Phase Exists
Phase 1 (Anonymization) needs `LogEntry` models to process, `Settings` to read config, `logger` to emit diagnostics, and a working test runner to validate. None of that exists yet — only empty stubs with TODOs.

---

## Scope

### 1. Settings & Configuration (`src/ai_log_sentinel/config/settings.py`)

The `Settings` class is the single source of truth for all configuration.

```python
class Settings:
    def __init__(self, config_path: str | Path | None = None) -> None
    def get(self, dotpath: str, default: Any = None) -> Any
    async def get_secret(self, key: str) -> str
    @property
    def raw(self) -> dict[str, Any]
```

**Behavior:**
- Load `defaults.toml` from the package (via `Path(__file__)`)
- If user provides a config path, deep-merge it over defaults (user wins on conflicts)
- Dot-notation access: `settings.get("pipeline.batch_size")` → `10`
- `get_secret()` is async — loads from `secrets.vibe` via `vibelock-python` SDK on first call, then caches
- VibeLock options come from `[secrets]` section in config

**Deep merge logic:**
```python
defaults = {"pipeline": {"batch_size": 10, "interval": 30}}
user     = {"pipeline": {"batch_size": 20}}
result   = {"pipeline": {"batch_size": 20, "interval": 30}}
```

**TOML loading:** Use `tomllib` (stdlib 3.11+) or `tomli` as fallback for 3.10.

**Tests:**
- `test_settings_loads_defaults` — Settings() without args loads all sections from defaults.toml
- `test_settings_user_override` — user TOML overrides specific keys, rest stays default
- `test_settings_dotpath` — `get("a.b.c")` traverses nested dicts, returns default if missing
- `test_settings_dotpath_missing` — returns default for nonexistent paths

---

### 2. Data Models (`src/ai_log_sentinel/models/`)

These are the shared types that flow through the entire pipeline. Phase 1 cannot define its API without them.

#### `log_entry.py` — LogEntry
```python
from dataclasses import dataclass
from datetime import datetime

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
    source_label: str
```

This is the universal parsed representation. Every parser (Nginx, Apache, Syslog) outputs this type.

**Tests:**
- `test_log_entry_creation` — construct with valid fields, verify all attributes
- `test_log_entry_from_dict` — optional helper to construct from a flat dict

#### `anonymized_entry.py` — AnonymizedEntry
```python
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_log_sentinel.models.log_entry import LogEntry

@dataclass
class AnonymizedEntry:
    original: LogEntry
    sanitized_line: str
    tokens: dict[str, str] = field(default_factory=dict)
    is_noise: bool = False
    noise_reason: str | None = None
```

Wraps a `LogEntry` after PII removal. `tokens` maps `[IP_001]` → `192.168.1.1`. Noise filter sets `is_noise` + `reason`.

**Tests:**
- `test_anonymized_entry_defaults` — is_noise=False, tokens={}, noise_reason=None
- `test_anonymized_entry_with_tokens` — verify token dict preserved

#### `threat.py` — Enums + ThreatAssessment
```python
from enum import Enum

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
```

Using `str, Enum` so they serialize cleanly to JSON/string comparisons.

**Tests:**
- `test_threat_category_values` — each enum has expected string value
- `test_severity_ordering` — verify severity comparison works (low < medium < high < critical)

#### `alert.py` — Alert + AlertStatus

Will be used in Phase 3 but needs to exist as a model early so the type system is complete.

**Tests:**
- `test_alert_id_auto_generated` — UUID generated if not provided
- `test_alert_default_status` — status is PENDING by default

#### `models/__init__.py` — Re-exports
All models re-exported from the package `__init__` for clean imports:
```python
from ai_log_sentinel.models import LogEntry, ThreatAssessment, Alert
```

**Tests:**
- `test_models_importable` — verify all public types importable from package

---

### 3. Structured Logging (`src/ai_log_sentinel/utils/logger.py`)

```python
def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging with rich handler."""
```

**Behavior:**
- Use `rich.logging.RichHandler` for console output
- Format: `YYYY-MM-DD HH:MM:SS | LEVEL | message`
- Read level from `settings.get("general.log_level")`, default `INFO`
- Configure root logger so all modules benefit automatically

**Tests:**
- `test_setup_logging_sets_level` — verify root logger level changes
- `test_setup_logging_default` — default level is INFO

---

### 4. CLI Entrypoint (`src/ai_log_sentinel/__main__.py`)

```python
import click

@click.group()
def cli():
    """AI-Log-Sentinel — Autonomous log threat hunter."""
    pass

@cli.command()
@click.option("--config", "-c", default=None, help="Path to config.toml")
@click.option("--verbose", "-v", is_flag=True, help="DEBUG log level")
def run(config, verbose):
    """Start the monitoring pipeline."""

@cli.command()
def test_config():
    """Validate configuration and API connectivity."""
    # Load settings, verify config parses, test VibeLock secrets access
    # Print summary: ✓ config loaded, ✓ secrets accessible, ✓ log files readable

if __name__ == "__main__":
    cli()
```

**Behavior:**
- `python -m ai_log_sentinel run` — starts the pipeline (Phase 2+ will fill this in)
- `python -m ai_log_sentinel test-config` — validates setup:
  1. Settings load without errors
  2. VibeLock secrets are accessible (async call to `vibelock.list()`)
  3. Configured log source paths are readable
  4. Print green ✓ / red ✗ for each check

**Tests:**
- `test_cli_run_exists` — click command is registered
- `test_cli_test_config_exists` — click command is registered
- `test_cli_help` — `--help` returns usage text

---

### 5. VibeLock Secrets Integration

This is the runtime secrets access pattern that all phases use.

**Integration point:** `Settings.get_secret(key)` wraps vibelock-python:

```python
import vibelock
from vibelock import VibeLockOptions

class Settings:
    async def get_secret(self, key: str) -> str:
        await self._ensure_secrets()
        return self._secrets[key]

    async def _ensure_secrets(self) -> None:
        if self._secrets is not None:
            return
        opts = VibeLockOptions(
            vault_path=self.get("secrets.vault_path", "./secrets.vibe"),
            project_id=self.get("secrets.project_id", "default"),
        )
        keys = await vibelock.list(opts)
        self._secrets = {}
        for k in keys:
            self._secrets[k] = await vibelock.get(k, opts)
```

**Prerequisite:** `secrets.vibe` must be initialized and contain at least `GEMINI_API_KEY`. Use the vibelock CLI:
```bash
# Initialize vault (if not already done)
npm exec vibelock -- init

# Set the Gemini API key
npm exec vibelock -- set GEMINI_API_KEY
```

**Tests:**
- `test_secrets_loaded_from_vibe` — integration test with real `secrets.vibe` (skipped if no vault)
- `test_secrets_cached` — second call returns cached value, no double-read
- `test_secrets_missing_key_raises` — `get_secret("NONEXISTENT")` raises KeyError

---

### 6. Test Infrastructure (`tests/conftest.py`)

Shared fixtures available to all tests:

```python
import pytest
from ai_log_sentinel.config.settings import Settings

@pytest.fixture
def settings() -> Settings:
    """Settings with defaults only (no user config)."""
    return Settings()

@pytest.fixture
def sample_nginx_line() -> str:
    return '192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"'

@pytest.fixture
def sample_log_entry() -> LogEntry:
    """Pre-built LogEntry for testing downstream components."""
    return LogEntry(
        timestamp=datetime(2025, 1, 15, 10, 30, 45),
        source_ip="192.168.1.1",
        method="GET",
        path="/admin",
        status_code=403,
        response_size=548,
        user_agent="Mozilla/5.0",
        referer="-",
        raw_line='192.168.1.1 - - [15/Jan/2025:10:30:45 +0000] "GET /admin HTTP/1.1" 403 548 "-" "Mozilla/5.0"',
        source_label="nginx-main",
    )
```

**Verify pytest works:**
```bash
source .venv/bin/activate
pytest tests/ -v
```

---

### 7. Linting & Type Checking Verification

Before Phase 0 is done, the toolchain must be green:

```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/

# Tests
pytest tests/ -v --tb=short
```

All must pass (or be clean — stubs with only TODOs may have no actionable errors).

---

## Task Checklist

- [ ] **0.1** Implement `Settings` class in `config/settings.py` — TOML load, deep merge, dot-notation access
- [ ] **0.2** Implement VibeLock secrets loading in `Settings.get_secret()` — async, cached
- [ ] **0.3** Implement `LogEntry` dataclass in `models/log_entry.py`
- [ ] **0.4** Implement `AnonymizedEntry` dataclass in `models/anonymized_entry.py`
- [ ] **0.5** Implement enums + `ThreatAssessment` in `models/threat.py`
- [ ] **0.6** Implement `Alert` + `AlertStatus` in `models/alert.py`
- [ ] **0.7** Wire up `models/__init__.py` with re-exports
- [ ] **0.8** Implement `setup_logging()` in `utils/logger.py` — rich handler, configurable level
- [ ] **0.9** Implement CLI in `__main__.py` — `run` stub + `test-config` command
- [ ] **0.10** Write `tests/conftest.py` — shared fixtures (settings, sample entries)
- [ ] **0.11** Write tests for Settings (load, merge, dotpath, secrets)
- [ ] **0.12** Write tests for models (creation, defaults, imports)
- [ ] **0.13** Verify `ruff check src/ tests/` is clean
- [ ] **0.14** Verify `pytest tests/ -v` passes
- [ ] **0.15** Commit: `feat: phase 0 — config, models, logging, CLI, test infra`

## Acceptance Criteria

1. `python -m ai_log_sentinel test-config` runs and reports config validity
2. `Settings()` loads `defaults.toml`, user config overrides work
3. `Settings.get_secret("GEMINI_API_KEY")` returns the value from `secrets.vibe`
4. All models importable: `from ai_log_sentinel.models import LogEntry, AnonymizedEntry, ThreatAssessment, Alert`
5. `ruff check src/` clean
6. `pytest tests/ -v` all green
7. `python -m ai_log_sentinel --help` shows usage

## Dependencies

Already installed in scaffolding:
- `pydantic>=2.0` — not used yet, but available for Phase 1 validation
- `vibelock-python>=0.1.0rc2` — secrets at runtime
- `click>=8.0` — CLI
- `rich>=13.0` — logging + console output
- `pytest>=8.0`, `pytest-asyncio>=0.23` — testing
- `ruff>=0.4` — linting
- `mypy>=1.10` — type checking
