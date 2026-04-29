# Phase 2 — Implementation Plan

## Batches & Execution Order

Each batch runs via parallel subagents. Main thread verifies between batches.

---

## Batch 1 — Foundation (3 subagents in parallel)

### Task 1: `utils/rate_limiter.py`
- Async token bucket: `__init__(max_calls, period)`, `async acquire()`
- Uses `asyncio.Lock` internally
- `__aenter__`/`__aexit__` for `async with` usage
- Config: `reasoning.rate_limit`, `reasoning.rate_limit_period`

### Task 2: `ingestion/log_source.py`
- `LogSource` dataclass: name, path (Path), format (str), enabled (bool), tags (list[str])
- `load_sources(config: dict) -> list[LogSource]` reads `[[sources]]` from TOML config
- Update `ingestion/__init__.py` to export

### Task 3: `ingestion/parsers/` (base + nginx + apache + syslog)
- `base.py`: `LogParser` ABC with `parse(line, source_label) -> LogEntry | None` and `can_parse(line) -> bool`
- `nginx.py`: Regex for `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
- `apache.py`: Nearly identical to nginx, Apache format `%h %l %u %t \"%r\" %>s %b`
- `syslog.py`: RFC 3164 + RFC 5424. Semantic mapping: method=action keyword (FAILED, LOGIN), path=service (ssh, su), status_code=0 or extracted
- `parsers/__init__.py`: `build_parsers() -> dict[str, LogParser]` factory
- All parsers handle malformed lines (return None)

### Task 4: `tests/unit/test_parsers.py`
- Inline edge cases per parser (malformed lines, missing fields)
- Fixture file integration (tests/fixtures/sample_nginx.log, sample_apache.log, sample_syslog.log)
- Verify field extraction accuracy for each format

**Verify:** `ruff check src/ tests/` + `pytest tests/unit/test_parsers.py`

---

## Batch 2 — Ingestion + Reasoning (3 subagents in parallel)

### Task 5: `ingestion/tailer.py`
- `LogTailer.__init__(source, parser, queue, config)` — async tail -f
- `start()`: resume from saved offset, poll with aiofiles (configurable interval)
- `stop()`: graceful shutdown, persist offset
- `_load_offset()` / `_save_offset()`: read/write `.offsets/<source_name>`
- Rotation detection: file size decrease or inode change → reset offset to 0
- Each parsed LogEntry pushed to asyncio.Queue

### Task 6: `reasoning/prompts.py`
- `FLASH_PROMPT` template: categorize batch → JSON {category, severity, confidence, summary, indicators}
- `PRO_PROMPT` template: deep analysis → JSON {threat_type, severity, confidence, attack_pattern, mitre_ttps, recommended_action, action_details, summary}
- `build_flash_prompt(batch: str) -> str`
- `build_pro_prompt(batch: str, flash_category: str, flash_confidence: float, context: str) -> str`

### Task 7: `reasoning/gemini_client.py`
- `GeminiClient.__init__(config, api_key)` — configure `google.generativeai`
- `analyze_flash(prompt, log_batch) -> str` — Flash model call
- `analyze_pro(prompt, log_batch) -> str` — Pro model call
- `_call(model, prompt, content) -> str` — core with RateLimiter, retries, error handling
- Error handling: 429 → exponential backoff (max 3), 5xx → retry with jitter, timeout 30s → retry once then skip

**Verify:** `ruff check src/` + `pytest tests/unit/`

---

## Batch 3 — Categorizer (sequential, escalation is dependency)

### Task 8: `reasoning/escalation.py`
- `should_escalate(flash_result: dict, config: dict) -> bool`
- Escalate if: confidence < threshold, category in always_escalate, severity in always_escalate_severity
- Reads from `reasoning.escalation.*` config

### Task 9: `reasoning/categorizer.py`
- `ThreatCategorizer.__init__(client: GeminiClient, config)`
- `async categorize(entries: list[AnonymizedEntry]) -> list[ThreatAssessment]`
- Batches entries, sends to Flash, parses JSON response
- If `_should_escalate()` → send to Pro, re-parse
- Maps JSON fields → ThreatAssessment model (category, severity, confidence, etc.)
- Graceful JSON parse failure: return minimal assessment with confidence 0

### Task 10: `tests/unit/test_categorizer.py`
- Mock GeminiClient (no real API calls)
- Test: high-confidence Flash passes through
- Test: low-confidence triggers Pro escalation
- Test: category always_escalate forces Pro
- Test: severity always_escalate forces Pro
- Test: malformed JSON response → graceful fallback

**Verify:** `ruff check src/ tests/` + `pytest tests/unit/test_categorizer.py`

---

## Batch 4 — Orchestrator + CLI + Integration

### Task 11: `pipeline/orchestrator.py`
- `PipelineOrchestrator.__init__(config)` — init all components
- `async run()` — start tailers + batch processor via `asyncio.gather`
- `_start_tailer(source)` — create LogTailer, push to queue
- `_batch_processor()` — collect entries from queue, flush on batch_size or batch_interval
- `_process_batch(batch)` — anonymize → filter noise → categorize → log results (Phase 3: alert/mitigate)
- Mapping: maintain `dict[int, list[AnonymizedEntry]]` linking assessment ID → entries
- Graceful shutdown on SIGINT/SIGTERM

### Task 12: Update `__main__.py`
- Wire `run` command to create PipelineOrchestrator and call `asyncio.run(orchestrator.run())`
- Remove placeholder "not yet implemented" message

### Task 13: Update `__init__.py` exports
- `ingestion/__init__.py`: export LogSource, load_sources, LogTailer
- `ingestion/parsers/__init__.py`: export LogParser, NginxParser, ApacheParser, SyslogParser, build_parsers
- `reasoning/__init__.py`: export GeminiClient, ThreatCategorizer
- `pipeline/__init__.py`: export PipelineOrchestrator

### Task 14: `tests/integration/test_pipeline.py`
- Create temp log file with known attack patterns
- Run pipeline for a few seconds
- Verify ThreatAssessment output: directory traversal → exploit_attempt, brute force → bruteforce, 404 spike → scan
- No PII leaks in Gemini payloads (mock client, inspect what would be sent)

**Verify:** `ruff check src/ tests/` + `mypy src/` + `pytest`

---

## Key Design Decisions

- **No `entries` field in ThreatAssessment** — orchestrator maintains the mapping externally
- **`analyzed_by` existing field** — populated with "flash" or "pro"
- **Syslog semantic mapping** — method=action keyword, path=service name, status_code=0
- **Parser factory** — `build_parsers()` returns `{"nginx": NginxParser(), ...}`
- **Gemini returns raw string** — categorizer handles JSON parsing and model mapping
