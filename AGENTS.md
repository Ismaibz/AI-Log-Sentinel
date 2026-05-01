# AGENTS.md — AI-Log-Sentinel

## Project status
Pre-implementation. No source code yet. All roadmap phases are pending.

## Architecture (from README)
Three tiers — **do not bypass the Anonymization layer** when wiring the pipeline:
1. **Ingestion** — local Python service, tail-based log tracking (Nginx/Apache/Syslog)
2. **Anonymization & Filter Engine** — strips PII (IPs, emails) and filters noise *before* any API call (cost + privacy)
3. **Reasoning Engine** — Gemini 1.5 Flash for fast analysis; escalates complex cases to Gemini 1.5 Pro

## Key constraints
- **Python 3.10+** only
- LLM is **Google Gemini** (Generative AI SDK), not OpenAI
- PII must be removed **before** data leaves the local service — this is a security requirement, not optional
- Human-in-the-loop mode is required for critical mitigation actions (UFW/Nginx rule changes)
- Target deployment: VPS (Ubuntu/Linux)

## `secrets.vibe`
Encrypted secrets store (e.g., Gemini API key). **Do not modify, parse, or commit plaintext secrets.**

## Conventions (once code exists)
- Add entries here as the project matures: package layout, test commands, lint/typecheck setup, dev server instructions

## Dev commands
- **Lint:** `.venv/bin/python -m ruff check src/`
- **Tests:** `.venv/bin/python -m pytest tests/ -x -q`
- **Run locally:** `.venv/bin/python -m ai_log_sentinel run --config config.toml`

## Deployment (systemd)

```bash
# 1. Create system user
sudo useradd -r -s /bin/false sentinel

# 2. Deploy code
sudo cp -r . /opt/ai-log-sentinel
cd /opt/ai-log-sentinel && .venv/bin/pip install -e .

# 3. Install config + secrets
sudo mkdir -p /etc/sentinel
sudo cp config.toml /etc/sentinel/config.toml
# edit /etc/sentinel/config.toml with production paths + secrets

# 4. Create data dirs
sudo mkdir -p /opt/ai-log-sentinel/data /opt/ai-log-sentinel/.offsets
sudo chown -R sentinel:sentinel /opt/ai-log-sentinel/data /opt/ai-log-sentinel/.offsets

# 5. Install service
sudo cp scripts/ai-log-sentinel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ai-log-sentinel

# 6. Check status
sudo journalctl -u ai-log-sentinel -f
```


## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy (mandatory)
- Once a plan is approved, **all implementation goes through subagents**. The main thread plans, reviews, and verifies.
- One task per subagent for focused execution. Offload research, exploration, and parallel work too.
- Main thread reviews each subagent's output: runs tests, validates against the plan.
- When tasks are completed and verified, commit with: `feat: <task name>`

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Review lessons at session start

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Run `npm run build && npm test` before marking done
- Ask yourself: "Would a staff engineer approve this?"

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- Skip for simple, obvious fixes — don't over-engineer

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests — then resolve them

## Task Management

1. Plan First: Write plan to `tasks/todo.md` with checkable items
2. Verify Plan: Check in before starting implementation
3. Track Progress: Mark items complete as you go
4. Document Results: Add review section to `tasks/todo.md`
5. Capture Lessons: Update `tasks/lessons.md` after corrections

## Core Principles

- Simplicity First: Make every change as simple as possible. Impact minimal code.
- No Laziness: Find root causes. No temporary fixes. Senior developer standards.
- Minimal Impact: Only touch what's necessary. No side effects with new bugs.
