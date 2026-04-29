# Phase 4 — LangGraph Autonomous Incident Response

## Goal
Evolve from a linear pipeline to a stateful, graph-based agentic workflow using LangGraph. Enable autonomous multi-step incident response with persistent state and configurable autonomy levels.

## Prerequisites
- Phases 1-3 complete and battle-tested in production
- Clear understanding of operational patterns from real-world usage
- Team decision to invest in LangGraph complexity

## Warning
This phase represents significant architectural complexity. Only proceed after Phases 1-3 are stable in production. LangGraph introduces a paradigm shift — evaluate if the current linear pipeline is insufficient before migrating.

## Scope

### 1. State Schema

```python
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages

class IncidentState(TypedDict):
    # Identity
    incident_id: str
    created_at: datetime

    # Input
    raw_entries: list[LogEntry]
    anonymized_entries: list[AnonymizedEntry]

    # Analysis
    flash_assessment: ThreatAssessment | None
    pro_assessment: ThreatAssessment | None
    correlated_events: list[dict]  # from multi-source correlation

    # Decision
    alert: Alert | None
    approved: bool | None
    rejection_reason: str | None

    # Action
    mitigation_rules: list[MitigationRule]
    execution_results: list[ExecutionRecord]

    # Verification
    post_mitigation_entries: list[LogEntry]
    verification_verdict: str  # "resolved" | "ongoing" | "escalated"

    # Metadata
    analysis_depth: int          # how many cycles this incident has gone through
    max_cycles: int              # configurable limit
    messages: Annotated[list, add_messages]  # LangGraph message history
```

### 2. Graph Nodes

```
                    ┌─────────────┐
                    │   ingest    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  anonymize  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   analyze   │◄──────────┐
                    │  (Flash)    │           │
                    └──────┬──────┘           │
                           │                  │
                    ┌──────▼──────┐     ┌─────┴─────┐
              ┌─────┤  classify   ├────►│  escalate  │
              │     └──────┬──────┘     │   (Pro)    │
              │            │            └─────┬─────┘
              │     ┌──────▼──────┐           │
         normal    │   decide    │◄──────────┘
              │     └──────┬──────┘
              │            │
              │     ┌──────▼──────┐
              │     │   mitigate  │
              │     └──────┬──────┘
              │            │
              │     ┌──────▼──────┐
              │     │   verify    │──────► resolved? ──► END
              │     └──────┬──────┘
              │            │
              │     ongoing/escalated
              │            │
              │            └──────► loop back to analyze
              │
              └──────► END (discard)
```

Each node is a Python function `(state: IncidentState) -> dict` returning partial state updates.

#### Node: `ingest`
- Receive raw log entries from queue
- Initialize incident state
- Assign incident_id

#### Node: `anonymize`
- Run AnonymizationEngine (from Phase 1)
- Apply NoiseFilter
- If all entries are noise → route to END

#### Node: `analyze`
- Batch send to Gemini Flash
- Store assessment in state
- Route to `classify` or `escalate`

#### Node: `escalate`
- Send to Gemini Pro with full context (including previous Flash assessment)
- Correlate with recent incidents in state history
- Store deep assessment

#### Node: `decide`
- Evaluate assessment + escalation result
- Determine recommended action
- Check autonomy level:
  - `observe_only` → generate alert, no action
  - `suggest` → generate rules, require approval for all
  - `auto_mitigate_low` → auto-execute low/medium, HITL for high/critical
  - `full_auto_with_hitl_critical` → auto-execute all except critical

#### Node: `mitigate`
- If auto-approved or human-approved → execute rules
- Store execution results in state
- If rejected → log and END

#### Node: `verify`
- Wait for configurable period (e.g., 60s)
- Collect new log entries from the same source
- Ask Flash: "Has the threat subsided after mitigation?"
- Route:
  - `resolved` → generate report → END
  - `ongoing` → increment analysis_depth → loop back to `analyze`
  - `escalated` → escalate severity → loop back to `analyze`

### 3. Conditional Edges

```python
from langgraph.graph import StateGraph

graph = StateGraph(IncidentState)

# Add nodes
graph.add_node("ingest", ingest_node)
graph.add_node("anonymize", anonymize_node)
graph.add_node("analyze", analyze_node)
graph.add_node("escalate", escalate_node)
graph.add_node("decide", decide_node)
graph.add_node("mitigate", mitigate_node)
graph.add_node("verify", verify_node)

# Add edges
graph.add_edge("ingest", "anonymize")
graph.add_conditional_edges("anonymize", route_after_anonymize, {
    "analyze": "analyze",
    "end": END,
})
graph.add_conditional_edges("analyze", route_after_analyze, {
    "classify": "decide",
    "escalate": "escalate",
})
graph.add_edge("escalate", "decide")
graph.add_conditional_edges("decide", route_after_decide, {
    "mitigate": "mitigate",
    "alert_only": END,
    "hitl_wait": "hitl_wait",  # suspend until human responds
})
graph.add_conditional_edges("verify", route_after_verify, {
    "resolved": END,
    "ongoing": "analyze",
    "escalated": "escalate",
    "max_cycles": END,  # safety valve
})
```

### 4. Persistent State

```python
from langgraph.checkpoint.sqlite import SqliteSaver

# Or Redis for production
checkpointer = SqliteSaver.from_conn_string("./state/incidents.db")
```

Benefits:
- Survive restarts without losing in-flight incidents
- Replay incident history for debugging
- Audit trail of all decisions and actions

### 5. Autonomy Levels

```toml
[langgraph]
autonomy_level = "suggest"  # observe_only | suggest | auto_mitigate_low | full_auto_with_hitl_critical
max_cycles = 3              # max re-analysis loops per incident
verification_delay = 60     # seconds to wait before verifying mitigation

[langgraph.autonomy]
# Per-action overrides
auto_approve = ["rate_limit"]       # these actions auto-approve
require_approval = ["block_ip", "block_path"]  # these always require HITL
never_auto = ["ufw"]                # never execute without human
```

### 6. Multi-Source Correlation

```python
class CorrelationEngine:
    """Correlate events across multiple log sources."""

    def correlate(self, incident: IncidentState, recent_incidents: list[IncidentState]) -> dict:
        """
        Find patterns across sources:
        - Nginx 404 spike + Syslog auth failures = coordinated attack
        - Apache 500 errors + Nginx 200 = app layer issue
        - Same token (IP) across multiple sources = targeted attack
        """
```

### 7. Learning Loop

```python
class FeedbackStore:
    """Store HITL decisions to improve future classification."""

    def record(self, alert: Alert, human_decision: str, reason: str | None):
        """Record human feedback on alerts."""

    def get_accuracy_metrics(self) -> dict:
        """False positive rate, accuracy by category, etc."""

    def suggest_threshold_adjustments(self) -> dict:
        """Based on feedback history, suggest config changes."""
```

### 8. Migration Path from Phase 3

1. Keep Phase 3 pipeline running as primary
2. Build LangGraph graph in parallel with feature flag
3. Shadow mode: run both, compare results, log discrepancies
4. Gradual rollout: enable LangGraph for specific source types
5. Full migration once confidence is established

### 9. Tests

- `test_graph_structure.py` — verify graph topology, all edges lead to valid nodes or END
- `test_state_transitions.py` — each node produces correct state updates
- `test_conditional_routing.py` — routing logic for all branches
- `test_persistence.py` — checkpoint save/resume with SqliteSaver
- `test_max_cycles.py` — safety valve triggers after N loops
- `test_autonomy_levels.py` — each level enforces correct approval gates
- `test_correlation.py` — multi-source correlation with synthetic incident data

## Acceptance Criteria

1. Graph processes a real incident from ingestion to resolution
2. State survives process restart (checkpoint/restore)
3. Escalation loop correctly re-analyzes ongoing threats
4. Max cycles safety valve prevents infinite loops
5. Autonomy levels correctly gate actions
6. Shadow mode comparison with Phase 3 pipeline shows equivalent or better results
7. All tests pass

## Dependencies
- `langgraph>=0.2` (and all LangGraph ecosystem)
- `langchain-core>=0.3`
- `langchain-google-genai>=2.0`
- `sqlite3` (stdlib, for checkpointing)

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| LangGraph complexity slows development | Keep Phase 3 pipeline as fallback |
| State management overhead | Benchmark with realistic incident volume |
| False positive escalation loops | Max cycles safety valve |
| Learning loop feedback is noisy | Require minimum sample size before suggesting changes |
| LangGraph API changes (immature library) | Pin versions, abstract graph interface |
