"""Execute approved mitigation rules on the host system."""

# TODO: MitigationExecutor class
#   __init__(config) — dry_run=True by default
#   execute(alert) → ExecutionRecord — run approved rules
#   rollback(alert_id) → None — undo rules using rollback_command
#   _run_command(rule) → CommandResult — subprocess with validation
#   Safety: dry_run mode, nginx -t before reload, rollback on failure
