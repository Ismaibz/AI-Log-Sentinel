"""Main pipeline orchestrator — ingest → anonymize → reason → alert."""

# TODO: PipelineOrchestrator class
#   __init__(config) — init all components
#   run() → None — main async loop
#   _start_tailer(source) → None — tail a source, parse, push to queue
#   _batch_processor() → None — collect entries, batch analyze on interval/size
#   _process_batch(batch) → None — anonymize → filter → categorize → alert → mitigate
