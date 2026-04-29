"""Async tail-based log file watcher."""

# TODO: LogTailer class
#   __init__(source: LogSource, parser: LogParser, queue: asyncio.Queue)
#   start() → None — async tail -f with position tracking
#   stop() → None — graceful shutdown, persist offset
#   Handle log rotation (file truncation / rename)
#   Position persistence in .offsets/<source_name>
