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
