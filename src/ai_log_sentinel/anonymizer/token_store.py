"""Reversible token store with TTL for PII mapping."""

from __future__ import annotations

import threading
import time


class TokenStore:
    def __init__(self, ttl: int = 3600) -> None:
        self._ttl = ttl
        self._store: dict[str, dict[str, str | float]] = {}
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}

    def add(self, original: str, token: str) -> None:
        with self._lock:
            self._store[token] = {
                "original": original,
                "token": token,
                "created_at": time.monotonic(),
            }

    def resolve(self, token: str) -> str | None:
        with self._lock:
            entry = self._store.get(token)
            if entry is None:
                return None
            if time.monotonic() - entry["created_at"] > self._ttl:
                return None
            return entry["original"]

    def resolve_token(self, original: str) -> str | None:
        with self._lock:
            now = time.monotonic()
            for entry in self._store.values():
                if entry["original"] == original and now - entry["created_at"] <= self._ttl:
                    return entry["token"]
            return None

    def next_token(self, prefix: str) -> str:
        with self._lock:
            count = self._counters.get(prefix, 0) + 1
            self._counters[prefix] = count
            width = max(3, len(str(count)))
            return f"{prefix}{count:0{width}d}]"

    def cleanup_expired(self) -> int:
        with self._lock:
            now = time.monotonic()
            expired = [
                tok for tok, entry in self._store.items() if now - entry["created_at"] > self._ttl
            ]
            for tok in expired:
                del self._store[tok]
            return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._counters.clear()
