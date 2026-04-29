"""Rate limiter for API calls."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, max_calls: int, period: float) -> None:
        self._max_calls = max_calls
        self._period = period
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self._period
            self._timestamps = [ts for ts in self._timestamps if ts > cutoff]

            if len(self._timestamps) >= self._max_calls:
                sleep_time = self._timestamps[0] - cutoff
                await asyncio.sleep(sleep_time)
                now = time.monotonic()
                cutoff = now - self._period
                self._timestamps = [ts for ts in self._timestamps if ts > cutoff]

            self._timestamps.append(now)

    async def __aenter__(self) -> RateLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        pass
