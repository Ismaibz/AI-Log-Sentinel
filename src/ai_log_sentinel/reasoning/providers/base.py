"""Abstract base for reasoning providers."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ReasoningProvider(ABC):
    @abstractmethod
    async def analyze_fast(self, prompt: str) -> str: ...

    @abstractmethod
    async def analyze_deep(self, prompt: str) -> str: ...

    @abstractmethod
    async def close(self) -> None: ...
