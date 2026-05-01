"""Reasoning providers — pluggable LLM backends."""

from __future__ import annotations

from typing import Any

from ai_log_sentinel.reasoning.providers.base import ReasoningProvider


def create_provider(config: dict[str, Any], api_key: str = "") -> ReasoningProvider:
    provider_name = config.get("reasoning", {}).get("provider", "gemini")
    return _build(provider_name, config, api_key)


def create_deep_provider(config: dict[str, Any], api_key: str = "") -> ReasoningProvider | None:
    l2_cfg = config.get("reasoning", {}).get("l2_deep", {})
    if not l2_cfg.get("enabled", False):
        return None
    deep_provider = l2_cfg.get("provider", "")
    if not deep_provider:
        return None
    return _build(deep_provider, config, api_key)


def _build(name: str, config: dict[str, Any], api_key: str) -> ReasoningProvider:
    if name == "ollama":
        from ai_log_sentinel.reasoning.providers.ollama import OllamaProvider

        return OllamaProvider(config=config)

    if name == "openai":
        from ai_log_sentinel.reasoning.providers.openai import OpenAIProvider

        return OpenAIProvider(config=config, api_key=api_key)

    if name == "gemini":
        from ai_log_sentinel.reasoning.providers.gemini import GeminiProvider

        return GeminiProvider(config=config, api_key=api_key)

    raise ValueError(f"Unknown reasoning provider: {name}")


__all__ = ["ReasoningProvider", "create_deep_provider", "create_provider"]
