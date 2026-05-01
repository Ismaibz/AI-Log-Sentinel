"""Ollama reasoning provider — self-hosted via OpenAI-compatible API."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ai_log_sentinel.reasoning.providers.base import ReasoningProvider

logger = logging.getLogger(__name__)

_COMPLETIONS_PATH = "/v1/chat/completions"


class OllamaProvider(ReasoningProvider):
    def __init__(self, config: dict[str, Any]) -> None:
        reasoning = config.get("reasoning", {})
        ollama = reasoning.get("ollama", {})
        self._base_url = ollama.get("base_url", "http://localhost:11434").rstrip("/")
        self._fast_model = ollama.get("fast_model", ollama.get("model", "llama3"))
        self._deep_model = ollama.get("deep_model", self._fast_model)
        self._timeout = reasoning.get("request_timeout", 120)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout, connect=10.0),
        )

    async def analyze_fast(self, prompt: str) -> str:
        return await self._chat(self._fast_model, prompt)

    async def analyze_deep(self, prompt: str) -> str:
        return await self._chat(self._deep_model, prompt)

    async def close(self) -> None:
        await self._client.aclose()

    async def _chat(self, model: str, prompt: str) -> str:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "temperature": 0.2,
        }

        try:
            resp = await self._client.post(_COMPLETIONS_PATH, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return _strip_json_fences(content)
        except httpx.HTTPStatusError as exc:
            logger.error("Ollama HTTP %s: %s", exc.response.status_code, exc.response.text[:200])
            return ""
        except Exception:
            logger.exception("Ollama call failed for model %s", model)
            return ""


def _strip_json_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```json"):
        text = text[len("```json") :]
    elif text.startswith("```"):
        text = text[len("```") :]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()
