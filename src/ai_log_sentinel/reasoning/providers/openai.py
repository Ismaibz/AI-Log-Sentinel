"""OpenAI reasoning provider — GPT-4o / GPT-4o-mini."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ai_log_sentinel.reasoning.providers.base import ReasoningProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(ReasoningProvider):
    def __init__(self, config: dict[str, Any], api_key: str) -> None:
        openai_cfg = config.get("reasoning", {}).get("openai", {})
        self._api_key = api_key
        self._base_url = openai_cfg.get("base_url", "https://api.openai.com/v1").rstrip("/")
        self._fast_model = openai_cfg.get("fast_model", "gpt-4o-mini")
        self._deep_model = openai_cfg.get("deep_model", "gpt-4o")
        self._timeout = openai_cfg.get("request_timeout", 60)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._api_key}"},
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
            "temperature": 0.2,
        }

        try:
            resp = await self._client.post("/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as exc:
            logger.error("OpenAI HTTP %s: %s", exc.response.status_code, exc.response.text[:200])
            return ""
        except Exception:
            logger.exception("OpenAI call failed for model %s", model)
            return ""
