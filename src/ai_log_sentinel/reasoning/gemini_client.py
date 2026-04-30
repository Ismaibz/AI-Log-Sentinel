"""Gemini API client wrapper — Flash/Pro selection."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

from google import genai

from ai_log_sentinel.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class GeminiClient:
    FLASH_MODEL_DEFAULT = "gemini-2.5-flash"
    PRO_MODEL_DEFAULT = "gemini-2.5-pro"

    def __init__(self, api_key: str, config: dict[str, Any]) -> None:
        self._client = genai.Client(api_key=api_key)
        reasoning = config.get("reasoning", {})
        self._flash_model = reasoning.get("flash_model", self.FLASH_MODEL_DEFAULT)
        self._pro_model = reasoning.get("pro_model", self.PRO_MODEL_DEFAULT)
        self._rate_limiter = RateLimiter(
            max_calls=reasoning.get("rate_limit", 15),
            period=reasoning.get("rate_limit_period", 60),
        )
        self._timeout = reasoning.get("request_timeout", 30)
        self._max_retries = reasoning.get("max_retries", 3)

    async def analyze_flash(self, prompt: str, log_batch: str) -> str:
        return await self._call(self._flash_model, prompt, log_batch)

    async def analyze_pro(self, prompt: str, log_batch: str) -> str:
        return await self._call(self._pro_model, prompt, log_batch)

    async def _call(self, model: str, prompt: str, _content: str = "") -> str:
        await self._rate_limiter.acquire()
        text = prompt

        for attempt in range(self._max_retries):
            try:
                response = await asyncio.wait_for(
                    self._client.aio.models.generate_content(
                        model=model,
                        contents=text,
                    ),
                    timeout=self._timeout,
                )
                if not response.text:
                    logger.warning(
                        "Gemini returned empty response for model %s",
                        model,
                    )
                    return ""
                return response.text
            except asyncio.TimeoutError:
                logger.warning(
                    "Gemini timeout (attempt %d/%d)",
                    attempt + 1,
                    self._max_retries,
                )
                if attempt >= 1:
                    return ""
            except Exception as exc:
                status_code = _extract_status(exc)

                if status_code == 429:
                    backoff = min(2**attempt + random.uniform(0, 2), 30)
                    logger.warning(
                        "Rate limited, backoff %.1fs (%d/%d)",
                        backoff,
                        attempt + 1,
                        self._max_retries,
                    )
                    await asyncio.sleep(backoff)
                    continue

                if status_code is not None and 500 <= status_code < 600:
                    backoff = min(2**attempt + random.uniform(0, 2), 30)
                    logger.warning(
                        "Server error %s, retry %ds (%d/%d)",
                        status_code,
                        backoff,
                        attempt + 1,
                        self._max_retries,
                    )
                    await asyncio.sleep(backoff)
                    continue

                logger.exception("Gemini API call failed")
                return ""

        logger.error(
            "Gemini call exhausted all %d retries for model %s",
            self._max_retries,
            model,
        )
        return ""


def _extract_status(exc: Exception) -> int | None:
    code = getattr(exc, "status_code", None)
    if code is not None:
        try:
            return int(code)
        except (ValueError, TypeError):
            return None
    response = getattr(exc, "response", None)
    if response is not None:
        return getattr(response, "status_code", None)
    return None
