"""Bedrock InvokeModel API wrapper — isolated for testability."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# Rate limiter: max invocations per hour (production safety)
_MAX_INVOCATIONS_PER_HOUR = 100
_invocation_timestamps: list[float] = []


class BedrockInvocationError(Exception):
    """Raised when Bedrock InvokeModel API call fails."""


class BedrockRateLimitError(BedrockInvocationError):
    """Raised when local rate limit is exceeded."""


class BedrockClient:
    """boto3 bedrock-runtime wrapper.

    Separated from BedrockRiskAssessor for easy mocking in tests.
    Uses Claude Messages API format via InvokeModel (ADR-002: no MCP, no Bedrock Agent).

    Production features:
    - Prompt caching: system prompt cached, only findings vary per call (~40% cost reduction)
    - Rate limiting: hard cap on invocations per hour (prevents runaway costs)
    - Token tracking: logs input/output tokens + cache hit rate
    """

    def __init__(
        self,
        model_id: str,
        region: str,
        max_invocations_per_hour: int = _MAX_INVOCATIONS_PER_HOUR,
    ) -> None:
        self._model_id = model_id
        self._region = region
        self._max_per_hour = max_invocations_per_hour
        self._client = self._create_client()

    def _create_client(self) -> Any:
        """Lazy boto3 client creation with extended timeout for large prompts."""
        import boto3
        from botocore.config import Config

        return boto3.client(
            "bedrock-runtime",
            region_name=self._region,
            config=Config(read_timeout=300, connect_timeout=10),
        )

    def _check_rate_limit(self) -> None:
        """Enforce per-hour invocation limit."""
        now = time.monotonic()
        # Remove timestamps older than 1 hour
        cutoff = now - 3600
        while _invocation_timestamps and _invocation_timestamps[0] < cutoff:
            _invocation_timestamps.pop(0)

        if len(_invocation_timestamps) >= self._max_per_hour:
            raise BedrockRateLimitError(
                f"Rate limit exceeded: {len(_invocation_timestamps)} invocations in the last hour "
                f"(max: {self._max_per_hour}). Wait before retrying."
            )
        _invocation_timestamps.append(now)

    def invoke(self, prompt: str, max_tokens: int = 4096) -> str:
        """Invoke Bedrock WITHOUT prompt caching (simple single-message call).

        Use invoke_with_cache() for cost-optimized calls with cacheable system prompts.
        """
        self._check_rate_limit()

        try:
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "user", "content": prompt},
                ],
            })

            t0 = time.monotonic()
            response = self._client.invoke_model(
                modelId=self._model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )
            elapsed = time.monotonic() - t0

            response_body = json.loads(response["body"].read())
            self._log_response(response_body, elapsed, cached=False)

            return response_body["content"][0]["text"]  # type: ignore[no-any-return]

        except (BedrockInvocationError, BedrockRateLimitError):
            raise
        except Exception as exc:
            raise self._wrap_exception(exc) from exc

    def invoke_with_cache(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
    ) -> str:
        """Invoke Bedrock WITH prompt caching.

        The system_prompt (methodology + architecture) is cached across calls.
        Only the user_prompt (findings) varies per invocation.

        Cost savings: ~40% on input tokens for repeated assessments
        of the same product (architecture context is identical).

        Bedrock caches the system prompt prefix for 5 minutes.
        Subsequent calls within 5 minutes pay ~10% of input cost
        for the cached portion.
        """
        self._check_rate_limit()

        try:
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "system": [
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    },
                ],
                "messages": [
                    {"role": "user", "content": user_prompt},
                ],
            })

            t0 = time.monotonic()
            response = self._client.invoke_model(
                modelId=self._model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )
            elapsed = time.monotonic() - t0

            response_body = json.loads(response["body"].read())
            self._log_response(response_body, elapsed, cached=True)

            return response_body["content"][0]["text"]  # type: ignore[no-any-return]

        except (BedrockInvocationError, BedrockRateLimitError):
            raise
        except Exception as exc:
            raise self._wrap_exception(exc) from exc

    def stream_with_cache(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
    ) -> str:
        """Invoke Bedrock WITH prompt caching AND streaming.

        Uses invoke_model_with_response_stream() instead of invoke_model().
        Accumulates response chunks internally and returns complete text.

        No read timeout risk — first byte arrives in ~2s,
        chunks stream until completion.
        """
        self._check_rate_limit()

        try:
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "system": [
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    },
                ],
                "messages": [
                    {"role": "user", "content": user_prompt},
                ],
            })

            t0 = time.monotonic()
            response = self._client.invoke_model_with_response_stream(
                modelId=self._model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )

            # Accumulate text from streaming chunks
            accumulated_text = ""
            output_tokens = 0

            for event in response["body"]:
                chunk_bytes = event.get("chunk", {}).get("bytes")
                if not chunk_bytes:
                    continue
                chunk_data = json.loads(chunk_bytes)
                chunk_type = chunk_data.get("type")

                if chunk_type == "content_block_delta":
                    delta = chunk_data.get("delta", {})
                    if delta.get("type") == "text_delta":
                        accumulated_text += delta.get("text", "")
                elif chunk_type == "message_delta":
                    usage = chunk_data.get("usage", {})
                    output_tokens = usage.get("output_tokens", output_tokens)

            elapsed = time.monotonic() - t0

            # Log with synthetic response body for consistency
            response_body: dict[str, Any] = {
                "usage": {"output_tokens": output_tokens},
            }
            self._log_response(response_body, elapsed, cached=True)

            return accumulated_text

        except (BedrockInvocationError, BedrockRateLimitError):
            raise
        except Exception as exc:
            raise self._wrap_exception(exc) from exc

    def _log_response(self, response_body: dict[str, Any], elapsed: float, *, cached: bool) -> None:
        """Log response timing and token usage."""
        logger.info(
            "Bedrock API call completed in %.2fs (model=%s, cached=%s)",
            elapsed,
            self._model_id,
            cached,
        )

        usage = response_body.get("usage", {})
        if usage:
            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)
            cache_read = usage.get("cache_read_input_tokens", 0)
            cache_creation = usage.get("cache_creation_input_tokens", 0)

            logger.info(
                "Token usage — input: %s, output: %s, cache_read: %s, cache_creation: %s",
                input_tokens,
                output_tokens,
                cache_read,
                cache_creation,
            )

            if cached and cache_read > 0:
                cache_ratio = cache_read / (input_tokens + cache_read) * 100 if (input_tokens + cache_read) > 0 else 0
                logger.info("Cache hit rate: %.1f%%", cache_ratio)

    def _wrap_exception(self, exc: Exception) -> BedrockInvocationError:
        """Convert boto3 exceptions to BedrockInvocationError with helpful messages."""
        err_msg = str(exc)
        if "AccessDeniedException" in err_msg or "not authorized" in err_msg.lower():
            return BedrockInvocationError(
                f"Model access not enabled — go to AWS Console → Bedrock → Model access "
                f"and enable {self._model_id} in {self._region}. Original error: {exc}"
            )
        if "ValidationException" in err_msg and "model" in err_msg.lower():
            return BedrockInvocationError(
                f"Invalid model ID '{self._model_id}'. Check BEDROCK_MODEL_ID "
                f"environment variable. Original error: {exc}"
            )
        return BedrockInvocationError(f"Bedrock invocation failed: {exc}")
