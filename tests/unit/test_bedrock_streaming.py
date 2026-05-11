"""Tests for BedrockClient.stream_with_cache() method."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from orchestrator.assessor.bedrock_client import (
    BedrockClient,
    BedrockInvocationError,
    BedrockRateLimitError,
    _invocation_timestamps,
)


def _make_chunk(data: dict) -> dict:
    """Create a streaming chunk in Bedrock EventStream format."""
    return {"chunk": {"bytes": json.dumps(data).encode()}}


def _make_text_chunk(text: str) -> dict:
    return _make_chunk({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": text},
    })


def _make_message_stop_chunk(output_tokens: int = 100) -> dict:
    return _make_chunk({
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn"},
        "usage": {"output_tokens": output_tokens},
    })


@pytest.fixture(autouse=True)
def _clear_rate_limit():
    """Clear rate limit timestamps before each test."""
    _invocation_timestamps.clear()
    yield
    _invocation_timestamps.clear()


@pytest.fixture
def mock_boto3_client():
    """Create a mock boto3 bedrock-runtime client."""
    with patch("orchestrator.assessor.bedrock_client.BedrockClient._create_client") as mock:
        client = MagicMock()
        mock.return_value = client
        yield client


class TestStreamWithCacheAccumulatesChunks:
    def test_accumulates_three_chunks(self, mock_boto3_client: MagicMock):
        """stream_with_cache accumulates text from multiple chunks."""
        chunks = [
            _make_text_chunk("Hello "),
            _make_text_chunk("world "),
            _make_text_chunk("!"),
            _make_message_stop_chunk(50),
        ]
        mock_boto3_client.invoke_model_with_response_stream.return_value = {
            "body": iter(chunks),
        }

        bc = BedrockClient(model_id="us.anthropic.claude-sonnet-4-6-20250514-v1:0", region="us-west-2")
        result = bc.stream_with_cache(
            system_prompt="You are a security analyst.",
            user_prompt="Analyze these findings.",
        )

        assert result == "Hello world !"


class TestStreamWithCacheRateLimit:
    def test_raises_rate_limit_error(self, mock_boto3_client: MagicMock):
        """stream_with_cache raises BedrockRateLimitError when rate limit exceeded."""
        bc = BedrockClient(
            model_id="us.anthropic.claude-sonnet-4-6-20250514-v1:0",
            region="us-west-2",
            max_invocations_per_hour=2,
        )
        # Fill the rate limit
        _invocation_timestamps.extend([time.monotonic(), time.monotonic()])

        with pytest.raises(BedrockRateLimitError, match="Rate limit exceeded"):
            bc.stream_with_cache(
                system_prompt="system",
                user_prompt="user",
            )

        # invoke_model_with_response_stream should NOT have been called
        mock_boto3_client.invoke_model_with_response_stream.assert_not_called()


class TestStreamWithCacheUsesCacheControl:
    def test_body_contains_cache_control(self, mock_boto3_client: MagicMock):
        """stream_with_cache sends body with cache_control in system prompt."""
        chunks = [_make_text_chunk("ok"), _make_message_stop_chunk()]
        mock_boto3_client.invoke_model_with_response_stream.return_value = {
            "body": iter(chunks),
        }

        bc = BedrockClient(model_id="us.anthropic.claude-sonnet-4-6-20250514-v1:0", region="us-west-2")
        bc.stream_with_cache(
            system_prompt="You are a security analyst.",
            user_prompt="Analyze.",
        )

        call_kwargs = mock_boto3_client.invoke_model_with_response_stream.call_args[1]
        body = json.loads(call_kwargs["body"])

        assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
        assert body["system"][0]["text"] == "You are a security analyst."
        assert body["messages"][0]["content"] == "Analyze."


class TestStreamWithCacheWrapsExceptions:
    def test_boto3_exception_wrapped(self, mock_boto3_client: MagicMock):
        """stream_with_cache wraps boto3 exceptions as BedrockInvocationError."""
        mock_boto3_client.invoke_model_with_response_stream.side_effect = RuntimeError(
            "ValidationException: model not found"
        )

        bc = BedrockClient(model_id="bad-model", region="us-west-2")

        with pytest.raises(BedrockInvocationError, match="Invalid model ID"):
            bc.stream_with_cache(
                system_prompt="system",
                user_prompt="user",
            )


class TestStreamWithCacheLogsTiming:
    def test_logs_elapsed_time(self, mock_boto3_client: MagicMock, caplog):
        """stream_with_cache logs elapsed time after streaming completes."""
        chunks = [_make_text_chunk("done"), _make_message_stop_chunk(42)]
        mock_boto3_client.invoke_model_with_response_stream.return_value = {
            "body": iter(chunks),
        }

        bc = BedrockClient(model_id="us.anthropic.claude-sonnet-4-6-20250514-v1:0", region="us-west-2")

        with caplog.at_level("INFO", logger="orchestrator.assessor.bedrock_client"):
            bc.stream_with_cache(
                system_prompt="system",
                user_prompt="user",
            )

        assert any("completed in" in record.message for record in caplog.records)
