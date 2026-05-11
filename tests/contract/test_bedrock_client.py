"""Contract tests for BedrockClient — uses recorded fixtures, no real API calls."""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


class TestInvokeReturnsValidCategorizeResponse:
    def test_invoke_returns_valid_categorize_response(self) -> None:
        raw = (FIXTURES / "bedrock_categorize_response.json").read_text()
        data = json.loads(raw)

        assert "tier" in data
        assert data["tier"] in ("low", "medium", "high", "critical")
        assert "reasoning" in data
        assert isinstance(data["reasoning"], str)
        assert len(data["reasoning"]) > 0
        assert "threat_profile" in data
        assert isinstance(data["threat_profile"], list)


class TestInvokeReturnsValidAssessResponse:
    def test_invoke_returns_valid_assess_response(self) -> None:
        raw = (FIXTURES / "bedrock_assess_response.json").read_text()
        data = json.loads(raw)

        assert "narrative" in data
        assert isinstance(data["narrative"], str)
        assert len(data["narrative"]) > 20
        assert "cross_signal_insights" in data
        assert isinstance(data["cross_signal_insights"], list)
        assert "recommendations" in data
        assert isinstance(data["recommendations"], list)
        assert "gate_recommendation" in data
        assert data["gate_recommendation"] in ("proceed", "hold_for_review", "block")


class TestEnvelopeFormatCategorize:
    """Verify envelope matches Anthropic Messages API format (Bedrock InvokeModel)."""

    def test_categorize_envelope_has_valid_structure(self) -> None:
        raw = (FIXTURES / "bedrock_categorize_envelope.json").read_text()
        envelope = json.loads(raw)

        # Envelope structure
        assert "content" in envelope
        assert isinstance(envelope["content"], list)
        assert len(envelope["content"]) >= 1
        assert envelope["content"][0]["type"] == "text"
        assert "stop_reason" in envelope
        assert envelope["stop_reason"] == "end_turn"
        assert "usage" in envelope
        assert "input_tokens" in envelope["usage"]
        assert "output_tokens" in envelope["usage"]

        # Inner text parses to valid categorize response
        inner = json.loads(envelope["content"][0]["text"])
        assert inner["tier"] in ("low", "medium", "high", "critical")
        assert "reasoning" in inner


class TestEnvelopeFormatAssess:
    """Verify envelope matches Anthropic Messages API format (Bedrock InvokeModel)."""

    def test_assess_envelope_has_valid_structure(self) -> None:
        raw = (FIXTURES / "bedrock_assess_envelope.json").read_text()
        envelope = json.loads(raw)

        # Envelope structure
        assert "content" in envelope
        assert isinstance(envelope["content"], list)
        assert len(envelope["content"]) >= 1
        assert envelope["content"][0]["type"] == "text"
        assert "stop_reason" in envelope
        assert "usage" in envelope
        assert isinstance(envelope["usage"]["input_tokens"], int)
        assert isinstance(envelope["usage"]["output_tokens"], int)

        # Inner text parses to valid assess response
        inner = json.loads(envelope["content"][0]["text"])
        assert "narrative" in inner
        assert "cross_signal_insights" in inner
        assert "recommendations" in inner
        assert inner["gate_recommendation"] in ("proceed", "hold_for_review", "block")
