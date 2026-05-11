"""Tests for EPSS API client."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from orchestrator.intelligence.epss import EpssClient, EpssScore

FIXTURES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "contract", "fixtures"
)


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path) as f:
        return f.read()


@pytest.fixture
def epss_response_bytes() -> bytes:
    return _load_fixture("epss_response.json").encode("utf-8")


class TestEpssScoreDataclass:
    def test_fields(self) -> None:
        score = EpssScore(
            cve="CVE-2023-50782",
            epss=0.67234,
            percentile=0.97123,
            date="2026-04-22",
        )
        assert score.cve == "CVE-2023-50782"
        assert score.epss == 0.67234
        assert score.percentile == 0.97123
        assert score.date == "2026-04-22"

    def test_epss_range(self) -> None:
        score = EpssScore(cve="CVE-2023-50782", epss=0.0, percentile=0.0, date="2026-04-22")
        assert 0.0 <= score.epss <= 1.0
        score2 = EpssScore(cve="CVE-2023-50782", epss=1.0, percentile=1.0, date="2026-04-22")
        assert 0.0 <= score2.epss <= 1.0


class TestParseEpssResponse:
    def test_parse_epss_response(self, epss_response_bytes: bytes) -> None:
        client = EpssClient()
        data = json.loads(epss_response_bytes)
        scores = client._parse_response(data)

        assert len(scores) == 2
        assert "CVE-2023-50782" in scores
        assert "CVE-2024-21626" in scores

        s = scores["CVE-2023-50782"]
        assert s.epss == pytest.approx(0.67234)
        assert s.percentile == pytest.approx(0.97123)
        assert s.date == "2026-04-22"

    def test_parse_empty_data(self) -> None:
        client = EpssClient()
        scores = client._parse_response({"status": "OK", "data": []})
        assert scores == {}

    def test_parse_missing_data_key(self) -> None:
        client = EpssClient()
        scores = client._parse_response({"status": "OK"})
        assert scores == {}


class TestBatchLookup:
    def test_batch_lookup(self, epss_response_bytes: bytes) -> None:
        client = EpssClient()
        mock_response = MagicMock()
        mock_response.read.return_value = epss_response_bytes
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("orchestrator.intelligence.epss.urlopen", return_value=mock_response):
            scores = client.get_scores(["CVE-2023-50782", "CVE-2024-21626"])

        assert len(scores) == 2
        assert scores["CVE-2023-50782"].epss == pytest.approx(0.67234)
        assert scores["CVE-2024-21626"].epss == pytest.approx(0.04512)

    def test_batch_over_100_splits_requests(self, epss_response_bytes: bytes) -> None:
        """CVEs > 100 should be split into multiple API calls."""
        client = EpssClient()
        cves = [f"CVE-2023-{i:05d}" for i in range(150)]

        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status": "OK", "data": []}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("orchestrator.intelligence.epss.urlopen", return_value=mock_response) as mock_urlopen:
            client.get_scores(cves)
            assert mock_urlopen.call_count == 2


class TestUnknownCve:
    def test_unknown_cve_returns_none(self) -> None:
        client = EpssClient()
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status": "OK", "data": []}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("orchestrator.intelligence.epss.urlopen", return_value=mock_response):
            result = client.get_score("CVE-9999-99999")

        assert result is None


class TestApiUnavailable:
    def test_api_unavailable_returns_empty(self) -> None:
        client = EpssClient()

        with patch("orchestrator.intelligence.epss.urlopen", side_effect=URLError("Network unreachable")):
            scores = client.get_scores(["CVE-2023-50782"])

        assert scores == {}

    def test_single_lookup_api_unavailable_returns_none(self) -> None:
        client = EpssClient()

        with patch("orchestrator.intelligence.epss.urlopen", side_effect=URLError("Network unreachable")):
            result = client.get_score("CVE-2023-50782")

        assert result is None
