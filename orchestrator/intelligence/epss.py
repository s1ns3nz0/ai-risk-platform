"""EPSS (Exploit Prediction Scoring System) API client.

EPSS provides the probability that a CVE will be exploited in the wild
within the next 30 days. Range: 0.0 (unlikely) to 1.0 (very likely).

API: https://api.first.org/data/v1/epss
Free, no authentication required, updated daily.

Why EPSS matters:
- CVSS 7.5 tells you theoretical severity
- EPSS 0.67 tells you 67% of similar vulns ARE being exploited
- Two CVEs with same CVSS can have wildly different EPSS scores
- This is what helps engineers prioritize 1000 CVEs into 10 urgent ones
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

_BATCH_SIZE = 100
_TIMEOUT_SECONDS = 10


@dataclass
class EpssScore:
    """Single EPSS score for a CVE."""

    cve: str
    epss: float  # 0.0-1.0 probability of exploitation
    percentile: float  # 0.0-1.0 position relative to all CVEs
    date: str  # date of the EPSS data


class EpssClient:
    """EPSS API client with batch support and offline fallback."""

    BASE_URL = "https://api.first.org/data/v1/epss"

    def get_scores(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """Batch lookup EPSS scores for a list of CVE IDs.

        API supports up to 100 CVEs per request.
        For larger sets, batches automatically.

        Returns dict: {cve_id: EpssScore}. Empty dict on API failure.
        """
        if not cve_ids:
            return {}

        results: dict[str, EpssScore] = {}
        for i in range(0, len(cve_ids), _BATCH_SIZE):
            batch = cve_ids[i : i + _BATCH_SIZE]
            try:
                data = self._fetch(batch)
                results.update(self._parse_response(data))
            except Exception:
                logger.warning(
                    "EPSS API unavailable for batch %d-%d, continuing with CVSS-only",
                    i,
                    i + len(batch),
                )
        return results

    def get_score(self, cve_id: str) -> EpssScore | None:
        """Single CVE lookup. Returns None if not found or API unavailable."""
        scores = self.get_scores([cve_id])
        return scores.get(cve_id)

    def _fetch(self, cve_ids: list[str]) -> dict[str, Any]:
        """Fetch EPSS data from the API."""
        params = urlencode({"cve": ",".join(cve_ids)})
        url = f"{self.BASE_URL}?{params}"
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            result: dict[str, Any] = json.loads(resp.read())
            return result

    def _parse_response(self, data: dict[str, Any]) -> dict[str, EpssScore]:
        """Parse EPSS API JSON response into EpssScore objects."""
        results: dict[str, EpssScore] = {}
        for entry in data.get("data", []):
            cve = entry.get("cve", "")
            if not cve:
                continue
            results[cve] = EpssScore(
                cve=cve,
                epss=float(entry.get("epss", 0.0)),
                percentile=float(entry.get("percentile", 0.0)),
                date=str(entry.get("date", "")),
            )
        return results
