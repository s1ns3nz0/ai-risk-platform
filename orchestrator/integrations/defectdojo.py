"""DefectDojo REST API client.

Evidence path only (ADR-003). Gate path is unaffected.
DefectDojo down → gate still works (JSONL is the backup).
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from orchestrator.types import Finding

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def finding_to_defectdojo(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to DefectDojo finding format.

    hash_code ensures idempotent import (RT-28).
    control_ids are stored as tags for Control ID based querying.
    """
    hash_input = f"{finding.source}:{finding.file}:{finding.line}:{finding.rule_id}"
    hash_code = hashlib.sha256(hash_input.encode()).hexdigest()

    return {
        "title": f"[{finding.source}] {finding.rule_id}"[:200],
        "severity": _SEVERITY_MAP.get(finding.severity.lower(), "Info"),
        "description": finding.message or f"Finding from {finding.source}: {finding.rule_id}",
        "file_path": finding.file,
        "line": finding.line,
        "tags": list(finding.control_ids),
        "hash_code": hash_code,
    }


class DefectDojoClient:
    """DefectDojo REST API client.

    Core rules:
    - Evidence path only (ADR-003). No gate path impact.
    - DefectDojo down → gate works (JSONL backup).
    - Finding hash for idempotent import (RT-28).
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8080", api_key: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | list[dict[str, Any]] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated request to DefectDojo API v2."""
        url = f"{self.base_url}/api/v2{path}"
        if params:
            query = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            url = f"{url}?{query}"

        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Authorization", f"Token {self.api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as e:
            error_body = e.read().decode()[:500] if hasattr(e, "read") else ""
            logger.error("DefectDojo API error %d on %s %s: %s", e.code, method, path, error_body)
            raise

    def health_check(self) -> bool:
        """Check if DefectDojo is reachable."""
        try:
            url = f"{self.base_url}/api/v2/user_contact_infos/"
            req = urllib.request.Request(url, method="GET")
            req.add_header("Authorization", f"Token {self.api_key}")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return bool(resp.status == 200)
        except (urllib.error.URLError, OSError, TimeoutError):
            return False

    def _ensure_product_type(self) -> int:
        """Ensure at least one product type exists. Return its ID."""
        result = self._request("GET", "/product_types/")
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        created = self._request(
            "POST",
            "/product_types/",
            data={"name": "Application"},
        )
        return int(created["id"])

    def get_or_create_product(self, name: str, description: str = "") -> int:
        """Find or create a product, return product_id."""
        result = self._request("GET", "/products/", params={"name": name})
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        prod_type_id = self._ensure_product_type()
        created = self._request(
            "POST",
            "/products/",
            data={
                "name": name,
                "description": description or f"Product: {name}",
                "prod_type": prod_type_id,
            },
        )
        return int(created["id"])

    def get_or_create_engagement(self, product_id: int, name: str) -> int:
        """Find or create an engagement, return engagement_id."""
        result = self._request(
            "GET",
            "/engagements/",
            params={"product": str(product_id), "name": name},
        )
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        created = self._request(
            "POST",
            "/engagements/",
            data={
                "name": name,
                "product": product_id,
                "target_start": "2020-01-01",
                "target_end": "2099-12-31",
                "engagement_type": "CI/CD",
                "status": "In Progress",
            },
        )
        return int(created["id"])

    def _ensure_test_type(self) -> int:
        """Ensure a test type exists for our findings. Return its ID."""
        result = self._request("GET", "/test_types/", params={"name": "Security Assessment"})
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        # Use the first available test type
        result = self._request("GET", "/test_types/", params={"limit": "1"})
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        return 1  # Fallback to ID 1 (usually exists by default)

    def get_or_create_test(self, engagement_id: int, name: str = "Platform Scan") -> int:
        """Find or create a test within an engagement, return test_id."""
        result = self._request(
            "GET",
            "/tests/",
            params={"engagement": str(engagement_id), "title": name},
        )
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        test_type_id = self._ensure_test_type()
        created = self._request(
            "POST",
            "/tests/",
            data={
                "engagement": engagement_id,
                "test_type": test_type_id,
                "title": name,
                "target_start": "2020-01-01",
                "target_end": "2099-12-31",
            },
        )
        return int(created["id"])

    def import_findings(
        self,
        engagement_id: int,
        findings: list[Finding],
    ) -> dict[str, int]:
        """Import findings to DefectDojo via individual /findings/ endpoint.

        Creates each finding individually with proper test linkage.
        Idempotent: hash_code based dedup (DefectDojo built-in).
        Each finding's control_ids are added as tags.

        Returns: {"created": N, "errors": N}
        """
        test_id = self.get_or_create_test(engagement_id)
        test_type_id = self._ensure_test_type()

        # Pre-fetch existing finding titles for idempotent import
        # Query by engagement (covers all tests) to avoid cross-test duplicates
        existing_titles: set[str] = set()
        try:
            offset = 0
            while True:
                existing = self._request(
                    "GET", "/findings/",
                    params={"test__engagement": str(engagement_id), "limit": "500", "offset": str(offset)},
                )
                results = existing.get("results", [])
                for f in results:
                    if f.get("title"):
                        existing_titles.add(f["title"].lower())
                if len(results) < 500:
                    break
                offset += 500
        except urllib.error.HTTPError:
            pass  # If query fails, proceed without dedup (worst case: duplicates)

        created = 0
        skipped = 0
        errors = 0
        for finding in findings:
            dd = finding_to_defectdojo(finding)

            # Idempotent: skip if title already exists (case-insensitive, DD may capitalize)
            if dd["title"].lower() in existing_titles:
                skipped += 1
                continue

            dd["test"] = test_id
            dd["found_by"] = [test_type_id]
            dd["active"] = True
            dd["verified"] = True
            dd["numerical_severity"] = (
                "S0" if finding.severity == "critical"
                else "S1" if finding.severity == "high"
                else "S2" if finding.severity == "medium"
                else "S3"
            )

            try:
                self._request("POST", "/findings/", data=dd)
                created += 1
                existing_titles.add(dd["title"].lower())
            except urllib.error.HTTPError:
                errors += 1

        logger.info("DefectDojo import: %d created, %d skipped, %d errors", created, skipped, errors)
        return {"created": created, "skipped": skipped, "errors": errors}

    def get_findings(
        self, product_name: str, tags: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Get findings for a product. Filter by tags (control_ids)."""
        params: dict[str, str] = {"test__engagement__product__name": product_name}
        if tags:
            params["tags"] = ",".join(tags)

        result = self._request("GET", "/findings/", params=params)
        return list(result.get("results", []))
