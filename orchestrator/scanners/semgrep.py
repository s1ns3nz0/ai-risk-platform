"""Semgrep scanner wrapper — SAST integration."""

from __future__ import annotations

import json
import logging
import subprocess

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

# Semgrep severity → normalized severity
_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

_SUBPROCESS_TIMEOUT = 300  # 5 minutes


class SemgrepScanner:
    """Semgrep SAST scanner wrapper."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "semgrep"

    def scan(self, target_path: str) -> list[Finding]:
        """Run semgrep CLI and parse output."""
        result = subprocess.run(
            ["semgrep", "scan", "--json", "--quiet", target_path],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if not result.stdout.strip():
            logger.warning("Semgrep produced no output. stderr: %s", result.stderr[:500])
            return []
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse Semgrep JSON output into Finding objects."""
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("Semgrep output is not valid JSON")
            return []

        results: list[dict[str, object]] = data.get("results", [])

        findings: list[Finding] = []
        for result in results:
            rule_id = str(result.get("check_id", ""))

            extra = result.get("extra", {})
            if not isinstance(extra, dict):
                extra = {}
            severity_raw = str(extra.get("severity", "INFO"))
            severity = _SEVERITY_MAP.get(severity_raw, "low")

            start = result.get("start", {})
            if not isinstance(start, dict):
                start = {}
            line = int(start.get("line", 0))

            control_ids = self._control_mapper.map_finding("semgrep", rule_id)

            findings.append(
                Finding(
                    source="semgrep",
                    rule_id=rule_id,
                    severity=severity,
                    file=str(result.get("path", "")),
                    line=line,
                    message=str(extra.get("message", "")),
                    control_ids=control_ids,
                    product="",
                )
            )

        return findings
