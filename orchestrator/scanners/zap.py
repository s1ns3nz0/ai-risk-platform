"""ZAP scanner wrapper — DAST integration.

Runs OWASP ZAP in API scan mode against a running target.
Unlike SAST/SCA scanners, ZAP requires a live URL or OpenAPI spec.

Usage:
  - CLI: target_path is an OpenAPI spec file path or a URL
  - CI: build-dast.yml runs ZAP via Docker, this class parses the output
"""

from __future__ import annotations

import json
import logging
import subprocess

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

# ZAP risk levels → normalized severity
_RISK_MAP: dict[str, str] = {
    "3": "high",      # High
    "2": "medium",    # Medium
    "1": "low",       # Low
    "0": "low",       # Informational
}

_RISK_DESC_MAP: dict[str, str] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}

_SUBPROCESS_TIMEOUT = 600  # 10 minutes — DAST is slower than SAST


class ZapScanner:
    """OWASP ZAP DAST scanner wrapper.

    Two modes:
    1. Live scan: target_path is a URL (http://...) or OpenAPI spec file
       → runs ZAP Docker container against the target
    2. Parse-only: call parse_output() with pre-existing ZAP JSON results
       (used in CI where build-dast.yml already ran ZAP)
    """

    def __init__(
        self,
        control_mapper: ControlMapper,
        target_url: str = "http://127.0.0.1:8080",
        zap_image: str = "ghcr.io/zaproxy/zaproxy:stable",
    ) -> None:
        self._control_mapper = control_mapper
        self._target_url = target_url
        self._zap_image = zap_image

    @property
    def name(self) -> str:
        return "zap"

    def scan(self, target_path: str) -> list[Finding]:
        """Run ZAP API scan against a target.

        target_path can be:
        - A URL (http://...) → ZAP scans that URL directly
        - A file path to an OpenAPI spec → ZAP uses it for endpoint coverage
        - A file path to pre-existing zap-results.json → parse only (no scan)
        """
        # Mode 1: Pre-existing results file
        if target_path.endswith(".json"):
            try:
                with open(target_path) as f:
                    return self.parse_output(f.read())
            except FileNotFoundError:
                logger.warning("ZAP results file not found: %s", target_path)
                return []

        # Mode 2: OpenAPI spec file → run ZAP Docker
        if target_path.endswith((".yaml", ".yml")):
            return self._run_with_openapi(target_path)

        # Mode 3: URL target → run ZAP Docker
        if target_path.startswith("http"):
            return self._run_against_url(target_path)

        logger.warning(
            "ZAP target_path must be a URL, OpenAPI spec, or results JSON: %s",
            target_path,
        )
        return []

    def _run_with_openapi(self, spec_path: str) -> list[Finding]:
        """Run ZAP API scan with OpenAPI spec for full endpoint coverage."""
        import os
        import tempfile

        spec_dir = os.path.dirname(os.path.abspath(spec_path))
        spec_name = os.path.basename(spec_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    "docker", "run", "--rm", "--network", "host",
                    "-v", f"{spec_dir}:/zap/spec:ro",
                    "-v", f"{tmpdir}:/zap/wrk:rw",
                    self._zap_image,
                    "zap-api-scan.py",
                    "-t", f"/zap/spec/{spec_name}",
                    "-f", "openapi",
                    "-J", "zap-results.json",
                    "-I",  # don't fail on warnings
                ],
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT,
            )
            logger.info("ZAP exit code: %d", result.returncode)
            if result.stderr:
                logger.debug("ZAP stderr (last 500): %s", result.stderr[-500:])

            results_file = os.path.join(tmpdir, "zap-results.json")
            if os.path.exists(results_file):
                with open(results_file) as f:
                    return self.parse_output(f.read())

            logger.warning("ZAP did not produce results file")
            return []

    def _run_against_url(self, url: str) -> list[Finding]:
        """Run ZAP baseline scan against a URL."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    "docker", "run", "--rm", "--network", "host",
                    "-v", f"{tmpdir}:/zap/wrk:rw",
                    self._zap_image,
                    "zap-baseline.py",
                    "-t", url,
                    "-J", "zap-results.json",
                    "-I",
                ],
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT,
            )
            logger.info("ZAP exit code: %d", result.returncode)

            import os

            results_file = os.path.join(tmpdir, "zap-results.json")
            if os.path.exists(results_file):
                with open(results_file) as f:
                    return self.parse_output(f.read())

            logger.warning("ZAP did not produce results file")
            return []

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse ZAP JSON output into Finding objects.

        ZAP JSON structure:
        {
            "site": [{
                "alerts": [{
                    "pluginid": "40012",
                    "alertRef": "40012",
                    "name": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "riskdesc": "High (Medium)",
                    "confidence": "2",
                    "desc": "...",
                    "solution": "...",
                    "instances": [{
                        "uri": "http://...",
                        "method": "GET",
                        "param": "query",
                        "evidence": "..."
                    }],
                    "count": "2",
                    "cweid": "79"
                }]
            }]
        }
        """
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("ZAP output is not valid JSON")
            return []

        findings: list[Finding] = []
        sites = data.get("site", [])

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                rule_id = f"ZAP-{alert.get('pluginid', alert.get('alertRef', 'unknown'))}"
                risk_code = str(alert.get("riskcode", "0"))
                severity = _RISK_MAP.get(risk_code, "low")

                # Also try parsing from riskdesc (e.g., "High (Medium)")
                if severity == "low" and "riskdesc" in alert:
                    risk_word = alert["riskdesc"].split(" ")[0].lower()
                    severity = _RISK_DESC_MAP.get(risk_word, severity)

                name = alert.get("name", "Unknown ZAP Alert")
                cwe_id = alert.get("cweid", "")
                solution = alert.get("solution", "")

                instances = alert.get("instances", [])
                control_ids = self._control_mapper.map_finding("zap", rule_id)

                if instances:
                    # Create one finding per unique instance
                    seen_uris: set[str] = set()
                    for inst in instances:
                        uri = inst.get("uri", "")
                        method = inst.get("method", "")
                        param = inst.get("param", "")
                        key = f"{method}:{uri}:{param}"
                        if key in seen_uris:
                            continue
                        seen_uris.add(key)

                        message = f"{name} — {method} {uri}"
                        if param:
                            message += f" (param: {param})"
                        if cwe_id:
                            message += f" [CWE-{cwe_id}]"

                        findings.append(
                            Finding(
                                source="zap",
                                rule_id=rule_id,
                                severity=severity,
                                file=uri,
                                line=0,
                                message=message,
                                control_ids=control_ids,
                                product="",
                            )
                        )
                else:
                    # No instances — create a single finding for the alert
                    message = name
                    if cwe_id:
                        message += f" [CWE-{cwe_id}]"

                    findings.append(
                        Finding(
                            source="zap",
                            rule_id=rule_id,
                            severity=severity,
                            file="",
                            line=0,
                            message=message,
                            control_ids=control_ids,
                            product="",
                        )
                    )

        logger.info("ZAP parsed %d findings from %d alerts", len(findings), sum(len(s.get("alerts", [])) for s in sites))
        return findings
