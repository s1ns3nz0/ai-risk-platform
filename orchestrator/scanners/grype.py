"""Grype scanner wrapper — SCA and container image scanning."""

from __future__ import annotations

import json
import logging
import subprocess

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 300  # 5 minutes
_DB_STALE_DAYS = 7


def check_grype_db_freshness() -> dict[str, object]:
    """Check Grype vulnerability DB status.

    Returns dict with 'status', 'built' (timestamp), and 'stale' (bool).
    """
    try:
        result = subprocess.run(
            ["grype", "db", "check"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        stale = "update available" in output.lower() or result.returncode != 0
        return {
            "status": "stale" if stale else "current",
            "stale": stale,
            "output": output.strip()[:200],
        }
    except Exception as e:
        return {"status": "unknown", "stale": True, "output": str(e)[:200]}


class GrypeScanner:
    """Grype SCA scanner wrapper.

    Supports three scan modes:
    - Directory scan: grype {dir} (scans lockfiles directly)
    - SBOM scan: grype sbom:{path} (scans a pre-generated CycloneDX SBOM)
    - Container scan: grype {image} (scans a Docker container image)
    """

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "grype"

    def scan(self, target_path: str) -> list[Finding]:
        """Run grype CLI against a directory path."""
        return self._run_grype(["grype", target_path, "-o", "json"])

    def scan_sbom(self, sbom_path: str) -> list[Finding]:
        """Run grype against a CycloneDX SBOM file."""
        return self._run_grype(["grype", f"sbom:{sbom_path}", "-o", "json"])

    def scan_image(self, image_ref: str) -> list[Finding]:
        """Run grype against a container image (e.g., 'nginx:latest')."""
        findings = self._run_grype(["grype", image_ref, "-o", "json"])
        for f in findings:
            f.message = f"[container:{image_ref}] {f.message}"
        return findings

    def _run_grype(self, cmd: list[str]) -> list[Finding]:
        """Execute grype and parse output."""
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if not result.stdout.strip():
            logger.warning("Grype produced no output. stderr: %s", result.stderr[:500])
            return []
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse Grype JSON output into Finding objects."""
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("Grype output is not valid JSON")
            return []

        matches = data.get("matches", [])
        if not isinstance(matches, list):
            return []

        findings: list[Finding] = []
        for match in matches:
            if not isinstance(match, dict):
                continue

            vuln = match.get("vulnerability", {})
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id", ""))
            severity = str(vuln.get("severity", "Unknown")).lower()

            # Extract CVE ID from relatedVulnerabilities (Grype uses GHSA as primary)
            cve_id = ""
            related = match.get("relatedVulnerabilities", [])
            if isinstance(related, list):
                for rv in related:
                    if isinstance(rv, dict):
                        rid = str(rv.get("id", ""))
                        if rid.startswith("CVE-"):
                            cve_id = rid
                            break

            artifact = match.get("artifact", {})
            file_path = ""
            pkg_name = ""
            pkg_version = ""
            if isinstance(artifact, dict):
                pkg_name = str(artifact.get("name", ""))
                pkg_version = str(artifact.get("version", ""))
                locations = artifact.get("locations", [])
                if isinstance(locations, list) and locations:
                    loc = locations[0]
                    if isinstance(loc, dict):
                        file_path = str(loc.get("path", ""))

            # Extract fixed version
            fix_versions = vuln.get("fix", {})
            fixed_version = ""
            if isinstance(fix_versions, dict):
                versions = fix_versions.get("versions", [])
                if isinstance(versions, list) and versions:
                    fixed_version = str(versions[0])

            # Use CVE ID when available (EPSS needs CVE, not GHSA)
            effective_id = cve_id if cve_id else vuln_id
            control_ids = self._control_mapper.map_finding("grype", effective_id, severity=severity)

            findings.append(
                Finding(
                    source="grype",
                    rule_id=effective_id,
                    severity=severity,
                    file=file_path,
                    line=0,
                    message=str(vuln.get("description", "")),
                    control_ids=control_ids,
                    product="",
                    package=pkg_name,
                    installed_version=pkg_version,
                    fixed_version=fixed_version,
                )
            )

        return findings
