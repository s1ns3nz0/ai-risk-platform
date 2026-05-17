"""Trivy scanner parser.

Trivy native JSON shape:
{
  "SchemaVersion": 2,
  "ArtifactName": "<image|fs|repo>",
  "ArtifactType": "container_image" | "filesystem" | "repository",
  "Results": [
    {
      "Target": "alpine:3.18 (alpine 3.18.4)",
      "Class": "os-pkgs" | "lang-pkgs" | "config" | "secret",
      "Type": "alpine" | "python-pkg" | ...,
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-...",
          "PkgName": "...",
          "InstalledVersion": "...",
          "FixedVersion": "...",
          "Severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"UNKNOWN",
          "Title": "...",
          "Description": "..."
        }
      ],
      "Secrets": [...],          # for class=secret
      "Misconfigurations": [...] # for class=config
    }
  ]
}

For SARIF output (`trivy --format sarif`), callers should pass scanner="sarif"
or "trivy-sarif" so it routes through the universal SARIF parser instead.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
    "NEGLIGIBLE": "info",
}


class TrivyScanner:
    """Parses Trivy native JSON. Currently extracts vulnerabilities, secrets,
    and misconfigurations into the unified Finding model."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    def parse_output(self, raw_output: str) -> list[Finding]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("Trivy output is not valid JSON")
            return []

        if not isinstance(data, dict):
            return []

        results = data.get("Results")
        if not isinstance(results, list):
            return []

        artifact_target = str(data.get("ArtifactName", ""))
        findings: list[Finding] = []

        for result in results:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target", artifact_target))

            findings.extend(self._parse_vulns(result, target))
            findings.extend(self._parse_misconfigs(result, target))
            findings.extend(self._parse_secrets(result, target))

        return findings

    # --- vulns ---
    def _parse_vulns(self, result: dict[str, Any], target: str) -> list[Finding]:
        vulns = result.get("Vulnerabilities")
        if not isinstance(vulns, list):
            return []
        out: list[Finding] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            rule_id = str(v.get("VulnerabilityID", ""))
            if not rule_id:
                continue
            severity = _SEVERITY_MAP.get(str(v.get("Severity", "")).upper(), "info")
            pkg = str(v.get("PkgName", ""))
            installed = str(v.get("InstalledVersion", ""))
            fixed = str(v.get("FixedVersion", ""))
            message = str(v.get("Title") or v.get("Description") or rule_id)

            # Trivy's CVSS is {vendor: {V3Score, V2Score, V3Vector, ...}, ...}.
            # Prefer NVD V3Score; fall back to the first vendor's V3Score, then V2.
            cvss_score = _pick_trivy_cvss(v.get("CVSS"))

            # Trivy reliably emits CweIDs[] when NVD has the mapping.
            cwe_ids_raw = v.get("CweIDs", [])
            cwe_ids = [str(c) for c in cwe_ids_raw if isinstance(c, str)] if isinstance(cwe_ids_raw, list) else []

            # SCA-equivalent: Trivy CVE findings use the same severity-threshold
            # mapping as Grype, so reuse `grype` as the mapper key. The Finding's
            # `source` stays "trivy" for audit trail.
            control_ids = self._control_mapper.map_finding("grype", rule_id, severity=severity)
            out.append(
                Finding(
                    source="trivy",
                    rule_id=rule_id,
                    severity=severity,
                    file=target,
                    line=0,
                    message=message,
                    control_ids=control_ids,
                    product="",
                    package=pkg,
                    installed_version=installed,
                    fixed_version=fixed,
                    cvss_score=cvss_score,
                    cwe_ids=cwe_ids,
                )
            )
        return out

    # --- misconfigs (IaC, Dockerfile, etc.) ---
    def _parse_misconfigs(self, result: dict[str, Any], target: str) -> list[Finding]:
        items = result.get("Misconfigurations")
        if not isinstance(items, list):
            return []
        out: list[Finding] = []
        for m in items:
            if not isinstance(m, dict):
                continue
            rule_id = str(m.get("ID") or m.get("AVDID") or "")
            if not rule_id:
                continue
            severity = _SEVERITY_MAP.get(str(m.get("Severity", "")).upper(), "info")
            location = m.get("CauseMetadata") if isinstance(m.get("CauseMetadata"), dict) else {}
            # StartLine may be null (not just absent) when Trivy can't resolve it.
            line = int((location or {}).get("StartLine") or 0)
            message = str(m.get("Title") or m.get("Description") or rule_id)

            # No clean SCA-equivalent mapper for IaC misconfig IDs (Trivy AVD-*
            # vs Checkov CKV_*). Leave under "trivy"; baselines may add explicit
            # support later.
            control_ids = self._control_mapper.map_finding("trivy", rule_id, severity=severity)
            out.append(
                Finding(
                    source="trivy",
                    rule_id=rule_id,
                    severity=severity,
                    file=target,
                    line=line,
                    message=message,
                    control_ids=control_ids,
                    product="",
                )
            )
        return out

    # --- secrets ---
    def _parse_secrets(self, result: dict[str, Any], target: str) -> list[Finding]:
        items = result.get("Secrets")
        if not isinstance(items, list):
            return []
        out: list[Finding] = []
        for s in items:
            if not isinstance(s, dict):
                continue
            raw_rule = str(s.get("RuleID") or s.get("Category") or "trivy-secret")
            # Prefix `secret-` so the gate's secrets_count predicate picks these up
            # regardless of which tool detected them. Doubles as a clear marker
            # in the SAR/POA&M.
            rule_id = raw_rule if raw_rule.startswith("secret-") else f"secret-{raw_rule}"
            severity = _SEVERITY_MAP.get(str(s.get("Severity", "")).upper(), "high")
            line = int(s.get("StartLine") or 0)
            message = str(s.get("Title") or rule_id)

            # Map via gitleaks so Trivy-detected secrets pick up the rule-agnostic
            # gitleaks control mappings (they're semantically the same — a leaked
            # credential is the same compliance event regardless of detector).
            control_ids = self._control_mapper.map_finding("gitleaks", rule_id, severity=severity)
            out.append(
                Finding(
                    source="trivy",
                    rule_id=rule_id,
                    severity=severity,
                    file=target,
                    line=line,
                    message=message,
                    control_ids=control_ids,
                    product="",
                )
            )
        return out


def _pick_trivy_cvss(cvss_map: Any) -> float | None:
    """Trivy emits CVSS as {vendor: {V3Score, V2Score, V3Vector, ...}}.
    Prefer NVD V3, then any V3, then any V2."""
    if not isinstance(cvss_map, dict):
        return None
    nvd = cvss_map.get("nvd")
    if isinstance(nvd, dict):
        v3 = nvd.get("V3Score")
        if isinstance(v3, (int, float)):
            return float(v3)
    for entry in cvss_map.values():
        if isinstance(entry, dict):
            v3 = entry.get("V3Score")
            if isinstance(v3, (int, float)):
                return float(v3)
    for entry in cvss_map.values():
        if isinstance(entry, dict):
            v2 = entry.get("V2Score")
            if isinstance(v2, (int, float)):
                return float(v2)
    return None
