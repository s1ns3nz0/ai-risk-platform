"""SARIF parser — universal scanner result importer.

Parses SARIF 2.1.0 (Static Analysis Results Interchange Format)
into normalized Finding objects. Works with ANY tool that outputs SARIF:
  Semgrep, Grype, Trivy, Bandit, Checkov, CodeQL, Snyk, Hadolint, etc.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import logging

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

# SARIF level → normalized severity
_LEVEL_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}

# Well-known tool name normalization. Keys are slug-normalized (lowercase,
# whitespace/punctuation collapsed to "-"); see `_normalize_tool_name`.
# Matching is substring-based so vendor-flavored variants like "Semgrep OSS",
# "semgrep-oss", "Trivy 0.50.0" all map to the canonical scanner key.
_TOOL_ALIASES: dict[str, str] = {
    "semgrep": "semgrep",
    "grype": "grype",
    "trivy": "trivy",
    "bandit": "bandit",
    "checkov": "checkov",
    "codeql": "codeql",
    "snyk": "snyk",
    "hadolint": "hadolint",
    "gitleaks": "gitleaks",
    "spotbugs": "spotbugs",
    "eslint": "eslint",
    "tfsec": "tfsec",
    "terrascan": "terrascan",
    "kics": "kics",
    "sonarqube": "sonarqube",
    "gosec": "gosec",
    "safety": "safety",
    "pip-audit": "pip-audit",
    "npm-audit": "npm-audit",
    "bearer": "bearer",
    "megalinter": "megalinter",
}


def _normalize_tool_name(raw: str) -> str:
    """Map SARIF tool.driver.name to a canonical scanner key.

    Handles vendor-decorated names ("Semgrep OSS", "Trivy 0.50.0",
    "hadolint v2.12") by lowercasing then substring-matching against the
    alias table. Falls back to a slugified version of the raw name when no
    alias matches.
    """
    if not raw:
        return "unknown"
    lowered = raw.lower().strip()
    for key, canonical in _TOOL_ALIASES.items():
        if key in lowered:
            return canonical
    # Slugify so multi-word tool names ("My Scanner") don't carry whitespace
    # into Finding.source (where downstream code uses exact equality).
    return "-".join(lowered.split())


def parse_sarif(
    raw_output: str,
    control_mapper: ControlMapper,
    default_product: str = "",
) -> list[Finding]:
    """Parse SARIF 2.1.0 JSON into Finding objects.

    Works with any SARIF-producing tool. Extracts:
    - Tool name from runs[].tool.driver.name
    - Rule ID from results[].ruleId
    - Severity from results[].level
    - Location from results[].locations[].physicalLocation
    - Message from results[].message.text
    - CWE from results[].taxa[] or rules[].properties.tags[]
    """
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        logger.warning("SARIF output is not valid JSON")
        return []

    if data.get("version") != "2.1.0":
        logger.warning("Unsupported SARIF version: %s", data.get("version"))

    runs = data.get("runs", [])
    if not runs:
        logger.warning("SARIF contains no runs")
        return []

    findings: list[Finding] = []

    for run in runs:
        tool = run.get("tool", {}).get("driver", {})
        tool_name = _normalize_tool_name(tool.get("name", ""))

        # Build rule metadata index (for severity overrides and CWE mapping)
        rule_index: dict[str, dict[str, object]] = {}
        for rule in tool.get("rules", []):
            rule_id = rule.get("id", "")
            rule_index[rule_id] = rule

        results = run.get("results", [])

        for result in results:
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "warning")
            severity = _level_to_severity(level, rule_id, rule_index)

            # Message
            message_obj = result.get("message", {})
            message = message_obj.get("text", "") or message_obj.get("markdown", "")

            # Location
            file_path = ""
            line = 0
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                file_path = artifact.get("uri", "")
                region = phys.get("region", {})
                line = region.get("startLine", 0)

            # CWE extraction (from taxa or rule properties)
            cwe_ids = _extract_cwes(result, rule_index.get(rule_id, {}))

            # Package info (for SCA tools like Grype, Trivy, Snyk)
            package = ""
            installed_version = ""
            fixed_version = ""
            props = result.get("properties", {})
            if props:
                package = props.get("package", "") or props.get("packageName", "")
                installed_version = props.get("installedVersion", "") or props.get("version", "")
                fixed_version = props.get("fixedVersion", "") or props.get("fixVersion", "")

            # Map to controls
            control_ids = control_mapper.map_finding(tool_name, rule_id, severity)

            # Enrich message with CWE
            if cwe_ids and not any(f"CWE-{c}" in message for c in cwe_ids):
                message += " [" + ", ".join(f"CWE-{c}" for c in cwe_ids) + "]"

            findings.append(
                Finding(
                    source=tool_name,
                    rule_id=rule_id,
                    severity=severity,
                    file=file_path,
                    line=line,
                    message=message,
                    control_ids=control_ids,
                    product=default_product,
                    package=package,
                    installed_version=installed_version,
                    fixed_version=fixed_version,
                )
            )

    logger.info(
        "SARIF parsed: %d findings from %d runs (%s)",
        len(findings),
        len(runs),
        ", ".join(run.get("tool", {}).get("driver", {}).get("name", "?") for run in runs),
    )
    return findings


def _level_to_severity(
    level: str,
    rule_id: str,
    rule_index: dict[str, dict[str, object]],
) -> str:
    """Map SARIF level to normalized severity.

    Checks rule metadata for severity overrides (some tools encode
    severity in rule properties rather than result level).
    """
    # Check if the rule has a severity property
    rule = rule_index.get(rule_id, {})
    rule_props = rule.get("properties", {})

    # Some tools use properties.security-severity (numeric 0-10)
    sec_severity = rule_props.get("security-severity")
    if sec_severity is not None:
        try:
            score = float(sec_severity)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
        except (ValueError, TypeError):
            pass

    # Some tools use properties.precision or properties.impact
    impact = rule_props.get("impact", "")
    if isinstance(impact, str):
        impact_lower = impact.lower()
        if impact_lower in ("critical", "high", "medium", "low"):
            return impact_lower

    # Default SARIF level mapping
    return _LEVEL_MAP.get(level, "medium")


def _extract_cwes(
    result: dict[str, object],
    rule: dict[str, object],
) -> list[str]:
    """Extract CWE IDs from SARIF result or rule metadata."""
    cwes: list[str] = []

    # From result taxa
    taxa = result.get("taxa", [])
    if isinstance(taxa, list):
        for t in taxa:
            if isinstance(t, dict):
                toolcomp = t.get("toolComponent", {})
                if isinstance(toolcomp, dict) and toolcomp.get("name") == "cwe":
                    cwes.append(str(t.get("id", "")))

    # From rule properties.tags (Semgrep style: ["CWE-89", "CWE-79"])
    tags = rule.get("properties", {}).get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("CWE-"):
                cwes.append(tag.replace("CWE-", ""))

    # From rule properties.cwe (CodeQL style)
    cwe_prop = rule.get("properties", {}).get("cwe", [])
    if isinstance(cwe_prop, list):
        for c in cwe_prop:
            if isinstance(c, str):
                cwes.append(c.replace("CWE-", ""))

    return list(set(cwes))


def is_sarif(raw_output: str) -> bool:
    """Check if a string is SARIF JSON."""
    try:
        data = json.loads(raw_output)
        return isinstance(data, dict) and (
            data.get("version") == "2.1.0"
            or "$schema" in data and "sarif" in str(data.get("$schema", ""))
        )
    except (json.JSONDecodeError, TypeError):
        return False
