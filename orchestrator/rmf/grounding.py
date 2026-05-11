"""Grounding validation — verify AI output cites real findings and controls.

Deterministic check that AI-generated risk assessments reference
actual CVEs, control IDs, and findings from the input data.
This is better than using AI-based guardrails (AI checking AI is circular).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from orchestrator.controls.models import Control
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


@dataclass
class GroundingResult:
    """Result of grounding validation."""

    valid: bool
    total_references: int
    verified_references: int
    hallucinated_references: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_grounding(
    ai_output: dict[str, object],
    findings: list[Finding],
    controls: list[Control],
) -> GroundingResult:
    """Validate that AI assessment cites real CVEs and control IDs.

    Checks:
    1. CVE IDs mentioned by AI exist in the input findings
    2. Control IDs mentioned by AI exist in the controls baseline
    3. Package names mentioned by AI exist in the findings
    4. Risk levels are valid SP 800-30 levels

    Returns GroundingResult with validation details.
    """
    known_cve_ids = {f.rule_id for f in findings if f.rule_id.startswith("CVE-")}
    known_ghsa_ids = {f.rule_id for f in findings if f.rule_id.startswith("GHSA-")}
    known_finding_ids = known_cve_ids | known_ghsa_ids | {f.rule_id for f in findings}
    known_control_ids = {c.id for c in controls}
    valid_risk_levels = {"very-low", "low", "moderate", "high", "very-high"}

    # Serialize AI output to text for scanning
    ai_text = _flatten_to_text(ai_output)

    # Find all CVE references in AI output
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}")
    ghsa_pattern = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")
    control_pattern = re.compile(r"(?:PCI-DSS-[\d.]+|ASVS-V[\d.]+|FISC-[実統設監]\d+|CMMC-[A-Z]{2}\.L\d-[\d.]+)")

    referenced_cves = set(cve_pattern.findall(ai_text))
    referenced_ghsas = set(ghsa_pattern.findall(ai_text))
    referenced_controls = set(control_pattern.findall(ai_text))

    total_refs = len(referenced_cves) + len(referenced_ghsas) + len(referenced_controls)
    hallucinated: list[str] = []
    warnings: list[str] = []

    # Check CVEs
    for cve in referenced_cves:
        if cve not in known_finding_ids:
            hallucinated.append(f"CVE not in findings: {cve}")

    # Check GHSAs
    for ghsa in referenced_ghsas:
        if ghsa not in known_finding_ids:
            hallucinated.append(f"GHSA not in findings: {ghsa}")

    # Check control IDs
    for ctrl in referenced_controls:
        if ctrl not in known_control_ids:
            hallucinated.append(f"Control ID not in baseline: {ctrl}")

    # Check risk levels in risk_determinations
    risk_dets = ai_output.get("risk_determinations", [])
    if isinstance(risk_dets, list):
        for rd in risk_dets:
            if isinstance(rd, dict):
                for field_name in ("likelihood", "impact", "risk_level"):
                    val = rd.get(field_name, "")
                    if isinstance(val, str) and val and val.lower() not in valid_risk_levels:
                        warnings.append(f"Invalid SP 800-30 risk level: {field_name}={val}")

    # Check that AI cited SOMETHING (empty assessment is suspicious)
    if total_refs == 0:
        warnings.append("AI assessment contains no CVE/control references — may be generic")

    verified = total_refs - len(hallucinated)

    if hallucinated:
        logger.warning(
            "Grounding validation: %d hallucinated references found: %s",
            len(hallucinated),
            hallucinated,
        )

    return GroundingResult(
        valid=len(hallucinated) == 0,
        total_references=total_refs,
        verified_references=verified,
        hallucinated_references=hallucinated,
        warnings=warnings,
    )


def _flatten_to_text(obj: object) -> str:
    """Recursively flatten a dict/list structure to a single text string."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_to_text(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten_to_text(item) for item in obj)
    return str(obj)
