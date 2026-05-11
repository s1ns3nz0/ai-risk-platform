"""Per-finding SP 800-30 prompt templates for two-stage AI pipeline.

Two new prompt pairs for the per-finding assessment architecture:
  1. PER_FINDING_ASSESSMENT_PROMPT — single finding deep analysis
  2. SUMMARY_SYNTHESIS_PROMPT — cross-signal synthesis of all per-finding results

Each pair has a system prompt (cacheable, same across calls) and a user prompt
(variable per call). Designed for stream_with_cache(system_prompt, user_prompt).

Existing FILTER_PROMPT and SP800_30_ASSESSMENT_PROMPT in pipeline.py are untouched.
"""

from __future__ import annotations

import json
from typing import Any

from orchestrator.types import ProductManifest

# ---------------------------------------------------------------------------
# 1. PER_FINDING_ASSESSMENT_PROMPT
# ---------------------------------------------------------------------------

PER_FINDING_SYSTEM_PROMPT = """\
You are a senior security risk assessor following NIST SP 800-30 Rev 1 methodology.

## Methodology
You will perform a complete SP 800-30 risk assessment for a SINGLE security finding.
Follow all six phases:
1. Threat Source Identification (Section 3.1)
2. Threat Event Identification (Section 3.2)
3. Likelihood Determination (Section 3.3)
4. Impact Determination (Section 3.4)
5. Risk Determination (Section 3.5)
6. Risk Response Recommendation

## Product Architecture Context
Product: {product_name}
Description: {product_description}
Cloud: {cloud}
Jurisdiction: {jurisdiction}

CIA Impact Levels (FIPS 199):
  Confidentiality: {cia_confidentiality}
  Integrity: {cia_integrity}
  Availability: {cia_availability}

## Response Schema
Respond with a single JSON object (no markdown fences):
{{
  "threat_source": {{
    "id": "TS-XXX-NNN",
    "type": "adversarial|accidental|structural|environmental",
    "name": "...",
    "capability": "very-low|low|moderate|high|very-high",
    "intent": "...",
    "targeting": "..."
  }},
  "threat_event": {{
    "id": "TE-NNN",
    "description": "...",
    "source_id": "TS-XXX-NNN",
    "mitre_technique": "TNNNN",
    "relevance": "confirmed|expected|predicted|possible",
    "cve_id": "",
    "target_component": "..."
  }},
  "likelihood": {{
    "initiation_likelihood": "very-low|low|moderate|high|very-high",
    "impact_likelihood": "very-low|low|moderate|high|very-high",
    "overall_likelihood": "very-low|low|moderate|high|very-high",
    "epss_score": null,
    "predisposing_conditions": ["..."],
    "evidence": "..."
  }},
  "impact": {{
    "impact_type": "harm to operations|harm to assets|harm to individuals",
    "cia_impact": {{"confidentiality": "...", "integrity": "...", "availability": "..."}},
    "severity": "very-low|low|moderate|high|very-high",
    "compliance_impact": ["CONTROL-ID"],
    "business_impact": "...",
    "evidence": "..."
  }},
  "risk_determination": {{
    "threat_event_id": "TE-NNN",
    "likelihood": "very-low|low|moderate|high|very-high",
    "impact": "very-low|low|moderate|high|very-high",
    "risk_level": "very-low|low|moderate|high|very-high",
    "risk_score": 0.0
  }},
  "risk_response": {{
    "risk_determination_id": "TE-NNN",
    "response_type": "accept|avoid|mitigate|share|transfer",
    "description": "...",
    "milestones": ["..."],
    "deadline": "YYYY-MM-DD",
    "responsible": "..."
  }},
  "narrative": "2-sentence summary of this finding's risk and recommended action."
}}
"""

PER_FINDING_USER_PROMPT = """\
## Finding (index {finding_index})

Source: {source}
Rule ID: {rule_id}
Severity: {severity}
File: {file}
Line: {line}
Message: {message}
Control IDs: {control_ids}
{package_info}

## Mapped Controls
{controls_text}

## EPSS Data
{epss_text}

Use threat event ID: TE-{te_id}

Analyze this finding following the SP 800-30 methodology described in the system prompt.
"""


# ---------------------------------------------------------------------------
# 2. SUMMARY_SYNTHESIS_PROMPT
# ---------------------------------------------------------------------------

SUMMARY_SYSTEM_PROMPT = """\
You are a senior security risk assessor synthesizing individual SP 800-30 \
finding assessments into an executive summary.

## Product Architecture Context
Product: {product_name}
Description: {product_description}
Cloud: {cloud}
Jurisdiction: {jurisdiction}

CIA Impact Levels (FIPS 199):
  Confidentiality: {cia_confidentiality}
  Integrity: {cia_integrity}
  Availability: {cia_availability}

## Cross-Signal Analysis Instructions
Go beyond individual findings. Identify:
- Attack chains: can multiple findings be chained for escalated impact?
- Compound risk: do findings in different categories amplify each other?
- Correlation patterns: do findings share root causes or affected components?
- Coverage gaps: are there control areas with no scanner coverage?

## Response Schema
Respond with a single JSON object (no markdown fences):
{{
  "executive_summary": "2-3 paragraph narrative for decision-makers",
  "cross_signal_insights": [
    "Finding A + Finding B together create an escalation path...",
    "..."
  ],
  "overall_risk_posture": "very-low|low|moderate|high|very-high",
  "recommendations": ["prioritized action items"]
}}
"""

SUMMARY_USER_PROMPT = """\
## Per-Finding Assessment Results

{per_finding_json}

## Finding Statistics
Total findings: {total_findings}
Severity breakdown: {severity_breakdown}

Synthesize the above per-finding assessments into a cross-signal executive summary.
Identify attack chains and compound risks that individual assessments cannot capture.
"""


# ---------------------------------------------------------------------------
# Builder functions
# ---------------------------------------------------------------------------


def _architecture_fields(manifest: ProductManifest) -> dict[str, str]:
    """Extract common architecture fields from manifest for prompt formatting."""
    cia = manifest.impact_levels
    return {
        "product_name": manifest.name,
        "product_description": manifest.description,
        "cloud": str(manifest.deployment.get("cloud", "unknown")),
        "jurisdiction": ", ".join(manifest.jurisdiction) if manifest.jurisdiction else "N/A",
        "cia_confidentiality": cia.get("confidentiality", "moderate").upper(),
        "cia_integrity": cia.get("integrity", "moderate").upper(),
        "cia_availability": cia.get("availability", "moderate").upper(),
    }


def build_per_finding_prompts(
    manifest: ProductManifest,
    finding: dict[str, Any],
    controls: list[dict[str, Any]],
    epss_data: dict[str, Any] | None,
    finding_index: int = 0,
) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) for a single finding assessment.

    system_prompt is identical across all findings for the same product,
    enabling Bedrock prompt caching via cache_control.

    Args:
        manifest: Product manifest with architecture context.
        finding: Single finding dict (from _step1_gather format).
        controls: Controls mapped to this finding.
        epss_data: EPSS enrichment data for this finding's CVE, or None.
        finding_index: 0-based index for TE-ID generation.

    Returns:
        (system_prompt, user_prompt) tuple for stream_with_cache().
    """
    arch = _architecture_fields(manifest)
    system_prompt = PER_FINDING_SYSTEM_PROMPT.format(**arch)

    # Controls text
    controls_text = "\n".join(
        f"- {c['id']}: {c.get('title', '')} ({c.get('framework', '')})"
        for c in controls
    ) or "No mapped controls."

    # EPSS text
    if epss_data:
        epss_text = (
            f"EPSS Score: {epss_data.get('epss_score', 'N/A')}\n"
            f"EPSS Percentile: {epss_data.get('epss_percentile', 'N/A')}\n"
            f"Priority: {epss_data.get('priority', 'N/A')}"
        )
    else:
        epss_text = "No EPSS data available."

    # Package info (SCA findings)
    pkg = finding.get("package", "")
    if pkg:
        package_info = (
            f"Package: {pkg}\n"
            f"Installed Version: {finding.get('installed_version', '')}\n"
            f"Fixed Version: {finding.get('fixed_version', '')}"
        )
    else:
        package_info = ""

    # Control IDs as string
    control_ids = finding.get("control_ids", [])
    control_ids_str = ", ".join(str(c) for c in control_ids) if control_ids else "unmapped"

    te_id = f"{finding_index + 1:03d}"

    user_prompt = PER_FINDING_USER_PROMPT.format(
        finding_index=finding_index,
        source=finding.get("source", "unknown"),
        rule_id=finding.get("rule_id", "unknown"),
        severity=finding.get("severity", "unknown"),
        file=finding.get("file", "unknown"),
        line=finding.get("line", 0),
        message=finding.get("message", ""),
        control_ids=control_ids_str,
        package_info=package_info,
        controls_text=controls_text,
        epss_text=epss_text,
        te_id=te_id,
    )

    return system_prompt, user_prompt


def build_summary_prompts(
    manifest: ProductManifest,
    per_finding_results: list[dict[str, Any]],
    total_findings: int,
    severity_counts: dict[str, int],
) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) for summary synthesis.

    system_prompt is cacheable (same product context).
    user_prompt contains all per-finding results and statistics.

    Args:
        manifest: Product manifest with architecture context.
        per_finding_results: List of per-finding assessment result dicts.
        total_findings: Total number of findings (not just assessed ones).
        severity_counts: Counts by severity level.

    Returns:
        (system_prompt, user_prompt) tuple for stream_with_cache().
    """
    arch = _architecture_fields(manifest)
    system_prompt = SUMMARY_SYSTEM_PROMPT.format(**arch)

    severity_breakdown = ", ".join(
        f"{k}: {v}" for k, v in severity_counts.items()
    )

    user_prompt = SUMMARY_USER_PROMPT.format(
        per_finding_json=json.dumps(per_finding_results, indent=2),
        total_findings=total_findings,
        severity_breakdown=severity_breakdown,
    )

    return system_prompt, user_prompt
