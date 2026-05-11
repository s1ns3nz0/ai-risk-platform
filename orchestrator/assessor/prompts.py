"""Prompt templates for Bedrock risk assessment."""

from __future__ import annotations

from orchestrator.controls.models import Control
from orchestrator.types import Finding, ProductManifest, RiskTier

CATEGORIZATION_PROMPT = """\
You are a security risk assessor. Analyze this product and determine the risk tier.

Product: {name}
Description: {description}
Data classification: {data_classification}
Jurisdiction: {jurisdiction}

Architecture:
{architecture_context}

Risk tier definitions:
- LOW: No sensitive data, internal tools
- MEDIUM: PII or moderate sensitivity
- HIGH: PCI cardholder data, financial data
- CRITICAL: PCI + regulated jurisdiction (JP/FISC)

Respond in JSON:
{{"tier": "high", "reasoning": "...", "threat_profile": ["T1190", "T1078"]}}
"""

ASSESSMENT_PROMPT = """\
You are a security risk assessor performing cross-signal analysis.

Product: {product_name} (Risk tier: {tier})
Trigger: {trigger}
Data classification: {data_classification}
Jurisdiction: {jurisdiction}

Architecture:
{architecture_context}

Findings ({n_findings} total):
{findings_summary}

Applicable controls ({n_controls}):
{controls_summary}

Risk score (deterministic): {risk_score}/10

Using the architecture context above, provide:
1. A 2-3 paragraph narrative explaining the risk in auditor-appropriate language.
   Reference SPECIFIC infrastructure components (e.g., "the RDS PostgreSQL database storing PCI data
   lacks encryption" or "the API Gateway endpoint is internet-facing, increasing exposure").
2. Cross-signal insights: connections between findings AND infrastructure that individual scanners miss.
   Example: "The S3 bucket without encryption (Checkov CKV_AWS_19) stores payment receipts,
   and the IAM policy (CKV_AWS_1) grants wildcard access — together these create a data
   exfiltration path for PCI cardholder data."
3. Recommendations for remediation, specific to the infrastructure components.
4. Gate recommendation: proceed / hold_for_review / block (advisory only)

Respond in JSON:
{{"narrative": "...", "cross_signal_insights": [...], "recommendations": [...], "gate_recommendation": "..."}}
"""


def _format_architecture_context(manifest: ProductManifest) -> str:
    """Format the full deployment architecture for AI context.

    This gives the AI the complete picture of what the product uses,
    enabling infrastructure-aware risk assessment.
    """
    lines: list[str] = []
    deploy = manifest.deployment

    cloud = deploy.get("cloud", "unknown")
    region = deploy.get("region", "unknown")
    lines.append(f"Cloud: {cloud} ({region})")

    # Compute
    compute = deploy.get("compute", [])
    if isinstance(compute, list):
        for c in compute:
            if isinstance(c, dict):
                lines.append(f"Compute: {c.get('type', '?')} — {c.get('description', '')}")
    elif isinstance(compute, str):
        lines.append(f"Compute: {compute}")

    # Databases
    databases = deploy.get("databases", [])
    if isinstance(databases, list):
        for db in databases:
            if isinstance(db, dict):
                enc = f", encryption={db['encryption']}" if "encryption" in db else ""
                engine = f" ({db['engine']})" if "engine" in db else ""
                lines.append(f"Database: {db.get('type', '?')}{engine}{enc} — {db.get('description', '')}")

    # Storage
    storage = deploy.get("storage", [])
    if isinstance(storage, list):
        for s in storage:
            if isinstance(s, dict):
                enc = f", encryption={s['encryption']}" if "encryption" in s else ""
                pub = f", public_access={s['public_access']}" if "public_access" in s else ""
                lines.append(f"Storage: {s.get('type', '?')}{enc}{pub} — {s.get('description', '')}")

    # Networking
    networking = deploy.get("networking", [])
    if isinstance(networking, list):
        for n in networking:
            if isinstance(n, dict):
                lines.append(f"Networking: {n.get('type', '?')} — {n.get('description', '')}")

    # Messaging
    messaging = deploy.get("messaging", [])
    if isinstance(messaging, list):
        for m in messaging:
            if isinstance(m, dict):
                enc = f", encryption={m['encryption']}" if "encryption" in m else ""
                lines.append(f"Messaging: {m.get('type', '?')}{enc} — {m.get('description', '')}")

    # Observability
    observability = deploy.get("observability", [])
    if isinstance(observability, list):
        for o in observability:
            if isinstance(o, dict):
                ret = f", retention={o['log_retention_days']}d" if "log_retention_days" in o else ""
                lines.append(f"Observability: {o.get('type', '?')}{ret} — {o.get('description', '')}")

    # Integrations
    if manifest.integrations:
        lines.append(f"External integrations: {', '.join(manifest.integrations)}")

    # FIPS 199 Impact Levels
    if manifest.impact_levels:
        lines.append("")
        lines.append("Impact Levels (FIPS 199):")
        for dim in ("confidentiality", "integrity", "availability"):
            level = manifest.impact_levels.get(dim, "moderate").upper()
            lines.append(f"  {dim.capitalize()}: {level}")

    # Mission Context (MbCRA)
    _format_mission_context(lines, manifest)

    return "\n".join(lines) if lines else "No architecture details provided."


def _format_mission_context(lines: list[str], manifest: ProductManifest) -> None:
    """Format mission context for AI risk assessment (MbCRA).

    Reads mission data from the deployment dict or manifest attributes.
    This gives the AI business context to produce mission-relevant narratives.
    """
    mission = manifest.mission
    if not mission:
        return

    lines.append("")
    lines.append("Mission Context (MbCRA):")

    biz_func = mission.get("business_function", "")
    if biz_func:
        lines.append(f"  Business function: {biz_func}")

    criticality = mission.get("criticality", "")
    if criticality:
        lines.append(f"  Criticality: {criticality}")

    revenue = mission.get("revenue_impact", "")
    if revenue:
        lines.append(f"  Revenue impact if down: {revenue}")

    users = mission.get("users_affected", "")
    if users:
        lines.append(f"  Users affected: {users}")

    # SLA requirements
    slas = mission.get("sla_requirements", [])
    if isinstance(slas, list) and slas:
        lines.append("  SLA requirements:")
        for sla in slas:
            if isinstance(sla, dict):
                lines.append(f"    {sla.get('partner', '?')}: uptime {sla.get('uptime', '?')}, penalty {sla.get('penalty', '?')}")

    # Recovery objectives
    recovery = mission.get("recovery_objectives", {})
    if isinstance(recovery, dict):
        rto = recovery.get("rto", "")
        rpo = recovery.get("rpo", "")
        if rto or rpo:
            lines.append(f"  Recovery: RTO={rto}, RPO={rpo}")

    # Dependencies
    deps = mission.get("dependencies", [])
    if isinstance(deps, list) and deps:
        lines.append("  Critical dependencies:")
        for dep in deps:
            if isinstance(dep, dict):
                lines.append(f"    {dep.get('system', '?')} ({dep.get('criticality', '?')}): {dep.get('impact_if_unavailable', '')}")

    # Mission impact scenarios
    scenarios = mission.get("mission_impact_scenarios", {})
    if isinstance(scenarios, dict) and scenarios:
        lines.append("  Mission impact scenarios:")
        for scenario_type, details in scenarios.items():
            if isinstance(details, dict):
                lines.append(f"    {scenario_type}:")
                lines.append(f"      Impact: {details.get('business_impact', '?')}")
                lines.append(f"      Estimated cost: {details.get('estimated_cost', '?')}")
                stakeholders = details.get("affected_stakeholders", [])
                if isinstance(stakeholders, list):
                    lines.append(f"      Stakeholders: {', '.join(str(s) for s in stakeholders)}")


def _format_findings_summary(findings: list[Finding]) -> str:
    lines: list[str] = []
    for f in findings:
        controls = ", ".join(f.control_ids) if f.control_ids else "unmapped"
        pkg_info = f" ({f.package} {f.installed_version})" if f.package else ""
        lines.append(f"- [{f.severity.upper()}] {f.source}: {f.message}{pkg_info} ({f.file}:{f.line}) → {controls}")
    return "\n".join(lines) if lines else "No findings."


def _format_controls_summary(controls: list[Control]) -> str:
    lines: list[str] = []
    for c in controls:
        lines.append(f"- {c.id}: {c.title} ({c.framework})")
    return "\n".join(lines) if lines else "No controls."


def build_categorization_prompt(manifest: ProductManifest) -> str:
    """Build categorization prompt from product manifest."""
    return CATEGORIZATION_PROMPT.format(
        name=manifest.name,
        description=manifest.description,
        data_classification=", ".join(manifest.data_classification),
        jurisdiction=", ".join(manifest.jurisdiction),
        architecture_context=_format_architecture_context(manifest),
    )


def build_assessment_prompt(
    *,
    manifest: ProductManifest,
    findings: list[Finding],
    controls: list[Control],
    risk_tier: RiskTier,
    risk_score: float,
    trigger: str,
) -> str:
    """Build assessment prompt from findings, controls, and full architecture context."""
    return ASSESSMENT_PROMPT.format(
        product_name=manifest.name,
        tier=risk_tier.value,
        trigger=trigger,
        data_classification=", ".join(manifest.data_classification),
        jurisdiction=", ".join(manifest.jurisdiction),
        architecture_context=_format_architecture_context(manifest),
        n_findings=len(findings),
        findings_summary=_format_findings_summary(findings),
        n_controls=len(controls),
        controls_summary=_format_controls_summary(controls),
        risk_score=risk_score,
    )
