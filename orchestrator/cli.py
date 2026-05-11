"""CLI entry point — thin wiring layer over existing modules."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
import yaml

from orchestrator.assessor.interface import RiskAssessor
from orchestrator.assessor.static import StaticRiskAssessor
from orchestrator.config.manifest import load_manifest
from orchestrator.config.profile import load_profile
from orchestrator.controls.baseline import select_baseline
from orchestrator.controls.repository import ControlsRepository
from orchestrator.evidence.export import EvidenceExporter
from orchestrator.evidence.jsonl import JsonlWriter
from orchestrator.gate.threshold import ThresholdEvaluator
from orchestrator.rmf.poam import AuthorizationEngine, POAMGenerator
from orchestrator.rmf.sar import SARGenerator
from orchestrator.rmf.static_pipeline import StaticRiskAssessmentPipeline
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.scanners.runner import ScannerRunner
from orchestrator.sigma.engine import SigmaEngine
from orchestrator.types import Finding, RiskTier

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _default_path(relative: str) -> str:
    return str(_PROJECT_ROOT / relative)


def get_assessor(controls_repo: ControlsRepository) -> RiskAssessor:
    """Return an appropriate RiskAssessor based on environment.

    - BEDROCK_MODEL_ID set + boto3 importable → BedrockRiskAssessor
    - Otherwise → StaticRiskAssessor
    """
    model_id = os.environ.get("BEDROCK_MODEL_ID")
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1")
    if model_id:
        try:
            from orchestrator.assessor.bedrock import BedrockRiskAssessor
            from orchestrator.assessor.bedrock_client import BedrockClient

            client = BedrockClient(model_id=model_id, region=region)
            return BedrockRiskAssessor(client=client)
        except Exception:
            pass
    return StaticRiskAssessor()


@click.group()
def cli() -> None:
    """Compliance-Driven AI Risk Platform"""


@cli.command()
@click.option("--output-dir", default=None, help="Base directory for product configs")
def init(output_dir: str | None) -> None:
    """Create product-manifest.yaml and risk-profile.yaml interactively."""
    base = Path(output_dir) if output_dir else _PROJECT_ROOT / "controls" / "products"

    name = click.prompt("Product name")
    description = click.prompt("Description")
    data_class = click.prompt("Data classification (comma-separated, e.g. PCI,PII-financial)")
    jurisdiction = click.prompt("Jurisdiction (comma-separated, e.g. JP,US)")
    cloud = click.prompt("Cloud provider")
    compute = click.prompt("Compute type")
    region = click.prompt("Region")

    data_classifications = [c.strip() for c in data_class.split(",")]
    jurisdictions = [j.strip() for j in jurisdiction.split(",")]

    product_dir = base / name
    product_dir.mkdir(parents=True, exist_ok=True)
    (product_dir / "risk-assessments").mkdir(exist_ok=True)

    manifest = {
        "product": {
            "name": name,
            "description": description,
            "data_classification": data_classifications,
            "jurisdiction": jurisdictions,
            "deployment": {"cloud": cloud, "compute": compute, "region": region},
            "integrations": [],
        }
    }
    manifest_path = product_dir / "product-manifest.yaml"
    manifest_path.write_text(yaml.dump(manifest, default_flow_style=False))

    # Determine risk tier
    from orchestrator.config.manifest import load_manifest as _load

    loaded = _load(str(manifest_path))
    assessor = StaticRiskAssessor()
    tier = assessor.categorize(loaded)

    # Generate risk profile based on tier
    if tier in (RiskTier.CRITICAL, RiskTier.HIGH):
        action = "block"
    else:
        action = "proceed"

    profile = {
        "risk_profile": {
            "frameworks": ["pci-dss-4.0"] if "PCI" in data_class.upper() else ["asvs-4.0.3-L3"],
            "risk_appetite": "conservative" if tier in (RiskTier.CRITICAL, RiskTier.HIGH) else "moderate",
            "thresholds": {
                "critical": {"max_critical_findings": 0, "max_secrets_detected": 0, "action": action},
                "high": {"max_critical_findings": 0, "action": action},
                "medium": {"max_high_findings": 5, "action": "proceed"},
                "low": {"action": "proceed"},
            },
            "failure_policy": {
                "critical": {"scan_failure": "block"},
                "high": {"scan_failure": "block"},
                "medium": {"scan_failure": "proceed"},
                "low": {"scan_failure": "proceed"},
            },
        }
    }
    (product_dir / "risk-profile.yaml").write_text(yaml.dump(profile, default_flow_style=False))

    click.echo(f"Product: {name} | Tier: {tier.value}")
    click.echo(f"Created: {manifest_path}")
    click.echo(f"Created: {product_dir / 'risk-profile.yaml'}")


@cli.command()
@click.argument("target_path")
@click.option("--product", required=True, help="Product name")
@click.option("--controls-dir", default=None, help="Controls baselines directory")
@click.option("--tier-mappings", default=None, help="Path to tier-mappings.yaml")
@click.option("--output-jsonl", default=None, help="JSONL output path")
def scan(
    target_path: str,
    product: str,
    controls_dir: str | None,
    tier_mappings: str | None,
    output_jsonl: str | None,
) -> None:
    """Scan target_path and record findings to JSONL."""
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    mapper = ControlMapper(repo)
    scanners = _build_scanners(mapper)
    runner = ScannerRunner(scanners)
    findings = runner.run_all(target_path)

    # Tag findings with product name
    for f in findings:
        f.product = product

    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    click.echo(f"[scan] {len(findings)} findings recorded to {jsonl_path}")


@cli.command()
@click.argument("target_path")
@click.option("--product", required=True, help="Product name")
@click.option("--trigger", default="pre_merge", type=click.Choice(["pre_merge", "pre_deploy", "periodic"]))
@click.option("--controls-dir", default=None)
@click.option("--tier-mappings", default=None)
@click.option("--product-dir", default=None)
@click.option("--output-jsonl", default=None)
@click.option("--retry", is_flag=True, default=False, help="Enable retry with failure policy")
@click.option("--force-override", is_flag=True, default=False, help="Override a scan failure block")
@click.option("--override-reason", default=None, help="Predefined override reason category")
@click.option("--override-justification", default=None, help="Free text explanation for override")
def assess(
    target_path: str,
    product: str,
    trigger: str,
    controls_dir: str | None,
    tier_mappings: str | None,
    product_dir: str | None,
    output_jsonl: str | None,
    retry: bool,
    force_override: bool,
    override_reason: str | None,
    override_justification: str | None,
) -> None:
    """Run full risk assessment: scan + gate + risk report.

    Exit code 0 = gate passed, 1 = gate blocked.
    """
    prod_dir = Path(product_dir) if product_dir else _PROJECT_ROOT / "controls" / "products" / product
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    # [1/4] Load configuration
    manifest = load_manifest(str(prod_dir / "product-manifest.yaml"))
    profile = load_profile(str(prod_dir / "risk-profile.yaml"))

    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    assessor = get_assessor(repo)
    tier = assessor.categorize(manifest)
    controls = select_baseline(repo, manifest, tier)
    frameworks = ", ".join(profile.frameworks)

    click.echo("[1/4] Loading configuration")
    click.echo(f"      Product: {product} | Tier: {tier.value} | Frameworks: {frameworks}")

    # [2/4] Run scanners
    click.echo("[2/4] Running scanners")
    mapper = ControlMapper(repo)
    scanners = _build_scanners(mapper)

    retry_results = None
    if retry:
        from orchestrator.resilience.retry import RetryConfig

        runner_obj = ScannerRunner(scanners, retry_config=RetryConfig())
        findings, retry_results = runner_obj.run_all_with_retry(target_path)
    else:
        runner_obj = ScannerRunner(scanners)
        findings = runner_obj.run_all(target_path)

    for f in findings:
        f.product = product

    # Summarize per scanner
    scanner_counts: dict[str, dict[str, int]] = {}
    for f in findings:
        sc = scanner_counts.setdefault(f.source, {})
        sc[f.severity] = sc.get(f.severity, 0) + 1

    for src, sevs in scanner_counts.items():
        total = sum(sevs.values())
        detail = ", ".join(f"{v} {k}" for k, v in sorted(sevs.items()))
        click.echo(f"      {src}: {total} findings ({detail})")

    if not findings:
        click.echo("      No findings")

    # [2.5/4] Failure policy evaluation (only when retry is enabled)
    if retry and retry_results is not None:
        from orchestrator.resilience.failure import FailureHandler
        from orchestrator.resilience.override import OverrideManager

        handler = FailureHandler(profile)
        decision = handler.handle(retry_results, tier)

        failed = decision.failed_scanners
        if failed:
            click.echo("[2.5/4] Failure policy evaluation")
            click.echo(f"      Failed scanners: {', '.join(failed)}")
            click.echo(f"      Tier: {tier.value} \u2192 policy: {decision.action}")

            if decision.action == "block":
                if force_override:
                    if not override_reason:
                        click.echo("      Error: --force-override requires --override-reason")
                        sys.exit(1)

                    writer = JsonlWriter(jsonl_path)
                    mgr = OverrideManager(writer)
                    record = mgr.create_override(
                        product=product,
                        tier=tier.value,
                        failed_scanners=failed,
                        reason=override_reason,
                        justification=override_justification or "",
                        approver="force-override",
                    )
                    click.echo("      Action: OVERRIDE GRANTED")
                    click.echo(f"      Reason: {record.reason}")
                    click.echo(f"      Justification: \"{record.justification}\"")
                    click.echo(f"      SLA deadline: {record.deferred_scan_sla}")
                    click.echo(f"      Override recorded: {record.id}")
                else:
                    click.echo(f"      Action: BLOCKED \u2014 scanner failure in {tier.value} tier")
                    click.echo("      Override: use --force-override --override-reason <reason>")
                    sys.exit(1)
            else:
                # warn_and_proceed
                click.echo(f"      Action: {decision.action} \u2014 {decision.reason}")

    # SBOM generation (supply chain evidence)
    try:
        from orchestrator.scanners.sbom import SbomGenerator

        sbom_gen = SbomGenerator()
        sbom_result = sbom_gen.generate(target_path, str(_PROJECT_ROOT / "output"))
        sbom_control_ids = mapper.map_finding("sbom", "sbom-generated")
        # Ensure control_ids is a real list (not a mock)
        if not isinstance(sbom_control_ids, list):
            sbom_control_ids = []
        findings.append(
            Finding(
                source="sbom",
                rule_id="sbom-generated",
                severity="info",
                file=sbom_result.sbom_path,
                line=0,
                message=f"CycloneDX SBOM generated: {sbom_result.components_count} components",
                control_ids=sbom_control_ids,
                product=product,
            )
        )
    except Exception:
        pass  # SBOM generation is optional (syft may not be installed)

    # Write findings to JSONL
    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    # Evidence path: optionally sync to DefectDojo (after JSONL, before gate)
    try:
        from orchestrator.integrations.defectdojo import DefectDojoClient

        dd_url = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080")
        dd_key = os.environ.get("DD_API_KEY", "")
        if dd_key:
            dd = DefectDojoClient(base_url=dd_url, api_key=dd_key)
            if dd.health_check():
                product_id = dd.get_or_create_product(product)
                engagement_id = dd.get_or_create_engagement(product_id, f"assess-{trigger}")
                dd.import_findings(engagement_id, findings)
                click.echo(f"      DefectDojo: {len(findings)} findings synced")
    except Exception:
        pass  # DefectDojo is optional (evidence path only)

    # [3/4] Gate evaluation — two additive layers (YAML + OPA)
    from orchestrator.gate.combined import CombinedGateEvaluator
    from orchestrator.gate.opa import OpaEvaluator

    threshold_eval = ThresholdEvaluator(profile)
    opa_eval = OpaEvaluator(str(_PROJECT_ROOT / "rego" / "gates"))
    combined = CombinedGateEvaluator(threshold_eval, opa_eval)

    context: dict[str, object] = {
        "product": product,
        "tier": tier.value,
        "frameworks": profile.frameworks,
        "findings_count": {
            s: sum(1 for f in findings if f.severity == s)
            for s in ["critical", "high", "medium", "low"]
        },
        "pci_scope_count": sum(
            1 for f in findings if any(c.startswith("PCI-DSS") for c in f.control_ids)
        ),
        "secrets_count": sum(1 for f in findings if f.source == "gitleaks"),
    }
    gate = combined.evaluate(findings, tier, context)

    click.echo("[3/4] Gate evaluation")
    if gate.passed:
        click.echo(f"      {gate.reason}")
    else:
        click.echo(f"      {gate.reason}")

    writer.write_gate_decision(gate, product)

    # [4/4] Risk assessment
    report = assessor.assess(findings, manifest, controls, trigger)
    writer.write_risk_report(report)

    mode = "bedrock" if os.environ.get("BEDROCK_MODEL_ID") else "static"
    click.echo("[4/4] Risk assessment")
    click.echo(f"      Risk score: {report.risk_score:.1f}/10")
    click.echo(f"      Mode: {mode}")

    # Save risk assessment YAML
    ra_dir = prod_dir / "risk-assessments"
    ra_dir.mkdir(parents=True, exist_ok=True)
    ra_data = {
        "id": report.id,
        "trigger": report.trigger,
        "product": report.product,
        "risk_tier": report.risk_tier.value,
        "risk_score": report.risk_score,
        "narrative": report.narrative,
        "gate_recommendation": report.gate_recommendation,
    }
    (ra_dir / f"{report.id}.yaml").write_text(yaml.dump(ra_data, default_flow_style=False))
    click.echo(f"\nReport saved: {ra_dir / f'{report.id}.yaml'}")
    click.echo(f"Findings logged: {jsonl_path} ({len(findings)} entries)")

    if not gate.passed:
        sys.exit(1)


@cli.command("risk-assess")
@click.argument("target_path")
@click.option("--product", required=True, help="Product name")
@click.option("--trigger", default="pre_merge", type=click.Choice(["pre_merge", "pre_deploy", "periodic"]))
@click.option("--output", default="output", help="Output directory for reports")
@click.option("--format", "fmt", default="yaml", type=click.Choice(["yaml", "json"]))
def risk_assess(target_path: str, product: str, trigger: str, output: str, fmt: str) -> None:
    """Run full NIST SP 800-30 risk assessment with RMF activities.

    Produces:
    1. SP 800-30 Risk Assessment Report
    2. Security Assessment Report (SAR)
    3. Plan of Action & Milestones (POA&M)
    4. Authorization Decision (ATO/DATO/ATO-with-conditions)
    """
    import json as json_mod
    from dataclasses import asdict
    from typing import Any

    from orchestrator.gate.combined import CombinedGateEvaluator
    from orchestrator.gate.opa import OpaEvaluator
    from orchestrator.intelligence.models import EnrichedVulnerability

    prod_dir = _PROJECT_ROOT / "controls" / "products" / product
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    ext = "json" if fmt == "json" else "yaml"

    # [1/8] Load configuration
    click.echo("[1/8] Loading configuration")
    manifest = load_manifest(str(prod_dir / "product-manifest.yaml"))
    profile = load_profile(str(prod_dir / "risk-profile.yaml"))

    repo = ControlsRepository(
        baselines_dir=str(_PROJECT_ROOT / "controls" / "baselines"),
        tier_mappings_path=str(_PROJECT_ROOT / "controls" / "tier-mappings.yaml"),
    )
    repo.load_all()

    assessor = get_assessor(repo)
    tier = assessor.categorize(manifest)
    controls = select_baseline(repo, manifest, tier)

    cia = manifest.impact_levels
    click.echo(f"      Product: {product} | Tier: {tier.value}")
    click.echo(
        f"      CIA: C={cia.get('confidentiality', 'moderate')} "
        f"I={cia.get('integrity', 'moderate')} "
        f"A={cia.get('availability', 'moderate')}"
    )

    # [2/8] Running scanners + EPSS
    click.echo("\n[2/8] Running scanners + EPSS")
    mapper = ControlMapper(repo)
    scanners = _build_scanners(mapper)
    runner = ScannerRunner(scanners)
    findings = runner.run_all(target_path)
    for f in findings:
        f.product = product

    # EPSS enrichment (best-effort)
    enriched_vulns: list[EnrichedVulnerability] = []
    cve_findings = [f for f in findings if f.rule_id.startswith("CVE-")]
    epss_enriched_count = 0
    try:
        from orchestrator.intelligence.enricher import VulnerabilityEnricher
        from orchestrator.intelligence.epss import EpssClient

        epss_client = EpssClient()
        enricher = VulnerabilityEnricher(epss_client, mapper)
        enriched_vulns = enricher.enrich(findings, manifest)
        epss_enriched_count = sum(1 for v in enriched_vulns if v.epss_score is not None)
    except Exception:
        pass

    click.echo(f"      Findings: {len(findings)} | EPSS enriched: {epss_enriched_count}/{len(cve_findings)}")

    # [3/8] SP 800-30 Risk Assessment
    import time as _time

    model_id = os.environ.get("BEDROCK_MODEL_ID")
    use_ai = False
    if model_id:
        try:
            from orchestrator.assessor.bedrock_client import BedrockClient as _BC
            from orchestrator.rmf.pipeline import RiskAssessmentPipeline

            bc = _BC(model_id=model_id, region=os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1"))
            pipeline = RiskAssessmentPipeline(bedrock_client=bc)
            use_ai = True
            click.echo("\n[3/8] SP 800-30 Risk Assessment (AI mode — Bedrock)")
        except Exception:
            pipeline = StaticRiskAssessmentPipeline()  # type: ignore[assignment]
            click.echo("\n[3/8] SP 800-30 Risk Assessment (static mode — Bedrock failed)")
    else:
        pipeline = StaticRiskAssessmentPipeline()  # type: ignore[assignment]
        click.echo("\n[3/8] SP 800-30 Risk Assessment (static mode)")

    def _progress(completed: int, total: int, finding_id: str) -> None:
        click.echo(f"      [{completed}/{total}] {finding_id} assessed")

    t0 = _time.monotonic()
    sp800_report = pipeline.run(
        findings=findings,
        enriched_vulns=enriched_vulns,
        manifest=manifest,
        controls=controls,
        trigger=trigger,
        progress_callback=_progress if use_ai else None,
    )
    duration = _time.monotonic() - t0

    click.echo(f"      Threat sources: {len(sp800_report.threat_sources)} identified")
    click.echo(f"      Threat events: {len(sp800_report.threat_events)} identified")
    if sp800_report.risk_determinations:
        click.echo("      Risk determinations:")
        level_counts: dict[str, int] = {}
        for rd in sp800_report.risk_determinations:
            level_counts[rd.risk_level.upper()] = level_counts.get(rd.risk_level.upper(), 0) + 1
        for level, count in sorted(level_counts.items()):
            click.echo(f"        {level}: {count}")

    # Gate evaluation (needed for SAR + Authorization)
    threshold_eval = ThresholdEvaluator(profile)
    opa_eval = OpaEvaluator(str(_PROJECT_ROOT / "rego" / "gates"))
    combined = CombinedGateEvaluator(threshold_eval, opa_eval)
    context: dict[str, object] = {
        "product": product,
        "tier": tier.value,
        "frameworks": profile.frameworks,
        "findings_count": {
            s: sum(1 for f in findings if f.severity == s)
            for s in ["critical", "high", "medium", "low"]
        },
        "pci_scope_count": sum(
            1 for f in findings if any(c.startswith("PCI-DSS") for c in f.control_ids)
        ),
        "secrets_count": sum(1 for f in findings if f.source == "gitleaks"),
    }
    gate = combined.evaluate(findings, tier, context)

    # [4/8] Security Assessment Report (SAR)
    click.echo("\n[4/8] Security Assessment Report (SAR)")
    sar_gen = SARGenerator(repo)
    sar = sar_gen.generate(
        product=product,
        findings=findings,
        gate_decision=gate,
        risk_report=sp800_report,
    )
    click.echo(f"      Controls assessed: {sar.total_controls}")
    click.echo(f"      Satisfied: {sar.satisfied}")
    click.echo(f"      Other-than-satisfied: {sar.other_than_satisfied}")
    click.echo(f"      Not assessed: {sar.not_assessed}")
    click.echo(f"      Coverage: {sar.coverage_percentage}%")

    # [5/8] Plan of Action & Milestones (POA&M)
    click.echo("\n[5/8] Plan of Action & Milestones (POA&M)")
    poam_gen = POAMGenerator()
    poam_items = poam_gen.generate(
        findings=findings,
        risk_report=sp800_report,
        gate_decision=gate,
    )

    deadline_counts: dict[str, int] = {}
    for item in poam_items:
        label = f"{item.severity}"
        deadline_counts[label] = deadline_counts.get(label, 0) + 1

    click.echo(f"      Items created: {len(poam_items)}")
    for label, count in sorted(deadline_counts.items()):
        click.echo(f"        {label}: {count}")

    # [6/8] Authorization Decision
    click.echo("\n[6/8] Authorization Decision")
    auth_engine = AuthorizationEngine()
    auth_decision = auth_engine.decide(
        gate_decision=gate,
        poam_items=poam_items,
    )
    click.echo(f"      Decision: {auth_decision.decision}")
    click.echo(f"      Reason: {auth_decision.reasoning}")

    # [7/8] Export reports (YAML)
    click.echo("\n[7/8] Reports exported (YAML)")

    def _serialize(obj: Any) -> dict[str, Any]:
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        return {}

    def _write_report(name: str, data: dict[str, Any]) -> None:
        path = output_dir / f"{name}-{product}.{ext}"
        if fmt == "json":
            path.write_text(json_mod.dumps(data, indent=2, default=str))
        else:
            path.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False))
        click.echo(f"      {path}")

    _write_report("sp800-30", _serialize(sp800_report))
    _write_report("sar", _serialize(sar))
    _write_report("poam", {
        "product": product,
        "total_items": len(poam_items),
        "items": [_serialize(item) for item in poam_items],
    })
    _write_report("authorization", _serialize(auth_decision))

    # [8/8] Dashboard export (JSON)
    click.echo("\n[8/8] Dashboard exported (JSON)")
    pipeline_metadata = {
        "scanners": list({f.source for f in findings}),
        "ai_model": model_id or "static",
        "duration_seconds": round(duration, 1),
    }
    try:
        from orchestrator.exporters.dashboard import export_dashboard

        written = export_dashboard(
            report=sp800_report,
            sar=sar,
            poam_items=poam_items,
            authorization=auth_decision,
            output_dir=str(output_dir),
            pipeline_metadata=pipeline_metadata,
        )
        for p in written:
            click.echo(f"      {p}")
    except Exception as exc:
        click.echo(f"      WARNING: dashboard export failed: {exc}", err=True)

    click.echo("\n\u2713 RMF assessment complete.")


@cli.command(name="export")
@click.option("--product", required=True)
@click.option("--control-id", default=None)
@click.option("--period", default=None)
@click.option("--output", default="output/evidence")
@click.option("--jsonl-path", default=None)
@click.option("--controls-dir", default=None)
@click.option("--tier-mappings", default=None)
def export_cmd(
    product: str,
    control_id: str | None,
    period: str | None,
    output: str,
    jsonl_path: str | None,
    controls_dir: str | None,
    tier_mappings: str | None,
) -> None:
    """Generate evidence report as JSON."""
    jpath = jsonl_path or _default_path("output/findings.jsonl")
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")

    reader = JsonlWriter(jpath)
    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    # Optionally use DefectDojo as data source
    dd_client = None
    try:
        dd_key = os.environ.get("DD_API_KEY", "")
        if dd_key:
            from orchestrator.integrations.defectdojo import DefectDojoClient

            dd_url = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080")
            dd_client = DefectDojoClient(base_url=dd_url, api_key=dd_key)
    except Exception:
        pass

    exporter = EvidenceExporter(jsonl_reader=reader, controls_repo=repo, defectdojo_client=dd_client)
    report = exporter.export(product=product, control_id=control_id, period=period, output_path=output)

    click.echo(f"Evidence report: {output}/{report['report_id']}.json")
    summary = report["summary"]
    click.echo(
        f"Coverage: {summary['coverage_percentage']}% "
        f"({summary['fully_evidenced']} full, "
        f"{summary['partially_evidenced']} partial, "
        f"{summary['no_evidence']} none)"
    )

    # Executive summary: findings by control
    exec_summary = report.get("executive_summary", {})
    if exec_summary:
        click.echo(f"\nFindings: {exec_summary['total_findings']} total, "
                    f"{exec_summary['mapped_to_controls']} mapped to controls, "
                    f"{exec_summary['unmapped_findings']} unmapped")
        click.echo("\nControl evidence:")
        for cs in exec_summary.get("controls", []):
            icon = {"full": "[OK]", "partial": "[!!]", "none": "[  ]"}.get(cs["status"], "[??]")
            sev = ", ".join(f"{v} {k}" for k, v in cs["severity_distribution"].items()) if cs["severity_distribution"] else "—"
            click.echo(f"  {icon} {cs['control_id']:<20} {cs['findings_count']:>4} findings  ({sev})")


@cli.command()
@click.argument("log_path")
@click.option("--product", default="")
@click.option("--rules-dir", default=None)
@click.option("--output-jsonl", default=None)
def detect(log_path: str, product: str, rules_dir: str | None, output_jsonl: str | None) -> None:
    """Analyze log file with Sigma rules."""
    rdir = rules_dir or _default_path("sigma/rules")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    engine = SigmaEngine(rdir)
    engine.load_rules()

    matches = engine.evaluate_log_file(log_path)

    if matches:
        writer = JsonlWriter(jsonl_path)
        findings = [m.to_finding(product=product) for m in matches]
        writer.write_findings(findings)

        for m in matches:
            tags = ", ".join(m.rule.tags) if m.rule.tags else "none"
            cids = ", ".join(m.rule.control_ids) if m.rule.control_ids else "none"
            click.echo(f"  [{m.rule.level}] {m.rule.title} | ATT&CK: {tags} | Controls: {cids}")

        click.echo(f"\n{len(matches)} matches found, logged to {jsonl_path}")
    else:
        click.echo("No matches found.")


@cli.command("sbom")
@click.argument("target")
@click.option("--output-dir", default="output", help="Directory to store SBOM file")
def sbom_cmd(target: str, output_dir: str) -> None:
    """Generate CycloneDX SBOM from a directory or container image."""
    from orchestrator.scanners.sbom import SbomGenerationError, SbomGenerator

    generator = SbomGenerator()
    try:
        result = generator.generate(target, output_dir)
        click.echo(f"SBOM generated: {result.sbom_path}")
        click.echo(f"Components: {result.components_count}")
        click.echo(f"Format: {result.format}")
    except SbomGenerationError as e:
        click.echo(f"SBOM generation failed: {e}", err=True)
        sys.exit(1)


@cli.command("container-scan")
@click.argument("image_ref")
@click.option("--product", required=True, help="Product name")
@click.option("--controls-dir", default=None)
@click.option("--tier-mappings", default=None)
@click.option("--output-jsonl", default=None)
def container_scan(
    image_ref: str,
    product: str,
    controls_dir: str | None,
    tier_mappings: str | None,
    output_jsonl: str | None,
) -> None:
    """Scan a container image for vulnerabilities using Grype."""
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    mapper = ControlMapper(repo)

    from orchestrator.scanners.grype import GrypeScanner

    grype = GrypeScanner(mapper)
    findings = grype.scan_image(image_ref)

    for f in findings:
        f.product = product

    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    click.echo(f"[container-scan] Image: {image_ref}")
    click.echo(f"[container-scan] {len(findings)} vulnerabilities found")
    for sev, count in sorted(severity_counts.items()):
        click.echo(f"  {sev}: {count}")
    click.echo(f"[container-scan] Findings logged to {jsonl_path}")


@cli.command()
@click.option("--product", required=True)
@click.option("--defectdojo-url", default="http://127.0.0.1:8080")
@click.option("--api-key", envvar="DD_API_KEY")
@click.option("--jsonl-path", default=None)
def sync(product: str, defectdojo_url: str, api_key: str | None, jsonl_path: str | None) -> None:
    """Sync JSONL findings to DefectDojo."""
    from orchestrator.integrations.defectdojo import DefectDojoClient

    jpath = jsonl_path or _default_path("output/findings.jsonl")

    if not api_key:
        click.echo("Error: --api-key or DD_API_KEY required", err=True)
        sys.exit(1)

    client = DefectDojoClient(base_url=defectdojo_url, api_key=api_key)

    if not client.health_check():
        click.echo(f"Warning: DefectDojo not reachable at {defectdojo_url}. Skipping sync.", err=True)
        click.echo("JSONL findings remain as backup (ADR-003).")
        return

    reader = JsonlWriter(jpath)
    entries = reader.read_findings(product=product)

    if not entries:
        click.echo(f"No findings for product '{product}' in {jpath}")
        return

    # Convert JSONL entries back to Finding objects
    findings: list[Finding] = []
    for entry in entries:
        data = entry.get("data", {})
        findings.append(
            Finding(
                source=data.get("source", ""),
                rule_id=data.get("rule_id", ""),
                severity=data.get("severity", ""),
                file=data.get("file", ""),
                line=data.get("line", 0),
                message=data.get("message", ""),
                control_ids=data.get("control_ids", []),
                product=data.get("product", ""),
            )
        )

    product_id = client.get_or_create_product(product)
    engagement_id = client.get_or_create_engagement(product_id, "pipeline-scan")
    result = client.import_findings(engagement_id, findings)

    click.echo(f"[sync] Synced {len(findings)} findings to DefectDojo")
    click.echo(f"       Product: {product} (id={product_id})")
    click.echo(f"       Created: {result['created']}, Skipped: {result['skipped']}, Errors: {result['errors']}")


@cli.command()
@click.option("--product", default=None, help="Filter by product name")
@click.option("--jsonl-path", default=None, help="JSONL path for override records")
def status(product: str | None, jsonl_path: str | None) -> None:
    """Show pending overrides and SLA status."""
    from orchestrator.resilience.override import OverrideManager

    jpath = jsonl_path or _default_path("output/findings.jsonl")
    writer = JsonlWriter(jpath)
    mgr = OverrideManager(writer)

    overrides = mgr.get_pending_overrides(product=product)

    if not overrides:
        click.echo("No pending overrides.")
        return

    click.echo("Pending overrides:")
    for o in overrides:
        click.echo(f"  {o.id} | {o.product} | {o.reason} | SLA: {o.deferred_scan_sla}")


@cli.command("threat-model")
@click.argument("target_path")
@click.option("--product", required=True)
@click.option("--output", default="output", help="Output directory")
def threat_model_cmd(target_path: str, product: str, output: str) -> None:
    """Generate threat model from real application components.

    Analyzes SBOM components + CVEs + product context to produce
    a threat model with concrete attack scenarios.
    """
    from orchestrator.intelligence.enricher import VulnerabilityEnricher
    from orchestrator.intelligence.epss import EpssClient
    from orchestrator.intelligence.threat_model import StaticThreatModelGenerator
    from orchestrator.scanners.grype import GrypeScanner
    from orchestrator.scanners.sbom import SbomGenerator

    # Load product manifest + controls
    prod_dir = _PROJECT_ROOT / "controls" / "products" / product
    manifest = load_manifest(str(prod_dir / "product-manifest.yaml"))

    baselines = _default_path("controls/baselines")
    mappings = _default_path("controls/tier-mappings.yaml")
    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    assessor = StaticRiskAssessor()
    tier = assessor.categorize(manifest)
    controls = select_baseline(repo, manifest, tier)

    mapper = ControlMapper(repo)

    # [1/4] SBOM generation
    click.echo("[1/4] SBOM generation")
    sbom_gen = SbomGenerator()
    sbom_result = sbom_gen.generate(target_path, output)
    raw_components = sbom_result.raw_sbom.get("components", [])
    components: list[dict[str, object]] = (
        raw_components if isinstance(raw_components, list) else []
    )
    component_names = [
        f"{c.get('name', '?')} {c.get('version', '?')}"
        for c in components
        if isinstance(c, dict)
    ]
    click.echo(f"      Components: {sbom_result.components_count}")

    # [2/4] Vulnerability scan + EPSS enrichment
    click.echo("[2/4] Vulnerability scan + EPSS enrichment")
    grype = GrypeScanner(mapper)
    findings = grype.scan(target_path)

    epss_client = EpssClient()
    enricher = VulnerabilityEnricher(epss_client, mapper)
    enriched = enricher.enrich(findings, manifest)
    enriched = enricher.sort_by_priority(enriched)

    epss_enriched = sum(1 for v in enriched if v.epss_score is not None)
    epss_critical = sum(1 for v in enriched if v.epss_score is not None and v.epss_score > 0.5)
    epss_high = sum(
        1 for v in enriched
        if v.epss_score is not None and 0.1 < v.epss_score <= 0.5
    )

    click.echo(f"      CVEs found: {len(findings)}")
    click.echo(f"      EPSS enriched: {epss_enriched}/{len(findings)}")
    click.echo(f"      CRITICAL (EPSS > 0.5): {epss_critical}")
    click.echo(f"      HIGH (EPSS > 0.1): {epss_high}")

    # [3/4] Threat model generation
    click.echo("[3/4] Threat model generation")
    generator = StaticThreatModelGenerator()
    threat_model = generator.generate(
        manifest=manifest,
        sbom_components=component_names,
        enriched_vulns=enriched,
        controls=controls,
    )

    click.echo(f"      Mode: {threat_model.mode}")
    click.echo(f"      Attack surface: {threat_model.attack_surface_summary}")
    click.echo(f"      Threat actors: {len(threat_model.threat_actors)}")
    click.echo(f"      Threat scenarios: {len(threat_model.threat_scenarios)}")

    # [4/4] Controls gap analysis
    click.echo("[4/4] Controls gap analysis")
    click.echo(f"      Required by threat model: {len(threat_model.controls_required)} controls")
    click.echo(f"      Currently covered: {len(threat_model.controls_covered)} controls")
    click.echo(f"      Gap: {len(threat_model.controls_gap)} controls")
    for gap_id in threat_model.controls_gap:
        click.echo(f"        - {gap_id}")

    # Write YAML output
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    yaml_file = output_path / f"threat-model-{product}.yaml"
    yaml_file.write_text(threat_model.to_yaml())

    click.echo(f"\nThreat model saved: {yaml_file}")


@cli.command("import-framework")
@click.argument("source")
@click.option("--framework-id", required=True, help="Framework identifier (e.g., cmmc-2.0-L2)")
@click.option("--format", "fmt", default="oscal", type=click.Choice(["oscal", "asvs-json", "generic-json"]))
@click.option("--output", default=None, help="Output YAML path (default: controls/baselines/{framework-id}.yaml)")
@click.option("--suggest-scanners/--no-suggest-scanners", default=True, help="Auto-suggest scanner mappings via keyword matching")
@click.option("--tiers", default="high,critical", help="Applicable tiers (comma-separated)")
def import_framework(
    source: str,
    framework_id: str,
    fmt: str,
    output: str | None,
    suggest_scanners: bool,
    tiers: str,
) -> None:
    """Import a compliance framework and generate baseline YAML.

    SOURCE can be a local file path or a URL.

    Examples:
      orchestrator import-framework ./nist-800-53-catalog.json --framework-id nist-800-53-r5

      orchestrator import-framework https://raw.githubusercontent.com/... --framework-id nist-800-53-r5

      orchestrator import-framework ./asvs.json --framework-id asvs-4.0.3-L2 --format asvs-json

      orchestrator import-framework ./cmmc.json --framework-id cmmc-2.0-L2 --no-suggest-scanners
    """
    from orchestrator.importer.baseline import BaselineGenerator
    from orchestrator.importer.oscal import OscalParser
    from orchestrator.importer.generic import GenericFrameworkParser
    from orchestrator.importer.suggest import ScannerSuggester

    tier_list = [t.strip() for t in tiers.split(",")]
    output_path = output or _default_path(f"controls/baselines/{framework_id}.yaml")

    # [1/3] Parse source
    click.echo("[1/3] Parsing source")
    click.echo(f"      Source: {source}")
    click.echo(f"      Format: {fmt}")

    is_url = source.startswith("http://") or source.startswith("https://")

    if fmt == "oscal":
        parser = OscalParser()
        if is_url:
            controls = parser.parse_url(source, framework_id)
        else:
            controls = parser.parse_file(source, framework_id)
    elif fmt == "asvs-json":
        gp = GenericFrameworkParser()
        controls = gp.parse_asvs_json(source, level=3)
    else:
        gp = GenericFrameworkParser()
        controls = gp.parse_generic_json(source, framework_id=framework_id)

    click.echo(f"      Controls found: {len(controls)}")

    # [2/3] Generate baseline YAML
    click.echo("[2/3] Generating baseline YAML")
    click.echo(f"      Output: {output_path}")
    click.echo(f"      Applicable tiers: {', '.join(tier_list)}")

    if suggest_scanners:
        # Generate with suggestions via ScannerSuggester
        suggester = ScannerSuggester()
        suggested, unmapped = suggester.apply_suggestions(controls, output_path)

        # Patch applicable_tiers into the generated YAML
        data = yaml.safe_load(Path(output_path).read_text())
        for entry in data["controls"]:
            entry["control"]["applicable_tiers"] = tier_list
        with open(output_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    else:
        gen = BaselineGenerator()
        gen.generate(controls, output_path, applicable_tiers=tier_list)
        suggested = 0
        unmapped = len(controls)

    # [3/3] Summary
    if suggest_scanners:
        click.echo("[3/3] Suggesting scanner mappings")
        click.echo(f"      Suggested: {suggested}/{len(controls)} controls (keyword match)")
        click.echo(f"      Unmapped: {unmapped}/{len(controls)} controls (manual review needed)")

        # Count per scanner
        data = yaml.safe_load(Path(output_path).read_text())
        scanner_counts: dict[str, int] = {}
        for entry in data["controls"]:
            for vm in entry["control"].get("verification_methods", []):
                sc = vm.get("scanner", "unknown")
                scanner_counts[sc] = scanner_counts.get(sc, 0) + 1

        if scanner_counts:
            click.echo("")
            click.echo("      Suggested mappings:")
            for sc, count in sorted(scanner_counts.items()):
                click.echo(f"        {sc}: {count} controls")

    click.echo("")
    click.echo(f"Baseline generated: {output_path}")
    click.echo("")
    click.echo("IMPORTANT: Scanner mappings are SUGGESTIONS based on keyword matching.")
    click.echo("  A security engineer must review and approve each mapping before use.")
    if unmapped > 0:
        click.echo(f"  {unmapped} controls have no suggested mapping and need manual assignment.")
    click.echo("")
    click.echo("Next steps:")
    click.echo(f"  1. Review {output_path}")
    click.echo("  2. Verify scanner mappings are correct")
    click.echo("  3. Add framework to controls/compliance-mappings.yaml")
    click.echo("  4. Add framework to controls/tier-mappings.yaml")
    click.echo("  5. Run: orchestrator assess ./your-app --product your-product")


@cli.command()
@click.argument("target_path")
@click.option("--product", default="payment-api")
def demo(target_path: str, product: str) -> None:
    """Run the full MVP-0 demo."""
    from orchestrator.demo import run_demo

    run_demo(target_path, product)


def _build_scanners(mapper: ControlMapper) -> list:  # type: ignore[type-arg]
    """Build scanner instances. Imported lazily to avoid hard dep on CLI tools at import time."""
    from orchestrator.scanners.checkov import CheckovScanner
    from orchestrator.scanners.gitleaks import GitleaksScanner
    from orchestrator.scanners.grype import GrypeScanner
    from orchestrator.scanners.semgrep import SemgrepScanner

    return [
        CheckovScanner(mapper),
        SemgrepScanner(mapper),
        GrypeScanner(mapper),
        GitleaksScanner(mapper),
    ]
