"""MVP-0 E2E demo — wires existing modules into a single flow."""

from __future__ import annotations

import os
from pathlib import Path

import click
import yaml

from orchestrator.cli import get_assessor
from orchestrator.config.manifest import load_manifest
from orchestrator.config.profile import load_profile
from orchestrator.controls.baseline import select_baseline
from orchestrator.controls.repository import ControlsRepository
from orchestrator.evidence.export import EvidenceExporter
from orchestrator.evidence.jsonl import JsonlWriter
from orchestrator.gate.threshold import ThresholdEvaluator
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.scanners.runner import ScannerRunner
from orchestrator.scanners.sbom import SbomGenerator
from orchestrator.sigma.engine import SigmaEngine
from orchestrator.types import Finding

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run_demo(target_path: str, product: str = "payment-api") -> None:
    """Run the full MVP-0 E2E demo.

    Flow:
    1. Load product manifest + risk profile, determine tier
    2. Select control baseline (RMF Step 3)
    3. Run all scanners (RMF Step 5)
    4. Generate SBOM + scan SBOM (supply chain)
    5. Gate evaluation (RMF Step 6)
    6. Risk assessment
    7. Sigma detection (log analysis)
    8. Evidence export
    """
    prod_dir = _PROJECT_ROOT / "controls" / "products" / product
    baselines_dir = str(_PROJECT_ROOT / "controls" / "baselines")
    tier_mappings = str(_PROJECT_ROOT / "controls" / "tier-mappings.yaml")
    output_dir = _PROJECT_ROOT / "output"
    jsonl_path = str(output_dir / "findings.jsonl")
    evidence_dir = str(output_dir / "evidence")
    log_path = Path(target_path) / "logs" / "access.jsonl"
    sigma_rules_dir = str(_PROJECT_ROOT / "sigma" / "rules")

    # ── [1/8] Load product manifest ─────────────────────────────
    click.echo(f"[1/8] Loading product manifest: {product}")
    manifest = load_manifest(str(prod_dir / "product-manifest.yaml"))
    profile = load_profile(str(prod_dir / "risk-profile.yaml"))

    repo = ControlsRepository(baselines_dir=baselines_dir, tier_mappings_path=tier_mappings)
    repo.load_all()

    assessor = get_assessor(repo)
    tier = assessor.categorize(manifest)

    data_classes = ", ".join(manifest.data_classification)
    click.echo(f"      Product: {product} | Data: {data_classes} | Tier: {tier.value}")

    # ── [2/8] Select control baseline ───────────────────────────
    click.echo("\n[2/8] Selecting control baseline (RMF Step 3: Select)")
    controls = select_baseline(repo, manifest, tier)

    fw_counts: dict[str, int] = {}
    for c in controls:
        fw_counts[c.framework] = fw_counts.get(c.framework, 0) + 1
    fw_detail = ", ".join(f"{fw} ({n})" for fw, n in sorted(fw_counts.items()))
    click.echo(f"      Frameworks applied: {fw_detail}")
    click.echo(f"      Total controls: {len(controls)}")

    # ── [3/8] Run scanners ──────────────────────────────────────
    click.echo("\n[3/8] Running scanners (RMF Step 5: Assess)")
    mapper = ControlMapper(repo)
    from orchestrator.cli import _build_scanners

    scanners = _build_scanners(mapper)
    runner = ScannerRunner(scanners)
    findings = runner.run_all(target_path)

    for f in findings:
        f.product = product

    scanner_counts: dict[str, int] = {}
    for f in findings:
        scanner_counts[f.source] = scanner_counts.get(f.source, 0) + 1

    for src in ["checkov", "semgrep", "grype", "gitleaks"]:
        count = scanner_counts.get(src, 0)
        click.echo(f"      {src.capitalize()}: {count} findings")

    # Write findings to JSONL
    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    # ── [4/8] SBOM generation + supply chain scan ─────────────
    click.echo("\n[4/8] SBOM generation (supply chain)")
    sbom_generator = SbomGenerator()
    try:
        sbom_result = sbom_generator.generate(target_path, str(output_dir))
        click.echo(f"      SBOM: {sbom_result.components_count} components ({sbom_result.format})")

        # Scan SBOM with Grype for vulnerability analysis
        from orchestrator.scanners.grype import GrypeScanner

        grype = GrypeScanner(mapper)
        sbom_findings = grype.scan_sbom(sbom_result.sbom_path)
        for f in sbom_findings:
            f.product = product
        findings.extend(sbom_findings)
        click.echo(f"      SBOM scan: {len(sbom_findings)} vulnerabilities")

        # Register SBOM generation as evidence (maps to PCI-DSS-6.3.2)
        sbom_evidence = Finding(
            source="sbom",
            rule_id="sbom-generated",
            severity="info",
            file=sbom_result.sbom_path,
            line=0,
            message=f"CycloneDX SBOM generated: {sbom_result.components_count} components",
            control_ids=mapper.map_finding("sbom", "sbom-generated"),
            product=product,
        )
        findings.append(sbom_evidence)
        writer.write_findings([sbom_evidence])
        click.echo(f"      Evidence: SBOM artifact stored at {sbom_result.sbom_path}")
    except Exception:
        click.echo("      SBOM generation skipped (syft not installed or error)")

    # ── [4.5] Failure policy evaluation (shown only when scanners fail) ──
    # In demo mode, scanners run without retry. This step is displayed only
    # when scanner failures are detected (e.g. when retry is enabled externally).
    # The demo uses ScannerRunner without retry_config, so failures are captured
    # via the log-and-continue pattern. This block is a placeholder that shows
    # the failure policy step in the demo output if scanner_counts indicate missing scanners.
    expected_scanners = {"checkov", "semgrep", "grype", "gitleaks"}
    actual_scanners = set(scanner_counts.keys())
    missing_scanners = expected_scanners - actual_scanners
    if missing_scanners:
        from orchestrator.resilience.failure import FailureHandler
        from orchestrator.resilience.retry import RetryResult

        # Synthesize retry results for missing scanners
        synth_results = [
            RetryResult(scanner=s, success=False, attempts=1, total_time=0.0, error_message="scanner not available")
            for s in sorted(missing_scanners)
        ]
        handler = FailureHandler(profile)
        decision = handler.handle(synth_results, tier)
        if decision.failed_scanners:
            click.echo("\n[4.5] Failure policy evaluation")
            click.echo(f"      Failed scanners: {', '.join(decision.failed_scanners)}")
            click.echo(f"      Tier: {tier.value} \u2192 policy: {decision.action}")
            click.echo(f"      Action: {decision.reason}")

    # ── [5/8] Gate evaluation — two additive layers (YAML + OPA) ──
    click.echo("\n[5/8] Gate evaluation (RMF Step 6: Authorize)")
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
    writer.write_gate_decision(gate, product)

    if gate.passed:
        click.echo(f"      {gate.reason}")
    else:
        click.echo(f"      {gate.reason}")

    # ── [6/8] Risk assessment ───────────────────────────────────
    click.echo("\n[6/8] Risk assessment")
    report = assessor.assess(findings, manifest, controls, "pre_merge")
    writer.write_risk_report(report)

    is_ai_mode = bool(os.environ.get("BEDROCK_MODEL_ID"))
    mode = "AI-augmented (Claude Sonnet)" if is_ai_mode else "static"
    click.echo(f"      Risk score: {report.risk_score:.1f}/10")
    click.echo(f"      Mode: {mode}")

    if is_ai_mode:
        # Show AI narrative (first 200 chars to keep demo output readable)
        narrative_preview = report.narrative[:200]
        if len(report.narrative) > 200:
            narrative_preview += "..."
        click.echo(f"      Narrative: \"{narrative_preview}\"")
        if report.cross_signal_insights:
            click.echo("      Cross-signal insights:")
            for insight in report.cross_signal_insights:
                click.echo(f"        - \"{insight}\"")
        if report.recommendations:
            click.echo("      Recommendations:")
            for rec in report.recommendations:
                click.echo(f"        - \"{rec}\"")

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

    # ── [7/8] Detection analysis ────────────────────────────────
    click.echo("\n[7/8] Detection analysis")
    sigma_matches = []
    if log_path.exists():
        engine = SigmaEngine(sigma_rules_dir)
        engine.load_rules()
        sigma_matches = engine.evaluate_log_file(str(log_path))

        if sigma_matches:
            sigma_findings = [m.to_finding(product=product) for m in sigma_matches]
            writer.write_findings(sigma_findings)

        click.echo(f"      Sigma rules: {len(sigma_matches)} matches")
        tags = sorted({t for m in sigma_matches for t in m.rule.tags})
        if tags:
            click.echo(f"      ATT&CK coverage: {', '.join(t.replace('attack.', '').upper() for t in tags)}")
    else:
        click.echo("      No log file found, skipping detection")

    # ── [8/8] Evidence export ───────────────────────────────────
    click.echo("\n[8/8] Evidence export")

    # Evidence path: optionally sync to DefectDojo
    dd_client = None
    dd_status = "skipped (not configured)"
    try:
        dd_key = os.environ.get("DD_API_KEY", "")
        if dd_key:
            from orchestrator.integrations.defectdojo import DefectDojoClient

            dd_url = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080")
            dd = DefectDojoClient(base_url=dd_url, api_key=dd_key)
            if dd.health_check():
                product_id = dd.get_or_create_product(product)
                engagement_id = dd.get_or_create_engagement(product_id, "demo-scan")
                dd.import_findings(engagement_id, findings)
                dd_client = dd
                dd_status = f"synced ({len(findings)} findings)"
            else:
                dd_status = "skipped (not reachable)"
    except Exception:
        dd_status = "skipped (error)"

    jsonl_count = len(writer.read_findings(product=product))
    click.echo(f"      JSONL: {jsonl_path} ({jsonl_count} entries)")
    click.echo(f"      DefectDojo: {dd_status}")

    exporter = EvidenceExporter(jsonl_reader=writer, controls_repo=repo, defectdojo_client=dd_client)
    evidence = exporter.export(product=product, output_path=evidence_dir)

    report_file = Path(evidence_dir) / f"{evidence['report_id']}.json"
    summary = evidence["summary"]
    click.echo(f"      Report: {report_file}")
    click.echo(f"      Coverage: {summary['coverage_percentage']}%")

    click.echo(f"\n\u2713 Demo complete. See {output_dir}/ for full results.")
