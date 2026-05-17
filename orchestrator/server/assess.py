"""Reusable assessment pipeline — pure functions callable from CLI or server.

Extracts the scan→assess→SAR→POA&M→authorization flow from cli.py
so both entry points share one code path.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable

logger = logging.getLogger(__name__)

from orchestrator.controls.baseline import select_baseline
from orchestrator.controls.repository import ControlsRepository
from orchestrator.gate.combined import CombinedGateEvaluator
from orchestrator.gate.opa import OpaEvaluator
from orchestrator.gate.threshold import ThresholdEvaluator
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.rmf.poam import AuthorizationEngine, POAMGenerator
from orchestrator.rmf.sar import SARGenerator
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.server.state import SharedClients
from orchestrator.types import (
    Finding,
    GateDecision,
    ProductManifest,
    RiskProfile,
    RiskTier,
    is_secret_finding,
)


@dataclass
class AssessmentResult:
    """All artefacts produced by a single assessment run."""

    product: str
    tier: str
    findings: list[Finding]
    gate: GateDecision
    sp800_report: Any
    sar: Any
    poam_items: list[Any]
    authorization: Any
    mode: str
    duration_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "tier": self.tier,
            "mode": self.mode,
            "duration_seconds": round(self.duration_seconds, 2),
            "findings_count": len(self.findings),
            "gate": {
                "passed": self.gate.passed,
                "reason": self.gate.reason,
                "findings_count": self.gate.findings_count,
                "threshold_results": self.gate.threshold_results,
            },
            "sp800_30_report": _safe_asdict(self.sp800_report),
            "sar": _safe_asdict(self.sar),
            "poam": {
                "total_items": len(self.poam_items),
                "items": [_safe_asdict(item) for item in self.poam_items],
            },
            "authorization": _safe_asdict(self.authorization),
        }


def run_assessment(
    product: str,
    findings: list[Finding],
    manifest: ProductManifest,
    profile: RiskProfile,
    controls_repo: ControlsRepository,
    clients: SharedClients,
    rego_dir: str,
    trigger: str = "pre_merge",
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> AssessmentResult:
    """Run gate + SP 800-30 + SAR + POA&M + authorization on a finding list."""
    t0 = time.monotonic()

    # Copy + tag so we don't mutate the caller's list.
    tagged = [_tagged(f, product) for f in findings]

    tier = clients.assessor.categorize(manifest)
    controls = select_baseline(controls_repo, manifest, tier)
    mapper = ControlMapper(controls_repo)

    enriched_vulns = _enrich_with_epss(tagged, manifest, mapper, clients)

    sp800_report = clients.pipeline.run(
        findings=tagged,
        enriched_vulns=enriched_vulns,
        manifest=manifest,
        controls=controls,
        trigger=trigger,
        progress_callback=progress_callback,
    )

    threshold_eval = ThresholdEvaluator(profile)
    opa_eval = OpaEvaluator(rego_dir)
    combined = CombinedGateEvaluator(threshold_eval, opa_eval)
    context: dict[str, object] = {
        "product": product,
        "tier": tier.value,
        "frameworks": profile.frameworks,
        "findings_count": {
            s: sum(1 for f in tagged if f.severity == s)
            for s in ["critical", "high", "medium", "low"]
        },
        "pci_scope_count": sum(
            1 for f in tagged if any(c.startswith("PCI-DSS") for c in f.control_ids)
        ),
        "secrets_count": sum(1 for f in tagged if is_secret_finding(f)),
    }
    gate = combined.evaluate(tagged, tier, context)

    sar = SARGenerator(controls_repo).generate(
        product=product, findings=tagged, gate_decision=gate, risk_report=sp800_report,
    )
    poam_items = POAMGenerator().generate(
        findings=tagged, risk_report=sp800_report, gate_decision=gate,
    )
    authorization = AuthorizationEngine().decide(gate_decision=gate, poam_items=poam_items)

    return AssessmentResult(
        product=product,
        tier=tier.value,
        findings=tagged,
        gate=gate,
        sp800_report=sp800_report,
        sar=sar,
        poam_items=poam_items,
        authorization=authorization,
        mode=clients.mode,
        duration_seconds=time.monotonic() - t0,
    )


def run_scanners(target_path: str, controls_repo: ControlsRepository) -> list[Finding]:
    """Execute the bundled scanners against a path on the local filesystem."""
    from orchestrator.scanners.checkov import CheckovScanner
    from orchestrator.scanners.gitleaks import GitleaksScanner
    from orchestrator.scanners.grype import GrypeScanner
    from orchestrator.scanners.runner import ScannerRunner
    from orchestrator.scanners.semgrep import SemgrepScanner

    mapper = ControlMapper(controls_repo)
    scanners = [
        CheckovScanner(mapper),
        SemgrepScanner(mapper),
        GrypeScanner(mapper),
        GitleaksScanner(mapper),
    ]
    return ScannerRunner(scanners).run_all(target_path)


def _tagged(finding: Finding, product: str) -> Finding:
    if finding.product == product:
        return finding
    return Finding(
        source=finding.source,
        rule_id=finding.rule_id,
        severity=finding.severity,
        file=finding.file,
        line=finding.line,
        message=finding.message,
        control_ids=list(finding.control_ids),
        product=product,
        package=finding.package,
        installed_version=finding.installed_version,
        fixed_version=finding.fixed_version,
    )


def _enrich_with_epss(
    findings: list[Finding],
    manifest: ProductManifest,
    mapper: ControlMapper,
    clients: SharedClients,
) -> list[EnrichedVulnerability]:
    if clients.epss_client is None:
        return []
    try:
        from orchestrator.intelligence.enricher import VulnerabilityEnricher

        return VulnerabilityEnricher(clients.epss_client, mapper).enrich(findings, manifest)
    except Exception:
        return []


def _safe_asdict(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, RiskTier):
        return obj.value
    if isinstance(obj, (str, int, float, bool, list, dict)):
        return obj
    # Anything else is a bug — pipelines should return dataclasses.
    logger.warning("_safe_asdict: unexpected type %s — coercing to str", type(obj).__name__)
    return str(obj)
