"""POA&M and Authorization Engine — RMF Step 6 deliverables.

Generates Plan of Action & Milestones from findings and produces
deterministic authorization decisions. AI is NOT used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from orchestrator.rmf.models import SP80030Report
from orchestrator.types import Finding, GateDecision, ProductManifest

if TYPE_CHECKING:
    from orchestrator.intelligence.models import EnrichedVulnerability


# Scanner → scan-type classification used by POA&M `source.scan_type`.
# Aligns with the DevSecOps phase taxonomy callers expect.
_SCAN_TYPE: dict[str, str] = {
    "semgrep": "SAST",
    "bandit": "SAST",
    "codeql": "SAST",
    "spotbugs": "SAST",
    "grype": "SCA",
    "trivy": "SCA",
    "snyk": "SCA",
    "gitleaks": "Secret",
    "checkov": "IaC",
    "hadolint": "IaC",
    "zap": "DAST",
    "kube-bench": "CIS",   # CIS Kubernetes Benchmark — runtime hardening
    "cis-java":   "CIS",   # CIS Java Runtime Environment Benchmark
    "sarif": "SAST",  # SARIF is universal — default to SAST for unclassified
}

# Trigger → DevSecOps phase. The CI POSTs `trigger`; map it to BUILD/TEST/DEPLOY.
_PHASE: dict[str, str] = {
    "pre_merge": "BUILD",
    "pre_deploy": "DEPLOY",
    "periodic": "OPERATE",
}


# Scanner → NIST 800-53 controls. Used as a fallback when a finding has no
# control_ids from the mapper (e.g. unmapped rule IDs). Keeps every POA&M item
# anchored to at least one NIST control so dashboards and CSRs don't show
# blanks.
_SCANNER_CONTROL_MAP: dict[str, list[str]] = {
    "hadolint": ["CM-7", "CM-2"],
    "checkov":  ["CM-2", "CM-6", "AC-4", "AC-6"],
    "zap":      ["SA-11", "AC-3", "SI-10"],
    "grype":    ["RA-5", "SI-2", "SR-3"],
    "trivy":    ["RA-5", "SI-2", "CM-2", "SI-3"],
    "semgrep":  ["SA-11", "SI-10", "SC-13"],
    "gitleaks": ["IA-5", "SI-3"],
    "spotbugs": ["SA-11", "SI-10"],
    "bandit":   ["SA-11", "SI-10"],
    "codeql":   ["SA-11", "SI-10"],
    "snyk":     ["RA-5", "SI-2", "SR-3"],
    "kube-bench": ["CM-6", "SI-7"],     # k8s runtime hardening + integrity
    "cis-java":   ["CM-6", "SC-13"],    # JRE config + crypto
}


# Scanner → external framework references (DoD DevSecOps Tables, SSDF, CIS,
# SP 800-204D, SOC 2). Used as a fallback for source_detail.framework_refs.
_SCANNER_FRAMEWORK_MAP: dict[str, list[str]] = {
    "hadolint": ["CIS Docker 4.x", "DoD Table 6", "SSDF PW.7.2"],
    "zap":      ["DoD Table 7", "SSDF PW.8.2", "SOC 2 CC6.1"],
    "grype":    ["DoD Table 6/7", "SSDF RV.1", "SP 800-204D §5.1.1"],
    "trivy":    ["DoD Table 7", "SSDF RV.1", "CIS Docker §4/§5"],
    "semgrep":  ["DoD Table 5/6", "SSDF PW.7", "SP 800-204D §5.1.3"],
    "gitleaks": ["DoD Table 5", "SSDF PS.1", "SP 800-204D §5.1.4"],
    "checkov":  ["DoD Table 6", "SSDF PW.9.1"],
    "spotbugs": ["DoD Table 5/6", "SSDF PW.7"],
    "bandit":   ["DoD Table 5/6", "SSDF PW.7"],
    "codeql":   ["DoD Table 5/6", "SSDF PW.7"],
    "snyk":     ["DoD Table 6/7", "SSDF RV.1"],
    "kube-bench": ["CIS Kubernetes 1.10", "DoD Table 10", "SSDF PW.9"],
    "cis-java":   ["CIS Java JRE", "DoD Table 6", "SSDF PW.9"],
}


# [CWE-XXX] embedded in scanner messages (ZAP, SARIF enrichment) — extract
# when the scanner didn't surface cwe_ids structurally.
_CWE_IN_MESSAGE = re.compile(r"\[CWE-(\d+)\]")


# Severity -> deadline in days
_DEADLINE_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
}

# Severity -> risk level mapping (when no SP 800-30 report available)
_SEVERITY_TO_RISK: dict[str, str] = {
    "critical": "very-high",
    "high": "high",
    "medium": "moderate",
    "low": "low",
    "info": "very-low",
}

# Severity -> cost estimate heuristic
_SEVERITY_TO_COST: dict[str, str] = {
    "critical": "high",
    "high": "moderate",
    "medium": "moderate",
    "low": "low",
    "info": "low",
}


@dataclass
class POAMTicket:
    """External tracking ticket — filled in by the CI pipeline after it
    creates the GitHub Issue / Jira ticket."""

    id: str = ""
    url: str = ""


@dataclass
class POAMWeakness:
    """The vulnerability itself. Fields marked AI are filled by Bedrock
    (or fall back to deterministic templates when Bedrock is unavailable)."""

    title: str = ""
    cve_id: str = ""
    cwe_id: str = ""           # primary CWE (first entry of cwe_ids)
    cwe_ids: list[str] = field(default_factory=list)
    severity: str = ""
    cvss_score: float | None = None
    epss_score: float | None = None
    package: str = ""
    supply_chain: bool = False
    description: str = ""  # AI-generated; static template fallback


@dataclass
class POAMSource:
    """Where this finding came from, in CI/CD terms."""

    scanner: str = ""
    scan_type: str = ""        # SAST / SCA / IaC / DAST / Secret / Container
    phase: str = ""             # BUILD / TEST / DEPLOY / OPERATE
    framework_refs: list[str] = field(default_factory=list)
    finding_id: str = ""
    evidence_url: str = ""     # filled by pipeline (e.g. GH Actions run URL)
    sbom_ref: str = ""         # bom.json#component — filled when SBOM is correlated


@dataclass
class POAMImpact:
    """Business + compliance impact, derived from product manifest."""

    affected_asset: str = ""
    cia: dict[str, str] = field(default_factory=dict)
    data_classification: list[str] = field(default_factory=list)
    business_impact: str = ""  # AI-generated; static template fallback


@dataclass
class POAMLifecycle:
    """Time-bound state of the POA&M item."""

    discovered_at: str = ""
    due_date: str = ""
    sla_days: int = 0
    closed_at: str | None = None  # set when the finding stops appearing in scans


@dataclass
class POAMRemediation:
    """Remediation plan. Fields marked AI are filled by Bedrock."""

    plan: str = ""                   # AI
    owner: str = ""
    resources_required: str = ""     # AI
    vendor_dependency: str = ""      # AI


@dataclass
class POAMDelay:
    """Operator-supplied delay justification. Empty unless the operator
    explicitly POSTed a delay record."""

    justification: str = ""
    approved_by: str = ""


@dataclass
class POAMRiskAcceptance:
    """AO-signed risk acceptance. Empty unless the AO formally accepts."""

    accepted_by: str = ""
    justification: str = ""
    compensating_controls: list[str] = field(default_factory=list)


@dataclass
class POAMVerification:
    """How the fix was verified."""

    verified_by: str = ""   # "automated" or person name
    verified_at: str = ""


@dataclass
class POAMItem:
    """Single weakness + remediation plan.

    Legacy flat fields (id, weakness, severity, …) are preserved for
    backwards compatibility with the SAR generator, dashboard exporter,
    and JSONL writer. The nested fields are the canonical detailed view
    that CI/CD systems and dashboards should consume.
    """

    id: str  # POAM-YYYY-MMDD-NNN
    weakness: str  # legacy: same as weakness_detail.title
    control_id: str  # legacy: first entry of source_detail.framework_refs
    source: str  # legacy: same as source_detail.scanner
    finding_id: str  # legacy: same as source_detail.finding_id
    severity: str  # critical / high / medium / low
    risk_level: str  # from SP 800-30 assessment
    status: str  # "open" / "in-progress" / "completed" / "accepted"

    # Milestones (template until Bedrock fills in)
    milestones: list[dict[str, str]]  # [{description, target_date, status}]
    scheduled_completion: str  # target date — legacy: same as lifecycle.due_date
    responsible: str  # legacy: same as remediation.owner
    cost_estimate: str  # "low" / "moderate" / "high"

    # Links
    finding_evidence: str
    override_id: str

    # New structured fields (matches the customer's POA&M schema spec)
    ticket: POAMTicket = field(default_factory=POAMTicket)
    weakness_detail: POAMWeakness = field(default_factory=POAMWeakness)
    source_detail: POAMSource = field(default_factory=POAMSource)
    impact: POAMImpact = field(default_factory=POAMImpact)
    lifecycle: POAMLifecycle = field(default_factory=POAMLifecycle)
    remediation: POAMRemediation = field(default_factory=POAMRemediation)
    delay: POAMDelay = field(default_factory=POAMDelay)
    risk_acceptance: POAMRiskAcceptance = field(default_factory=POAMRiskAcceptance)
    verification: POAMVerification = field(default_factory=POAMVerification)

    # Stable identity across runs — `source + rule_id + package + file`.
    # Used by the reconciler to mark closed_at when a finding stops appearing.
    # Line numbers and assessment ids deliberately excluded — they shift on
    # benign refactors and re-runs.
    fingerprint: str = ""

    # Dedup: when one weakness (scanner+rule) recurs across many locations
    # (e.g. ZAP-90005 across 4 URLs × 4 headers = 16 occurrences), collapse
    # them into a single POA&M item with the locations listed here.
    affected_locations: list[str] = field(default_factory=list)
    occurrence_count: int = 1


@dataclass
class AuthorizationDecision:
    """RMF Step 6 authorization decision."""

    decision: str  # "ATO" or "DATO" — binary for CI/CD automation
    risk_level: str  # overall risk from SP 800-30
    conditions: list[str]  # informational POA&M / override remediation items
    authorizer: str  # "automated-gate" or role
    timestamp: str
    valid_until: str  # re-authorization date
    reasoning: str


class POAMGenerator:
    """Generate POA&M from findings + risk assessment."""

    _counter: int = 0

    def generate(
        self,
        findings: list[Finding],
        risk_report: SP80030Report | None = None,
        gate_decision: GateDecision | None = None,
        manifest: ProductManifest | None = None,
        enriched_vulns: list["EnrichedVulnerability"] | None = None,
        trigger: str = "pre_merge",
        evidence_url: str = "",
        sbom: dict[str, object] | None = None,
        phase: str | None = None,
    ) -> list[POAMItem]:
        """Generate POA&M items from findings.

        Priority -> deadline mapping:
        - critical: 7 days
        - high: 30 days
        - moderate/medium: 90 days
        - low: 180 days

        Each item has 4 milestones:
        1. Identify fix (day 1)
        2. Implement fix (50% of deadline)
        3. Verify in staging (75% of deadline)
        4. Deploy to production (deadline)

        Auto-populated nested fields (when inputs are available):
        - weakness: cve_id, cvss_score, epss_score, package, supply_chain
        - source: scan_type, phase, framework_refs, evidence_url
        - impact: affected_asset, cia, data_classification (from manifest)
        - lifecycle: discovered_at, due_date, sla_days

        AI-generated fields (description, business_impact, remediation.plan,
        remediation.resources_required, remediation.vendor_dependency) are
        filled by deterministic templates here; a Bedrock pass can overwrite
        them later.
        """
        now = datetime.now(timezone.utc)
        items: list[POAMItem] = []

        # Build risk level lookup from SP 800-30 report
        risk_lookup: dict[str, str] = {}
        if risk_report:
            for rd in risk_report.risk_determinations:
                risk_lookup[rd.threat_event_id] = rd.risk_level

        # EPSS lookup by CVE id (Trivy uses VulnerabilityID, Grype uses rule_id)
        epss_lookup: dict[str, float | None] = {}
        if enriched_vulns:
            for ev in enriched_vulns:
                epss_lookup[ev.cve_id] = ev.epss_score

        product_name = manifest.name if manifest else ""
        cia = dict(manifest.impact_levels) if manifest else {}
        data_class = list(manifest.data_classification) if manifest else []
        # Caller-supplied phase wins over the trigger-derived default. CI runs
        # frequently mix scanner phases (BUILD-time SAST + TEST-time DAST) in
        # a single submission, so callers should pass the actual phase per run.
        effective_phase = phase or _PHASE.get(trigger, "UNKNOWN")

        # SBOM correlation (best-effort — empty string when SBOM is missing
        # or the package isn't in it).
        from orchestrator.rmf.sbom_correlator import SbomCorrelator
        correlator = SbomCorrelator(sbom)

        # Group findings by (scanner, rule_id, package, installed_version).
        # Same vulnerability across N URLs/files/headers becomes one POA&M
        # item with affected_locations listing each occurrence. Package +
        # version are kept in the key so two different vulnerable packages
        # that happen to share a CVE id don't get collapsed.
        groups: dict[tuple[str, str, str, str], list[Finding]] = {}
        ordered_keys: list[tuple[str, str, str, str]] = []
        for finding in findings:
            key = (
                finding.source,
                finding.rule_id,
                finding.package or "",
                finding.installed_version or "",
            )
            if key not in groups:
                groups[key] = []
                ordered_keys.append(key)
            groups[key].append(finding)

        for key in ordered_keys:
            group = groups[key]
            representative = self._pick_representative(group)
            POAMGenerator._counter += 1
            item_id = f"POAM-{now.strftime('%Y')}-{now.strftime('%m%d')}-{POAMGenerator._counter:03d}"

            severity = representative.severity
            deadline_days = _DEADLINE_DAYS.get(severity, 90)
            deadline_date = now + timedelta(days=deadline_days)
            risk_level = _SEVERITY_TO_RISK.get(severity, "moderate")
            owner = self._assign_responsible(severity)
            milestones = self._build_milestones(now, deadline_days)

            scan_type = _SCAN_TYPE.get(representative.source, "")
            is_sca = scan_type == "SCA"
            cve_id = representative.rule_id if representative.rule_id.startswith("CVE-") else ""
            epss = epss_lookup.get(cve_id) if cve_id else None

            cwe_ids = list(representative.cwe_ids)
            # IMPROVE-5c: pull CWE out of "...[CWE-XXX]" message text when the
            # scanner didn't expose it structurally (ZAP embeds CWE in message).
            if not cwe_ids:
                cwe_ids = _extract_cwes_from_text(representative.message)

            scanner_controls = _SCANNER_CONTROL_MAP.get(representative.source, [])
            effective_control_ids = list(representative.control_ids) or list(scanner_controls)
            control_id = effective_control_ids[0] if effective_control_ids else ""

            weakness = POAMWeakness(
                title=(representative.message or representative.rule_id)[:200],
                cve_id=cve_id,
                cwe_id=(f"CWE-{cwe_ids[0]}" if cwe_ids and not cwe_ids[0].startswith("CWE-") else (cwe_ids[0] if cwe_ids else "")),
                cwe_ids=[c if c.startswith("CWE-") else f"CWE-{c}" for c in cwe_ids],
                severity=severity,
                cvss_score=representative.cvss_score,
                epss_score=epss,
                package=representative.package,
                supply_chain=is_sca and bool(representative.package),
                description=self._describe_weakness(representative),
            )
            framework_refs = list(representative.control_ids) or list(
                _SCANNER_FRAMEWORK_MAP.get(representative.source, [])
            )
            source_detail = POAMSource(
                scanner=representative.source,
                scan_type=scan_type,
                phase=effective_phase,
                framework_refs=framework_refs,
                finding_id=representative.rule_id,
                evidence_url=evidence_url,
                sbom_ref=correlator.correlate(representative.package, representative.installed_version),
            )
            impact = POAMImpact(
                affected_asset=product_name,
                cia=cia,
                data_classification=data_class,
                business_impact=self._describe_business_impact(representative, manifest),
            )
            lifecycle = POAMLifecycle(
                discovered_at=now.isoformat(),
                due_date=deadline_date.strftime("%Y-%m-%d"),
                sla_days=deadline_days,
                closed_at=None,
            )
            remediation = POAMRemediation(
                plan=self._describe_remediation(representative),
                owner=owner,
                resources_required=self._estimate_resources(representative),
                vendor_dependency=self._vendor_dependency(representative),
            )

            locations = _collect_locations(group)

            items.append(
                POAMItem(
                    id=item_id,
                    weakness=representative.message,
                    control_id=control_id,
                    source=representative.source,
                    finding_id=representative.rule_id,
                    severity=severity,
                    risk_level=risk_level,
                    status="open",
                    milestones=milestones,
                    scheduled_completion=deadline_date.strftime("%Y-%m-%d"),
                    responsible=owner,
                    cost_estimate=_SEVERITY_TO_COST.get(severity, "moderate"),
                    finding_evidence="findings.jsonl",
                    override_id="",
                    ticket=POAMTicket(),  # filled by pipeline post-creation
                    weakness_detail=weakness,
                    source_detail=source_detail,
                    impact=impact,
                    lifecycle=lifecycle,
                    remediation=remediation,
                    delay=POAMDelay(),
                    risk_acceptance=POAMRiskAcceptance(),
                    verification=POAMVerification(verified_by="automated"),
                    fingerprint=fingerprint_for_finding(representative),
                    affected_locations=locations,
                    occurrence_count=len(group),
                )
            )

        return items

    @staticmethod
    def _pick_representative(group: list[Finding]) -> Finding:
        """Pick the most severe finding in the group as the canonical one."""
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return max(group, key=lambda f: order.get(f.severity, -1))

    # --- static-template fallbacks for AI-generated fields ---
    # These keep the schema fully populated when Bedrock isn't configured.
    # A future Bedrock pass replaces them with model-generated text.

    @staticmethod
    def _describe_weakness(f: Finding) -> str:
        if f.rule_id.startswith("CVE-") and f.package:
            base = f"{f.rule_id} in {f.package}"
            if f.installed_version:
                base += f" {f.installed_version}"
            if f.cvss_score is not None:
                base += f" (CVSS {f.cvss_score})"
            return f"{base}. {f.message}" if f.message else base
        if f.message:
            return f.message
        return f"{f.source}:{f.rule_id} flagged a finding in {f.file or 'the codebase'}"

    @staticmethod
    def _describe_business_impact(f: Finding, manifest: ProductManifest | None) -> str:
        if manifest is None:
            return ""
        cls = ", ".join(manifest.data_classification) or "data"
        cia = manifest.impact_levels
        sev = f.severity.upper()
        return (
            f"{sev} severity finding on {manifest.name} "
            f"(CIA: C={cia.get('confidentiality','?')} I={cia.get('integrity','?')} "
            f"A={cia.get('availability','?')}; data: {cls}). "
            "Refer to the SP 800-30 risk report for the full impact narrative."
        )

    @staticmethod
    def _describe_remediation(f: Finding) -> str:
        if f.package and f.fixed_version:
            return f"Upgrade {f.package} from {f.installed_version or '?'} to {f.fixed_version}."
        if f.package:
            return f"Upgrade {f.package} when a fixed version is published."
        if f.source == "gitleaks" or f.rule_id.startswith("secret-"):
            return "Rotate the leaked credential and remove it from the repository history."
        if f.source == "checkov":
            return f"Address Checkov rule {f.rule_id} per IaC policy."
        if f.source == "semgrep":
            return f"Refactor the code at {f.file}:{f.line} to satisfy rule {f.rule_id}."
        return "Apply remediation per scanner guidance."

    @staticmethod
    def _estimate_resources(f: Finding) -> str:
        # Heuristic: package upgrades are usually <1 engineer-day; SAST fixes
        # vary. Bedrock will refine this; the template just gives operators
        # a starting estimate.
        if f.package and f.fixed_version:
            return "1 engineer, ~0.5 day (dependency upgrade + regression test)"
        if f.severity == "critical":
            return "1-2 engineers, 1-2 days"
        if f.severity == "high":
            return "1 engineer, 1 day"
        return "1 engineer, 0.5 day"

    @staticmethod
    def _vendor_dependency(f: Finding) -> str:
        # SCA without a fixed version → blocked on the upstream maintainer.
        if f.package and not f.fixed_version:
            return f"Awaiting upstream patch for {f.package}."
        return ""

    @staticmethod
    def _build_milestones(start: datetime, deadline_days: int) -> list[dict[str, str]]:
        """Build 4 milestones with target dates."""
        return [
            {
                "description": "Identify fix",
                "target_date": (start + timedelta(days=1)).strftime("%Y-%m-%d"),
                "status": "open",
            },
            {
                "description": "Implement fix",
                "target_date": (start + timedelta(days=deadline_days // 2)).strftime("%Y-%m-%d"),
                "status": "open",
            },
            {
                "description": "Verify in staging",
                "target_date": (start + timedelta(days=int(deadline_days * 0.75))).strftime("%Y-%m-%d"),
                "status": "open",
            },
            {
                "description": "Deploy to production",
                "target_date": (start + timedelta(days=deadline_days)).strftime("%Y-%m-%d"),
                "status": "open",
            },
        ]

    @staticmethod
    def _assign_responsible(severity: str) -> str:
        """Assign responsible party based on severity."""
        if severity in ("critical", "high"):
            return "security-engineer"
        return "dev-team"


class AuthorizationEngine:
    """RMF Step 6 authorization decision.

    Binary outcome for automation:
    - Gate PASS  -> ATO   (remediation deadlines tracked separately in POA&M)
    - Gate BLOCK -> DATO

    `ATO-with-conditions` was intentionally retired: a CI/CD gate needs a
    strict pass/fail signal. Open POA&M items and active overrides are still
    surfaced via the `conditions` field so the SAR and downstream tooling can
    show remediation work, but they do not change the top-level decision.
    """

    def decide(
        self,
        gate_decision: GateDecision,
        poam_items: list[POAMItem],
        overrides: list[dict[str, object]] | None = None,
    ) -> AuthorizationDecision:
        """Produce authorization decision."""
        now = datetime.now(timezone.utc)
        valid_until = (now + timedelta(days=90)).strftime("%Y-%m-%d")

        # Gate BLOCK -> DATO
        if not gate_decision.passed:
            return AuthorizationDecision(
                decision="DATO",
                risk_level="unacceptable",
                conditions=[],
                authorizer="automated-gate",
                timestamp=now.isoformat(),
                valid_until=valid_until,
                reasoning=f"Gate blocked: {gate_decision.reason}",
            )

        # Gate PASS -> ATO. Surface open POA&M items + active overrides as
        # informational `conditions` (not gates).
        conditions: list[str] = []
        for item in poam_items:
            if item.status in ("open", "in-progress"):
                conditions.append(
                    f"{item.id}: {item.weakness} (deadline: {item.scheduled_completion})"
                )
        if overrides:
            for ovr in overrides:
                ovr_id = ovr.get("id", "unknown")
                conditions.append(
                    f"Override {ovr_id}: deferred scan must complete per SLA"
                )

        if conditions:
            reasoning = (
                f"Gate passed; {len(conditions)} remediation item(s) tracked in POA&M"
            )
        else:
            reasoning = "Gate passed; no open POA&M items"

        return AuthorizationDecision(
            decision="ATO",
            risk_level="acceptable",
            conditions=conditions,
            authorizer="automated-gate",
            timestamp=now.isoformat(),
            valid_until=valid_until,
            reasoning=reasoning,
        )


def fingerprint_for_finding(f: Finding) -> str:
    """Stable identity for a finding across runs.

    Excludes line number (shifts on refactors) and product (the assessment
    is already product-scoped). Includes file when present so SAST findings
    on the same rule but different files don't collapse.
    """
    parts = [f.source, f.rule_id, f.package or "", f.installed_version or "", f.file or ""]
    return "|".join(p.strip() for p in parts)


def _extract_cwes_from_text(text: str) -> list[str]:
    """Find every [CWE-NNN] reference in a string.

    Some scanners (notably ZAP) only embed the CWE in the human-readable
    message rather than as a structured field. Pulling it out keeps
    weakness_detail.cwe_id populated.
    """
    if not text:
        return []
    return [m for m in _CWE_IN_MESSAGE.findall(text)]


def _collect_locations(group: list[Finding]) -> list[str]:
    """Format affected locations from a dedup group.

    For SAST/IaC: "path/to/file.py:42". For DAST (ZAP): "http://host/path"
    plus the affected parameter pulled from the message.
    """
    seen: list[str] = []
    deduped: set[str] = set()
    param_re = re.compile(r"\(param:\s*([^)]+)\)")
    for f in group:
        if f.file:
            loc = f.file if not f.line else f"{f.file}:{f.line}"
            if f.source == "zap":
                m = param_re.search(f.message or "")
                if m:
                    loc = f"{f.file} ({m.group(1).strip()})"
        elif f.message:
            loc = f.message[:120]
        else:
            loc = "(unknown)"
        if loc not in deduped:
            deduped.add(loc)
            seen.append(loc)
    return seen
