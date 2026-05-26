"""Regression tests for _parse_payloads scanner-submission tracking."""

from orchestrator.controls.repository import ControlsRepository
from orchestrator.server.app import _parse_payloads
from orchestrator.server.models import ScannerResultPayload
from orchestrator.server.state import ServerState


class _FakeState:
    def __init__(self):
        self.controls_repo = ControlsRepository(
            baselines_dir="controls/baselines",
            tier_mappings_path="controls/tier-mappings.yaml",
        )
        self.controls_repo.load_all()


def test_trivy_credits_grype_for_sar():
    """Trivy CVE findings map to grype-assessed controls. The SAR's
    'did the scanner run' check requires grype in submitted_scanners,
    so a trivy upload must also credit grype.
    """
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="trivy",
        content={"SchemaVersion": 2, "Results": []},
    )]
    _, submitted = _parse_payloads(payloads, state)
    assert "trivy" in submitted
    assert "grype" in submitted


def test_trivy_image_alias_credits_grype():
    """Aliased trivy-image submission must still pick up grype equivalence."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="trivy-image",
        content={"SchemaVersion": 2, "Results": []},
    )]
    _, submitted = _parse_payloads(payloads, state)
    assert "trivy" in submitted
    assert "grype" in submitted


def test_grype_alone_does_not_credit_trivy():
    """The equivalence is asymmetric — grype shouldn't credit trivy."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="grype",
        content={"matches": []},
    )]
    _, submitted = _parse_payloads(payloads, state)
    assert "grype" in submitted
    assert "trivy" not in submitted


def test_semgrep_sarif_alias_normalizes_to_semgrep():
    """semgrep-sarif submission must credit "semgrep" (what controls expect),
    not the raw "semgrep-sarif" alias.
    """
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="semgrep-sarif",
        content={"version": "2.1.0", "runs": []},
    )]
    _, submitted = _parse_payloads(payloads, state)
    assert "semgrep" in submitted
    assert "semgrep-sarif" not in submitted


def test_clean_gitleaks_sarif_credits_gitleaks():
    """0-findings gitleaks SARIF upload must credit gitleaks for SAR."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="gitleaks",
        format="sarif",
        content={
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}],
        },
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert findings == []
    assert "gitleaks" in submitted


def test_kube_bench_text_routes_to_cis_parser():
    """kube-bench plain-text payload yields a finding per [FAIL] line and
    credits kube-bench in the submitted-scanners set."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="kube-bench",
        format="text",
        content=(
            "[PASS] 4.1.1 kubelet permissions\n"
            "[FAIL] 4.1.3 proxy kubeconfig permissions wrong\n"
            "[WARN] 4.1.5 kubeconfig ownership not root\n"
        ),
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert "kube-bench" in submitted
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"4.1.3", "4.1.5"}
    assert all(f.source == "kube-bench" for f in findings)


def test_cis_java_text_routes_to_cis_parser():
    """cis-java plain-text payload — single FAIL produces a single finding."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="cis-java",
        format="text",
        content=(
            "[PASS] 1.1 java.security exists\n"
            "[FAIL] 1.3 SHA-1 not in disabledAlgorithms\n"
        ),
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert "cis-java" in submitted
    assert [f.rule_id for f in findings] == ["1.3"]
    assert findings[0].severity == "medium"


def test_clean_kube_bench_credits_scanner_with_zero_findings():
    """A kube-bench run that's 100% PASS must still credit the scanner so the
    SAR can mark CIS controls as 'satisfied' rather than 'not-assessed'."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="kube-bench",
        format="text",
        content="[PASS] 4.1.1 ok\n[PASS] 4.1.2 ok\n",
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert findings == []
    assert "kube-bench" in submitted


def test_cosign_verified_credits_scanner_with_zero_findings():
    """A fully-verified cosign bundle yields zero findings but must still
    register 'cosign' in submitted_scanners — that's what lets the SAR mark
    supply-chain integrity controls as satisfied instead of not-assessed."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="cosign",
        content={
            "verifications": [
                {"subject": "img@sha256:a", "type": "image-signature", "verified": True},
                {"subject": "img@sha256:a", "type": "attestation",
                 "attestation_type": "cyclonedx", "verified": True},
            ]
        },
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert findings == []
    assert "cosign" in submitted


def test_cosign_attestation_alias_routes_to_cosign():
    """The cosign-attestation alias must collapse to canonical cosign."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="cosign-attestation",
        content={"verifications": [
            {"subject": "img", "type": "attestation", "verified": False, "error": "missing"},
        ]},
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert "cosign" in submitted
    assert len(findings) == 1
    assert findings[0].source == "cosign"


def test_gatekeeper_alias_routes_to_opa_admission():
    """Gatekeeper / Kyverno engines collapse onto canonical opa-admission."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="gatekeeper",
        content={"violations": [
            {"policy": "p", "engine": "gatekeeper", "message": "v"},
        ]},
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert "opa-admission" in submitted
    assert len(findings) == 1
    assert findings[0].source == "opa-admission"


def test_opa_admission_clean_credits_scanner():
    """Zero admission violations is the satisfied path — must credit the scanner."""
    state = _FakeState()
    payloads = [ScannerResultPayload(
        scanner="opa-admission",
        content={"violations": []},
    )]
    findings, submitted = _parse_payloads(payloads, state)
    assert findings == []
    assert "opa-admission" in submitted
