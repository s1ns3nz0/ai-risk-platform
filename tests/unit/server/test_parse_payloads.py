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
