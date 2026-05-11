"""Tests for AI output grounding validation."""

from __future__ import annotations

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.rmf.grounding import validate_grounding
from orchestrator.types import Finding


def _make_finding(rule_id: str = "CVE-2023-50782", **kwargs: object) -> Finding:
    defaults = {
        "source": "grype",
        "rule_id": rule_id,
        "severity": "high",
        "file": "requirements.txt",
        "line": 0,
        "message": "test",
        "control_ids": ["PCI-DSS-6.3.1"],
        "product": "test",
        "package": "cryptography",
        "installed_version": "3.4.6",
        "fixed_version": "41.0.6",
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


def _make_control(control_id: str = "PCI-DSS-6.3.1") -> Control:
    return Control(
        id=control_id,
        title="test",
        framework="pci-dss-4.0",
        description="test",
        verification_methods=[VerificationMethod(scanner="grype", rules=None, check_ids=None, severity_threshold="high")],
        applicable_tiers=["high", "critical"],
        risk_tier_mapping=None,
    )


class TestGroundingValidation:
    def test_valid_when_all_references_real(self) -> None:
        ai_output = {
            "executive_summary": "CVE-2023-50782 affects cryptography and violates PCI-DSS-6.3.1",
            "risk_determinations": [{"likelihood": "high", "impact": "very-high", "risk_level": "very-high"}],
        }
        findings = [_make_finding()]
        controls = [_make_control()]

        result = validate_grounding(ai_output, findings, controls)

        assert result.valid
        assert result.verified_references > 0
        assert result.hallucinated_references == []

    def test_invalid_when_cve_hallucinated(self) -> None:
        ai_output = {
            "executive_summary": "CVE-2099-99999 is a critical vulnerability",
        }
        findings = [_make_finding("CVE-2023-50782")]
        controls = [_make_control()]

        result = validate_grounding(ai_output, findings, controls)

        assert not result.valid
        assert "CVE-2099-99999" in result.hallucinated_references[0]

    def test_invalid_when_control_hallucinated(self) -> None:
        ai_output = {
            "executive_summary": "This violates PCI-DSS-99.99.99",
        }
        findings = [_make_finding()]
        controls = [_make_control("PCI-DSS-6.3.1")]

        result = validate_grounding(ai_output, findings, controls)

        assert not result.valid
        assert any("PCI-DSS-99.99.99" in h for h in result.hallucinated_references)

    def test_warns_on_invalid_risk_level(self) -> None:
        ai_output = {
            "risk_determinations": [{"likelihood": "super-high", "impact": "extreme", "risk_level": "mega"}],
        }
        findings = [_make_finding()]
        controls = [_make_control()]

        result = validate_grounding(ai_output, findings, controls)

        assert len(result.warnings) >= 1
        assert any("Invalid SP 800-30 risk level" in w for w in result.warnings)

    def test_warns_when_no_references(self) -> None:
        ai_output = {
            "executive_summary": "The system has some risks.",
        }
        findings = [_make_finding()]
        controls = [_make_control()]

        result = validate_grounding(ai_output, findings, controls)

        assert any("no CVE/control references" in w for w in result.warnings)

    def test_handles_ghsa_ids(self) -> None:
        ai_output = {
            "executive_summary": "GHSA-3ww4-gg4f-jr7f is exploitable",
        }
        findings = [_make_finding("GHSA-3ww4-gg4f-jr7f")]
        controls = [_make_control()]

        result = validate_grounding(ai_output, findings, controls)

        assert result.valid

    def test_handles_fisc_control_ids(self) -> None:
        ai_output = {
            "executive_summary": "This violates FISC-実127",
        }
        findings = [_make_finding()]
        controls = [_make_control("FISC-実127")]

        result = validate_grounding(ai_output, findings, controls)

        assert result.valid
