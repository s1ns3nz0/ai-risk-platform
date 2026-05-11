"""Tests for compute_risk_score — Likelihood × Impact risk scoring."""

from __future__ import annotations

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.scoring.risk import compute_risk_score
from orchestrator.types import Finding, ProductManifest, RiskTier


def _make_manifest(
    data_classification: list[str] | None = None,
    jurisdiction: list[str] | None = None,
) -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="test",
        data_classification=data_classification or [],
        jurisdiction=jurisdiction or [],
        deployment={"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
        integrations=[],
    )


def _make_finding(
    severity: str = "medium",
    source: str = "semgrep",
    control_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        source=source,
        rule_id="test-rule",
        severity=severity,
        file="test.py",
        line=1,
        message="test finding",
        control_ids=control_ids or [],
        product="payment-api",
    )


def _make_control(control_id: str = "PCI-DSS-6.3.1") -> Control:
    return Control(
        id=control_id,
        title="Test Control",
        framework="pci-dss-4.0",
        description="Test",
        verification_methods=[
            VerificationMethod(scanner="semgrep", rules=["test-rule"]),
        ],
        applicable_tiers=[RiskTier.HIGH, RiskTier.CRITICAL],
    )


class TestNoFindingsLowScore:
    def test_no_findings_low_score(self) -> None:
        manifest = _make_manifest(data_classification=["public"])
        controls = [_make_control()]
        score, factors = compute_risk_score([], manifest, controls)
        assert score < 3.0


class TestCriticalFindingsHighScore:
    def test_critical_findings_high_score(self) -> None:
        manifest = _make_manifest(data_classification=["PCI"])
        controls = [_make_control()]
        findings = [_make_finding(severity="critical") for _ in range(3)]
        score, factors = compute_risk_score(findings, manifest, controls)
        assert score > 7.0


class TestPciScopeIncreasesImpact:
    def test_pci_scope_increases_impact(self) -> None:
        controls = [_make_control()]
        findings = [_make_finding(severity="high")]

        manifest_public = _make_manifest(data_classification=["public"])
        _, factors_public = compute_risk_score(findings, manifest_public, controls)

        manifest_pci = _make_manifest(data_classification=["PCI"])
        _, factors_pci = compute_risk_score(findings, manifest_pci, controls)

        assert factors_pci["impact_score"] > factors_public["impact_score"]


class TestSecretsIncreaseLikelihood:
    def test_secrets_increase_likelihood(self) -> None:
        manifest = _make_manifest(data_classification=["PCI"])
        controls = [_make_control()]

        findings_no_secret = [_make_finding(severity="high")]
        _, factors_no = compute_risk_score(findings_no_secret, manifest, controls)

        findings_with_secret = [
            _make_finding(severity="high"),
            _make_finding(source="gitleaks", severity="critical"),
        ]
        _, factors_yes = compute_risk_score(findings_with_secret, manifest, controls)

        assert factors_yes["likelihood_score"] > factors_no["likelihood_score"]


class TestScoreRange:
    def test_score_range(self) -> None:
        manifest = _make_manifest(data_classification=["PCI", "PII-financial"])
        controls = [_make_control()]

        # Empty findings
        score_empty, _ = compute_risk_score([], manifest, controls)
        assert 0.0 <= score_empty <= 10.0

        # Many critical findings
        findings = [_make_finding(severity="critical") for _ in range(20)]
        score_many, _ = compute_risk_score(findings, manifest, controls)
        assert 0.0 <= score_many <= 10.0


class TestFactorsContainEvidence:
    def test_factors_contain_evidence(self) -> None:
        manifest = _make_manifest(data_classification=["PCI"])
        controls = [_make_control()]
        findings = [_make_finding(severity="high")]

        _, factors = compute_risk_score(findings, manifest, controls)

        assert "finding_severity_distribution" in factors
        assert "pci_scope_ratio" in factors
        assert "secrets_detected" in factors
        assert "data_classification" in factors
        assert "control_coverage" in factors
        assert "jurisdiction_sensitivity" in factors
        assert "likelihood_score" in factors
        assert "impact_score" in factors
