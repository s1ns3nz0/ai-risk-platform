"""Shared test fixtures."""

from __future__ import annotations

import pytest

from orchestrator.types import Finding, ProductManifest, RiskProfile


@pytest.fixture
def sample_manifest() -> ProductManifest:
    """payment-api product manifest fixture."""
    return ProductManifest(
        name="payment-api",
        description="QR code payment confirmation service",
        data_classification=["PCI", "PII-financial"],
        jurisdiction=["JP"],
        deployment={"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
        integrations=["external-payment-gateway", "internal-user-db"],
    )


@pytest.fixture
def sample_profile() -> RiskProfile:
    """Conservative risk profile fixture."""
    return RiskProfile(
        frameworks=["pci-dss-4.0", "asvs-4.0.3-L3", "fisc-safety"],
        risk_appetite="conservative",
        thresholds={
            "critical": {"max_critical_findings": 0, "max_secrets_detected": 0, "action": "block"},
            "high": {"max_critical_findings": 0, "max_high_findings_pci": 0, "action": "block"},
            "medium": {"max_high_findings": 5, "action": "proceed"},
            "low": {"action": "proceed"},
        },
        failure_policy={
            "critical": {"scan_failure": "block"},
            "high": {"scan_failure": "block"},
            "medium": {"scan_failure": "proceed"},
            "low": {"scan_failure": "proceed"},
        },
    )


@pytest.fixture
def sample_finding() -> Finding:
    """PCI-DSS-6.3.1 mapped semgrep finding fixture."""
    return Finding(
        source="semgrep",
        rule_id="python.django.security.injection.sql-injection",
        severity="high",
        file="src/api/export.py",
        line=42,
        message="Possible SQL injection via string concatenation",
        control_ids=["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
        product="payment-api",
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Mixed severity findings for gate/scoring tests."""
    return [
        Finding(
            source="semgrep",
            rule_id="python.django.security.injection.sql-injection",
            severity="high",
            file="src/api/export.py",
            line=42,
            message="Possible SQL injection",
            control_ids=["PCI-DSS-6.3.1"],
            product="payment-api",
        ),
        Finding(
            source="gitleaks",
            rule_id="aws-access-key",
            severity="critical",
            file="src/config.py",
            line=10,
            message="AWS access key detected",
            control_ids=["PCI-DSS-3.5.1"],
            product="payment-api",
        ),
        Finding(
            source="checkov",
            rule_id="CKV_AWS_19",
            severity="medium",
            file="terraform/s3.tf",
            line=5,
            message="S3 bucket without encryption",
            control_ids=["PCI-DSS-3.5.1"],
            product="payment-api",
        ),
        Finding(
            source="grype",
            rule_id="CVE-2023-1234",
            severity="low",
            file="requirements.txt",
            line=1,
            message="Known vulnerability in dependency",
            control_ids=[],
            product="payment-api",
        ),
    ]
