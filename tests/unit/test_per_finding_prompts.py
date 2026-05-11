"""Tests for per-finding SP 800-30 prompt builders (TDD — step 1)."""

from __future__ import annotations

from orchestrator.rmf.prompts import build_per_finding_prompts, build_summary_prompts
from orchestrator.types import ProductManifest


def _make_manifest() -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="QR code payment processing API",
        data_classification=["PCI", "PII-financial"],
        jurisdiction=["JP"],
        deployment={"cloud": "aws", "region": "ap-northeast-1"},
        impact_levels={
            "confidentiality": "high",
            "integrity": "high",
            "availability": "moderate",
        },
    )


def _make_finding() -> dict[str, object]:
    return {
        "source": "semgrep",
        "rule_id": "python.django.security.injection.sql-injection",
        "severity": "high",
        "file": "src/api/export.py",
        "line": 42,
        "message": "SQL injection via string concatenation",
        "control_ids": ["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
        "package": "",
        "installed_version": "",
        "fixed_version": "",
    }


def _make_controls() -> list[dict[str, object]]:
    return [
        {
            "id": "PCI-DSS-6.3.1",
            "title": "Secure software development",
            "framework": "PCI-DSS-4.0",
            "description": "Develop software securely",
        },
    ]


def _make_epss() -> dict[str, object]:
    return {"epss_score": 0.87, "epss_percentile": 0.95, "priority": "critical"}


# --- Per-finding prompt tests ---


def test_per_finding_system_prompt_contains_methodology() -> None:
    manifest = _make_manifest()
    finding = _make_finding()
    system_prompt, _ = build_per_finding_prompts(
        manifest=manifest, finding=finding, controls=_make_controls(), epss_data=None,
    )
    assert "SP 800-30" in system_prompt


def test_per_finding_system_prompt_contains_architecture() -> None:
    manifest = _make_manifest()
    finding = _make_finding()
    system_prompt, _ = build_per_finding_prompts(
        manifest=manifest, finding=finding, controls=_make_controls(), epss_data=None,
    )
    assert "payment-api" in system_prompt
    assert "high" in system_prompt.lower()  # CIA levels


def test_per_finding_user_prompt_contains_finding() -> None:
    manifest = _make_manifest()
    finding = _make_finding()
    _, user_prompt = build_per_finding_prompts(
        manifest=manifest, finding=finding, controls=_make_controls(), epss_data=None,
    )
    assert "python.django.security.injection.sql-injection" in user_prompt
    assert "high" in user_prompt.lower()
    assert "src/api/export.py" in user_prompt


def test_per_finding_user_prompt_contains_epss() -> None:
    manifest = _make_manifest()
    finding = _make_finding()
    epss = _make_epss()
    _, user_prompt = build_per_finding_prompts(
        manifest=manifest, finding=finding, controls=_make_controls(), epss_data=epss,
    )
    assert "0.87" in user_prompt


# --- Summary synthesis prompt tests ---


def test_summary_system_prompt_contains_cross_signal() -> None:
    manifest = _make_manifest()
    per_finding_results = [
        {"narrative": f"Finding {i} narrative about risk."} for i in range(5)
    ]
    system_prompt, _ = build_summary_prompts(
        manifest=manifest,
        per_finding_results=per_finding_results,
        total_findings=20,
        severity_counts={"critical": 3, "high": 7, "medium": 5, "low": 5},
    )
    assert "cross-signal" in system_prompt.lower() or "correlation" in system_prompt.lower()


def test_summary_user_prompt_contains_all_narratives() -> None:
    manifest = _make_manifest()
    per_finding_results = [
        {"narrative": f"Narrative-{i}-unique-marker"} for i in range(5)
    ]
    _, user_prompt = build_summary_prompts(
        manifest=manifest,
        per_finding_results=per_finding_results,
        total_findings=20,
        severity_counts={"critical": 3, "high": 7, "medium": 5, "low": 5},
    )
    for i in range(5):
        assert f"Narrative-{i}-unique-marker" in user_prompt
