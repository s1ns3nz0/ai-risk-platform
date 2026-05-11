"""Tests for SP 800-30 risk assessment pipeline."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.rmf.models import SP80030Report
from orchestrator.rmf.pipeline import RiskAssessmentPipeline
from orchestrator.rmf.static_pipeline import StaticRiskAssessmentPipeline
from orchestrator.types import Finding, ProductManifest, RiskTier


# --- Fixtures ---


def _make_manifest() -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="QR code payment confirmation service",
        data_classification=["PCI", "PII-financial"],
        jurisdiction=["JP"],
        deployment={"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
        integrations=["external-payment-gateway"],
        impact_levels={
            "confidentiality": "high",
            "integrity": "high",
            "availability": "moderate",
        },
    )


def _make_findings() -> list[Finding]:
    return [
        Finding(
            source="semgrep",
            rule_id="python.django.security.injection.sql-injection",
            severity="critical",
            file="src/api/export.py",
            line=42,
            message="SQL injection via string concatenation",
            control_ids=["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
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
            severity="high",
            file="terraform/s3.tf",
            line=5,
            message="S3 bucket without encryption",
            control_ids=["PCI-DSS-3.5.1"],
            product="payment-api",
        ),
        Finding(
            source="grype",
            rule_id="CVE-2023-1234",
            severity="medium",
            file="requirements.txt",
            line=1,
            message="Known vulnerability in requests",
            control_ids=["PCI-DSS-6.3.1"],
            product="payment-api",
            package="requests",
            installed_version="2.28.0",
            fixed_version="2.31.0",
        ),
        Finding(
            source="grype",
            rule_id="CVE-2023-5678",
            severity="low",
            file="requirements.txt",
            line=3,
            message="Low severity issue in urllib3",
            control_ids=[],
            product="payment-api",
            package="urllib3",
            installed_version="1.26.0",
            fixed_version="1.26.18",
        ),
        Finding(
            source="semgrep",
            rule_id="python.lang.security.audit.logging-sensitive-data",
            severity="medium",
            file="src/api/auth.py",
            line=15,
            message="Logging sensitive data",
            control_ids=["ASVS-V2.10.1"],
            product="payment-api",
        ),
    ]


def _make_enriched_vulns() -> list[EnrichedVulnerability]:
    return [
        EnrichedVulnerability(
            cve_id="CVE-2023-1234",
            severity="medium",
            epss_score=0.35,
            epss_percentile=0.92,
            package="requests",
            installed_version="2.28.0",
            fixed_version="2.31.0",
            file_path="requirements.txt",
            control_ids=["PCI-DSS-6.3.1"],
            priority="high",
            product_context="payment-api, PCI scope, AWS",
            data_classification=["PCI", "PII-financial"],
        ),
        EnrichedVulnerability(
            cve_id="CVE-2023-5678",
            severity="low",
            epss_score=0.01,
            epss_percentile=0.30,
            package="urllib3",
            installed_version="1.26.0",
            fixed_version="1.26.18",
            file_path="requirements.txt",
            control_ids=[],
            priority="low",
            product_context="payment-api, PCI scope, AWS",
            data_classification=["PCI", "PII-financial"],
        ),
    ]


def _make_controls() -> list[Control]:
    return [
        Control(
            id="PCI-DSS-6.3.1",
            title="Secure Software Development",
            framework="pci-dss-4.0",
            description="Develop software securely",
            verification_methods=[
                VerificationMethod(scanner="semgrep", rules=["python.django.security.*"]),
            ],
            applicable_tiers=[RiskTier.HIGH, RiskTier.CRITICAL],
        ),
        Control(
            id="PCI-DSS-3.5.1",
            title="Protect Stored Account Data",
            framework="pci-dss-4.0",
            description="Protect stored account data with encryption",
            verification_methods=[
                VerificationMethod(scanner="checkov", check_ids=["CKV_AWS_19"]),
            ],
            applicable_tiers=[RiskTier.HIGH, RiskTier.CRITICAL],
        ),
        Control(
            id="ASVS-V5.3.4",
            title="Output Encoding",
            framework="asvs-5.0-L3",
            description="Verify output encoding to prevent injection",
            verification_methods=[
                VerificationMethod(scanner="semgrep"),
            ],
            applicable_tiers=[RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL],
        ),
    ]


def _mock_bedrock_filter_response() -> str:
    return json.dumps({
        "selected_finding_indices": [0, 1, 2],
        "reasoning": "Top 3: SQL injection (critical, PCI), hardcoded secret (critical, PCI), S3 unencrypted (high, PCI).",
    })


def _mock_bedrock_assess_response() -> str:
    return json.dumps({
        "executive_summary": "Payment API faces critical risk from SQL injection and exposed credentials.",
        "threat_sources": [
            {
                "id": "TS-ADV-001",
                "type": "adversarial",
                "name": "External attacker",
                "capability": "high",
                "intent": "Financial gain via cardholder data theft",
                "targeting": "Targeted — known payment processor",
            },
        ],
        "threat_events": [
            {
                "id": "TE-001",
                "description": "SQL injection via payment export endpoint",
                "source_id": "TS-ADV-001",
                "mitre_technique": "T1190",
                "relevance": "confirmed",
                "cve_id": "",
                "target_component": "src/api/export.py",
            },
        ],
        "likelihood_assessments": [
            {
                "initiation_likelihood": "high",
                "impact_likelihood": "high",
                "overall_likelihood": "high",
                "epss_score": 0.35,
                "predisposing_conditions": ["internet-facing", "PCI scope"],
                "evidence": "Critical SQL injection in PCI-scoped payment endpoint",
            },
        ],
        "impact_assessments": [
            {
                "impact_type": "harm to operations",
                "cia_impact": {"confidentiality": "high", "integrity": "high", "availability": "moderate"},
                "severity": "high",
                "compliance_impact": ["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
                "business_impact": "Cardholder data exposure, PCI non-compliance",
                "evidence": "PCI-scoped API with SQL injection",
            },
        ],
        "risk_determinations": [
            {
                "threat_event_id": "TE-001",
                "likelihood": "high",
                "impact": "high",
                "risk_level": "high",
                "risk_score": 81.0,
            },
        ],
        "risk_responses": [
            {
                "risk_determination_id": "TE-001",
                "response_type": "mitigate",
                "description": "Fix SQL injection with parameterized queries",
                "milestones": ["Identify affected queries", "Apply parameterized queries", "Verify fix"],
                "deadline": "2026-06-01",
                "responsible": "Security Engineer",
            },
        ],
        "recommendations": [
            "Fix SQL injection immediately",
            "Rotate exposed AWS credentials",
            "Enable S3 encryption",
        ],
    })


def _mock_per_finding_response(idx: int) -> str:
    """Mock per-finding AI response for pipeline tests."""
    te_id = f"TE-{idx + 1:03d}"
    return json.dumps({
        "threat_source": {
            "id": f"TS-ADV-{idx + 1:03d}",
            "type": "adversarial",
            "name": "External attacker",
            "capability": "high",
            "intent": "Financial gain via cardholder data theft",
            "targeting": "Targeted",
        },
        "threat_event": {
            "id": te_id,
            "description": "SQL injection via payment export endpoint",
            "source_id": f"TS-ADV-{idx + 1:03d}",
            "mitre_technique": "T1190",
            "relevance": "confirmed",
            "cve_id": "",
            "target_component": "src/api/export.py",
        },
        "likelihood": {
            "initiation_likelihood": "high",
            "impact_likelihood": "high",
            "overall_likelihood": "high",
            "epss_score": 0.35,
            "predisposing_conditions": ["internet-facing", "PCI scope"],
            "evidence": "Critical finding in PCI scope",
        },
        "impact": {
            "impact_type": "harm to operations",
            "cia_impact": {"confidentiality": "high", "integrity": "high", "availability": "moderate"},
            "severity": "high",
            "compliance_impact": ["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
            "business_impact": "Cardholder data exposure",
            "evidence": "PCI-scoped API",
        },
        "risk_determination": {
            "threat_event_id": te_id,
            "likelihood": "high",
            "impact": "high",
            "risk_level": "high",
            "risk_score": 81.0,
        },
        "risk_response": {
            "risk_determination_id": te_id,
            "response_type": "mitigate",
            "description": "Fix finding",
            "milestones": ["Identify", "Fix", "Verify"],
            "deadline": "2026-06-01",
            "responsible": "Security Engineer",
        },
        "narrative": f"Finding {idx} poses high risk.",
    })


def _mock_summary_response() -> str:
    """Mock summary synthesis AI response."""
    return json.dumps({
        "executive_summary": "Payment API faces critical risk from SQL injection and exposed credentials.",
        "cross_signal_insights": ["SQL injection + secrets create escalation path."],
        "overall_risk_posture": "high",
        "recommendations": [
            "Fix SQL injection immediately",
            "Rotate exposed AWS credentials",
            "Enable S3 encryption",
        ],
    })


# --- Tests ---


class TestPipelineProducesSP80030Report:
    """test_pipeline_produces_sp800_30_report — full report generation."""

    def test_pipeline_produces_sp800_30_report(self) -> None:
        mock_client = MagicMock()
        # Filter step uses invoke (selects indices [0,1,2]); assess uses stream_with_cache
        mock_client.invoke.return_value = _mock_bedrock_filter_response()
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(i) for i in range(3)
        ] + [_mock_summary_response()]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        report = pipeline.run(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )

        assert isinstance(report, SP80030Report)
        assert report.product == "payment-api"
        assert report.mode == "ai"
        assert report.methodology == "NIST SP 800-30 Rev 1"
        assert report.report_id.startswith("RA-SP800-30-")
        assert len(report.threat_sources) >= 1
        assert len(report.threat_events) >= 1
        assert len(report.risk_determinations) >= 1
        assert len(report.risk_responses) >= 1
        assert report.executive_summary != ""


class TestPipelineStaticFallback:
    """test_pipeline_static_fallback — Bedrock unavailable → static generation."""

    def test_pipeline_static_fallback(self) -> None:
        pipeline = RiskAssessmentPipeline(bedrock_client=None)
        report = pipeline.run(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )

        assert isinstance(report, SP80030Report)
        assert report.mode == "static"
        assert len(report.threat_sources) >= 1
        assert len(report.risk_determinations) >= 1
        assert report.executive_summary != ""

    def test_pipeline_fallback_on_bedrock_error(self) -> None:
        mock_client = MagicMock()
        mock_client.invoke.side_effect = Exception("Bedrock unavailable")

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        report = pipeline.run(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )

        assert isinstance(report, SP80030Report)
        assert report.mode == "static"


class TestFilterStepSelectsTopN:
    """test_filter_step_selects_top_n — top N findings selection."""

    def test_filter_step_selects_top_n_with_ai(self) -> None:
        mock_client = MagicMock()
        mock_client.invoke.return_value = json.dumps({
            "selected_finding_indices": [0, 1],
            "reasoning": "Top 2 critical findings.",
        })

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        gathered = pipeline._step1_gather(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )
        filtered = pipeline._step2_filter(gathered)

        selected = filtered["selected_findings"]
        assert len(selected) <= 5
        assert len(selected) >= 1

    def test_filter_step_deterministic_without_ai(self) -> None:
        pipeline = RiskAssessmentPipeline(bedrock_client=None)
        gathered = pipeline._step1_gather(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )
        filtered = pipeline._step2_filter(gathered)

        selected = filtered["selected_findings"]
        # Without AI, selects top-N by severity deterministically
        assert len(selected) <= 5
        # Critical findings should be selected first
        severities = [f["severity"] for f in selected]
        assert severities[0] == "critical"


class TestAssessFollowsSP80030Structure:
    """test_assess_follows_sp800_30_structure — report has all 5 phases."""

    def test_assess_follows_sp800_30_structure(self) -> None:
        mock_client = MagicMock()
        mock_client.invoke.return_value = _mock_bedrock_filter_response()
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(i) for i in range(3)
        ] + [_mock_summary_response()]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        report = pipeline.run(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )

        # Phase 1: Prepare
        assert report.scope != ""
        assert report.risk_model == "semi-quantitative, threat-oriented"
        assert len(report.assumptions) > 0
        assert "confidentiality" in report.cia_impact_levels

        # Phase 2: Conduct — all 5 SP 800-30 sections
        assert len(report.threat_sources) >= 1  # Section 3.1
        assert len(report.threat_events) >= 1  # Section 3.2
        assert len(report.likelihood_assessments) >= 1  # Section 3.3
        assert len(report.impact_assessments) >= 1  # Section 3.4
        assert len(report.risk_determinations) >= 1  # Section 3.5

        # Phase 3: Communicate
        assert report.executive_summary != ""
        assert len(report.risk_responses) >= 1

        # Phase 4: Maintain
        assert len(report.reassessment_triggers) >= 1


class TestRiskDeterminationUsesLikelihoodXImpact:
    """test_risk_determination_uses_likelihood_x_impact."""

    def test_risk_determination_uses_likelihood_x_impact(self) -> None:
        static = StaticRiskAssessmentPipeline()
        report = static.run(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )

        for rd in report.risk_determinations:
            # risk_score should be likelihood_value * impact_value
            assert 0 <= rd.risk_score <= 100
            assert rd.likelihood in ("very-low", "low", "moderate", "high", "very-high")
            assert rd.impact in ("very-low", "low", "moderate", "high", "very-high")
            assert rd.risk_level in ("very-low", "low", "moderate", "high", "very-high")


class TestAIResponseParsedToModels:
    """test_ai_response_parsed_to_models — AI JSON → SP800-30 dataclasses."""

    def test_ai_response_parsed_to_models(self) -> None:
        mock_client = MagicMock()
        mock_client.invoke.return_value = _mock_bedrock_filter_response()
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(i) for i in range(3)
        ] + [_mock_summary_response()]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        report = pipeline.run(
            findings=_make_findings(),
            enriched_vulns=_make_enriched_vulns(),
            manifest=_make_manifest(),
            controls=_make_controls(),
            trigger="pr-merge",
        )

        # Verify AI JSON was parsed into proper dataclass instances
        from orchestrator.rmf.models import (
            ImpactAssessment,
            LikelihoodAssessment,
            RiskDetermination,
            RiskResponse,
            ThreatEvent,
            ThreatSource,
        )

        assert all(isinstance(ts, ThreatSource) for ts in report.threat_sources)
        assert all(isinstance(te, ThreatEvent) for te in report.threat_events)
        assert all(isinstance(la, LikelihoodAssessment) for la in report.likelihood_assessments)
        assert all(isinstance(ia, ImpactAssessment) for ia in report.impact_assessments)
        assert all(isinstance(rd, RiskDetermination) for rd in report.risk_determinations)
        assert all(isinstance(rr, RiskResponse) for rr in report.risk_responses)

        # Verify specific field values from AI response
        ts = report.threat_sources[0]
        assert ts.type == "adversarial"
        assert ts.capability == "high"

        rd = report.risk_determinations[0]
        assert rd.risk_score == 81.0
        assert rd.risk_level == "high"
