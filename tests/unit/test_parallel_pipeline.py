"""Tests for parallel per-finding assessment pipeline (step 2)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from orchestrator.rmf.models import SP80030Report
from orchestrator.rmf.pipeline import RiskAssessmentPipeline
from orchestrator.types import Finding, ProductManifest


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


def _make_5_findings() -> list[dict[str, object]]:
    """5 selected findings in _step1_gather dict format."""
    base = [
        ("semgrep", "sql-injection", "critical", "src/api/export.py", 42,
         "SQL injection via string concatenation", ["PCI-DSS-6.3.1", "ASVS-V5.3.4"]),
        ("gitleaks", "aws-access-key", "critical", "src/config.py", 10,
         "AWS access key detected", ["PCI-DSS-3.5.1"]),
        ("checkov", "CKV_AWS_19", "high", "terraform/s3.tf", 5,
         "S3 bucket without encryption", ["PCI-DSS-3.5.1"]),
        ("grype", "CVE-2023-1234", "medium", "requirements.txt", 1,
         "Known vulnerability in requests", ["PCI-DSS-6.3.1"]),
        ("semgrep", "logging-sensitive-data", "medium", "src/api/auth.py", 15,
         "Logging sensitive data", ["ASVS-V2.10.1"]),
    ]
    return [
        {
            "index": i,
            "source": src,
            "rule_id": rule,
            "severity": sev,
            "file": f,
            "line": ln,
            "message": msg,
            "control_ids": cids,
            "package": "",
            "installed_version": "",
            "fixed_version": "",
        }
        for i, (src, rule, sev, f, ln, msg, cids) in enumerate(base)
    ]


def _make_filtered(findings: list[dict[str, object]] | None = None) -> dict[str, object]:
    """Simulated _step2_filter output."""
    selected = findings or _make_5_findings()
    return {
        "selected_findings": selected,
        "relevant_controls": [
            {"id": "PCI-DSS-6.3.1", "title": "Secure Software Development", "framework": "pci-dss-4.0"},
            {"id": "PCI-DSS-3.5.1", "title": "Protect Stored Account Data", "framework": "pci-dss-4.0"},
            {"id": "ASVS-V5.3.4", "title": "Output Encoding", "framework": "asvs-5.0-L3"},
        ],
        "manifest": _make_manifest(),
        "epss_map": {
            "CVE-2023-1234": {"epss_score": 0.35, "epss_percentile": 0.92, "priority": "high"},
        },
        "n_findings": 6,
        "n_controls": 3,
        "trigger": "pr-merge",
        "findings": selected,
        "controls": [
            {"id": "PCI-DSS-6.3.1", "title": "Secure Software Development",
             "framework": "pci-dss-4.0", "description": "Develop software securely"},
            {"id": "PCI-DSS-3.5.1", "title": "Protect Stored Account Data",
             "framework": "pci-dss-4.0", "description": "Protect stored account data"},
            {"id": "ASVS-V5.3.4", "title": "Output Encoding",
             "framework": "asvs-5.0-L3", "description": "Verify output encoding"},
        ],
    }


def _mock_per_finding_response(finding_index: int) -> str:
    """Mock AI response for a single finding assessment."""
    te_id = f"TE-{finding_index + 1:03d}"
    return json.dumps({
        "threat_source": {
            "id": f"TS-ADV-{finding_index + 1:03d}",
            "type": "adversarial",
            "name": f"External attacker — finding {finding_index}",
            "capability": "high",
            "intent": "Financial gain",
            "targeting": "Targeted",
        },
        "threat_event": {
            "id": te_id,
            "description": f"Exploit finding {finding_index}",
            "source_id": f"TS-ADV-{finding_index + 1:03d}",
            "mitre_technique": "T1190",
            "relevance": "confirmed",
            "cve_id": "",
            "target_component": "src/api/export.py:42",
        },
        "likelihood": {
            "initiation_likelihood": "high",
            "impact_likelihood": "high",
            "overall_likelihood": "high",
            "epss_score": None,
            "predisposing_conditions": ["PCI scope"],
            "evidence": "Critical finding in PCI scope",
        },
        "impact": {
            "impact_type": "harm to operations",
            "cia_impact": {"confidentiality": "high", "integrity": "high", "availability": "moderate"},
            "severity": "high",
            "compliance_impact": ["PCI-DSS-6.3.1"],
            "business_impact": "Data exposure risk",
            "evidence": "PCI-scoped API",
        },
        "risk_determination": {
            "threat_event_id": te_id,
            "likelihood": "high",
            "impact": "high",
            "risk_level": "high",
            "risk_score": 64.0,
        },
        "risk_response": {
            "risk_determination_id": te_id,
            "response_type": "mitigate",
            "description": f"Fix finding {finding_index}",
            "milestones": ["Identify", "Fix", "Verify"],
            "deadline": "2026-06-01",
            "responsible": "Security Engineer",
        },
        "narrative": f"Finding {finding_index} poses high risk and should be remediated immediately.",
    })


def _mock_summary_response() -> str:
    """Mock AI response for summary synthesis."""
    return json.dumps({
        "executive_summary": "Payment API faces critical risk from multiple findings.",
        "cross_signal_insights": [
            "SQL injection + exposed credentials create escalation path.",
        ],
        "overall_risk_posture": "high",
        "recommendations": [
            "Fix SQL injection immediately",
            "Rotate exposed AWS credentials",
        ],
    })


# --- Tests ---


class TestParallel5FindingsAllSucceed:
    """test_parallel_5_findings_all_succeed: 5 mock AI → 5 AI results + summary, mode='ai'."""

    def test_parallel_5_findings_all_succeed(self) -> None:
        mock_client = MagicMock()

        # stream_with_cache called: 5 per-finding + 1 summary = 6 total
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(0),
            _mock_per_finding_response(1),
            _mock_per_finding_response(2),
            _mock_per_finding_response(3),
            _mock_per_finding_response(4),
            _mock_summary_response(),
        ]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        filtered = _make_filtered()
        assessment = pipeline._step3_assess(filtered)

        # All 5 per-finding results should be AI mode
        per_finding = assessment["per_finding_results"]
        assert len(per_finding) == 5
        assert all(r["mode"] == "ai" for r in per_finding)

        # Summary should exist
        assert "executive_summary" in assessment
        assert assessment["executive_summary"] != ""

        # 6 calls: 5 per-finding + 1 summary
        assert mock_client.stream_with_cache.call_count == 6


class TestParallel2Of5FailFallback:
    """test_parallel_2_of_5_fail_fallback: 2 fail → 3 AI + 2 static, mode='hybrid'."""

    def test_parallel_2_of_5_fail_fallback(self) -> None:
        mock_client = MagicMock()

        # Findings 1 and 3 fail, others succeed
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(0),
            Exception("Bedrock timeout"),
            _mock_per_finding_response(2),
            Exception("Bedrock throttled"),
            _mock_per_finding_response(4),
            _mock_summary_response(),
        ]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        filtered = _make_filtered()
        results = pipeline._assess_findings_parallel(filtered)

        modes = [r["mode"] for r in results]
        assert modes.count("ai") == 3
        assert modes.count("static") == 2


class TestParallelAllFailFullStatic:
    """test_parallel_all_fail_full_static: 5 all fail → 5 static + static summary, mode='static'."""

    def test_parallel_all_fail_full_static(self) -> None:
        mock_client = MagicMock()
        mock_client.stream_with_cache.side_effect = Exception("Bedrock down")

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        filtered = _make_filtered()
        assessment = pipeline._step3_assess(filtered)

        per_finding = assessment["per_finding_results"]
        assert len(per_finding) == 5
        assert all(r["mode"] == "static" for r in per_finding)

        # Summary should be static too
        assert "executive_summary" in assessment


class TestParallelProgressCallback:
    """test_parallel_progress_callback: callback called 5 times."""

    def test_parallel_progress_callback(self) -> None:
        mock_client = MagicMock()
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(i) for i in range(5)
        ]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        filtered = _make_filtered()

        progress_calls: list[tuple[int, int, str]] = []

        def on_progress(completed: int, total: int, finding_id: str) -> None:
            progress_calls.append((completed, total, finding_id))

        pipeline._assess_findings_parallel(filtered, progress_callback=on_progress)

        assert len(progress_calls) == 5
        # All should have total=5
        assert all(t == 5 for _, t, _ in progress_calls)
        # Completed should go 1..5 (in any order since as_completed)
        completed_values = sorted(c for c, _, _ in progress_calls)
        assert completed_values == [1, 2, 3, 4, 5]


class TestParallelNoBedrockUsesStatic:
    """test_parallel_no_bedrock_uses_static: bedrock_client=None → all static."""

    def test_parallel_no_bedrock_uses_static(self) -> None:
        pipeline = RiskAssessmentPipeline(bedrock_client=None)
        filtered = _make_filtered()
        assessment = pipeline._step3_assess(filtered)

        per_finding = assessment["per_finding_results"]
        assert len(per_finding) == 5
        assert all(r["mode"] == "static" for r in per_finding)


class TestSummaryReceivesAllNarratives:
    """test_summary_receives_all_narratives: summary prompt includes all 5 narratives."""

    def test_summary_receives_all_narratives(self) -> None:
        mock_client = MagicMock()
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(0),
            _mock_per_finding_response(1),
            _mock_per_finding_response(2),
            _mock_per_finding_response(3),
            _mock_per_finding_response(4),
            _mock_summary_response(),
        ]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)
        filtered = _make_filtered()
        pipeline._step3_assess(filtered)

        # The 6th call is the summary call — check its user_prompt
        summary_call = mock_client.stream_with_cache.call_args_list[5]
        user_prompt = summary_call[1].get("user_prompt") or summary_call[0][1]

        # All 5 narratives should appear in the summary user prompt
        for i in range(5):
            assert f"Finding {i}" in user_prompt


class TestReportModeHybrid:
    """test_report_mode_hybrid: mixed results → SP80030Report.mode == 'hybrid'."""

    def test_report_mode_hybrid(self) -> None:
        mock_client = MagicMock()

        # First call to invoke (filter step) + stream_with_cache for assess
        mock_client.invoke.return_value = json.dumps({
            "selected_finding_indices": [0, 1, 2, 3, 4],
            "reasoning": "Top 5.",
        })

        # Finding 2 fails, rest succeed
        mock_client.stream_with_cache.side_effect = [
            _mock_per_finding_response(0),
            _mock_per_finding_response(1),
            Exception("Bedrock error"),
            _mock_per_finding_response(3),
            _mock_per_finding_response(4),
            _mock_summary_response(),
        ]

        pipeline = RiskAssessmentPipeline(bedrock_client=mock_client)

        findings = [
            Finding(
                source=f["source"],  # type: ignore[arg-type]
                rule_id=f["rule_id"],  # type: ignore[arg-type]
                severity=f["severity"],  # type: ignore[arg-type]
                file=f["file"],  # type: ignore[arg-type]
                line=f["line"],  # type: ignore[arg-type]
                message=f["message"],  # type: ignore[arg-type]
                control_ids=list(f["control_ids"]),  # type: ignore[arg-type]
                product="payment-api",
            )
            for f in _make_5_findings()
        ] + [
            Finding(
                source="grype",
                rule_id="CVE-2023-9999",
                severity="low",
                file="requirements.txt",
                line=5,
                message="Low severity issue",
                control_ids=[],
                product="payment-api",
            ),
        ]

        from orchestrator.controls.models import Control, VerificationMethod
        from orchestrator.types import RiskTier

        report = pipeline.run(
            findings=findings,
            enriched_vulns=[],
            manifest=_make_manifest(),
            controls=[
                Control(
                    id="PCI-DSS-6.3.1",
                    title="Secure Software Development",
                    framework="pci-dss-4.0",
                    description="Develop software securely",
                    verification_methods=[VerificationMethod(scanner="semgrep")],
                    applicable_tiers=[RiskTier.CRITICAL],
                ),
            ],
            trigger="pr-merge",
        )

        assert isinstance(report, SP80030Report)
        assert report.mode == "hybrid"
