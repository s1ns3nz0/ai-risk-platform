"""Tests for OpaEvaluator — OPA/Rego policy gate layer."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from orchestrator.gate.opa import OpaEvaluator
from orchestrator.types import Finding, GateDecision


def _make_finding(
    severity: str = "high",
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


class TestNoRegoFilesPasses:
    def test_no_rego_files_passes(self, tmp_path: Path) -> None:
        """Empty rego/gates/ directory → PASS (no policies to evaluate)."""
        evaluator = OpaEvaluator(policies_dir=str(tmp_path))
        findings = [_make_finding(severity="critical")]
        context = {
            "product": "payment-api",
            "tier": "critical",
            "frameworks": ["pci-dss-4.0"],
            "findings_count": {"critical": 1},
            "pci_scope_count": 0,
            "secrets_count": 0,
        }
        decision = evaluator.evaluate(findings, context)
        assert decision.passed
        assert isinstance(decision, GateDecision)


class TestOpaNotInstalledPasses:
    def test_opa_not_installed_passes(self, tmp_path: Path) -> None:
        """OPA CLI not installed → graceful skip with warning, returns PASS."""
        # Create a .rego file so evaluator attempts OPA execution
        rego_file = tmp_path / "test.rego"
        rego_file.write_text("package gates\n")

        evaluator = OpaEvaluator(policies_dir=str(tmp_path))
        findings = [_make_finding(severity="critical")]
        context = {
            "product": "payment-api",
            "tier": "critical",
            "frameworks": ["pci-dss-4.0"],
            "findings_count": {"critical": 1},
            "pci_scope_count": 0,
            "secrets_count": 0,
        }

        with patch("orchestrator.gate.opa.subprocess.run", side_effect=FileNotFoundError("opa not found")):
            decision = evaluator.evaluate(findings, context)

        assert decision.passed
        assert "opa" in decision.reason.lower() or "skip" in decision.reason.lower()


class TestBuildInputFormat:
    def test_build_input_format(self, tmp_path: Path) -> None:
        """Verify OPA input JSON structure."""
        evaluator = OpaEvaluator(policies_dir=str(tmp_path))
        findings = [
            _make_finding(severity="critical", control_ids=["PCI-DSS-6.3.1"]),
            _make_finding(severity="high", source="gitleaks"),
        ]
        context = {
            "product": "payment-api",
            "tier": "critical",
            "frameworks": ["pci-dss-4.0", "asvs-4.0.3-L3"],
            "findings_count": {"critical": 1, "high": 1},
            "pci_scope_count": 1,
            "secrets_count": 1,
        }

        input_data = evaluator._build_input(findings, context)

        assert "findings" in input_data
        assert "context" in input_data
        assert len(input_data["findings"]) == 2
        assert input_data["context"]["product"] == "payment-api"
        assert input_data["context"]["tier"] == "critical"
        assert input_data["context"]["frameworks"] == ["pci-dss-4.0", "asvs-4.0.3-L3"]

        # Verify finding structure
        f0 = input_data["findings"][0]
        assert f0["source"] == "semgrep"
        assert f0["severity"] == "critical"
        assert f0["control_ids"] == ["PCI-DSS-6.3.1"]


class TestDenyMessagesInGateDecision:
    def test_deny_messages_in_gate_decision(self, tmp_path: Path) -> None:
        """Deny messages from OPA appear in GateDecision.reason."""
        rego_file = tmp_path / "security.rego"
        rego_file.write_text("package gates\n")

        evaluator = OpaEvaluator(policies_dir=str(tmp_path))
        findings = [_make_finding(severity="critical")]
        context = {
            "product": "payment-api",
            "tier": "critical",
            "frameworks": ["pci-dss-4.0"],
            "findings_count": {"critical": 1},
            "pci_scope_count": 0,
            "secrets_count": 0,
        }

        # Mock OPA returning deny messages
        deny_result = {
            "result": [
                {
                    "expressions": [
                        {
                            "value": [
                                "critical findings exceed limit for critical tier",
                                "secrets detected in PCI scope",
                            ],
                            "text": "data.gates.deny",
                        }
                    ]
                }
            ]
        }
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(deny_result)

        with patch("orchestrator.gate.opa.subprocess.run", return_value=mock_proc):
            decision = evaluator.evaluate(findings, context)

        assert not decision.passed
        assert "critical findings exceed limit" in decision.reason
        assert "secrets detected" in decision.reason


class TestOpaPassWhenNoDenials:
    def test_opa_pass_when_no_denials(self, tmp_path: Path) -> None:
        """OPA returns empty deny set → PASS."""
        rego_file = tmp_path / "security.rego"
        rego_file.write_text("package gates\n")

        evaluator = OpaEvaluator(policies_dir=str(tmp_path))
        findings = [_make_finding(severity="low")]
        context = {
            "product": "payment-api",
            "tier": "low",
            "frameworks": [],
            "findings_count": {"low": 1},
            "pci_scope_count": 0,
            "secrets_count": 0,
        }

        # Mock OPA returning empty deny set
        deny_result = {
            "result": [
                {
                    "expressions": [
                        {
                            "value": [],
                            "text": "data.gates.deny",
                        }
                    ]
                }
            ]
        }
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(deny_result)

        with patch("orchestrator.gate.opa.subprocess.run", return_value=mock_proc):
            decision = evaluator.evaluate(findings, context)

        assert decision.passed


class TestOpaFailClosed:
    """OPA errors should fail-closed (deny), not silently pass."""

    def test_nonzero_exit_code_denies(self, tmp_path: Path) -> None:
        """OPA crash/error → gate BLOCKED, not silently passed."""
        policies_dir = tmp_path / "gates"
        policies_dir.mkdir()
        (policies_dir / "test.rego").write_text("package gates\ndeny[msg] { msg := \"test\" }")

        evaluator = OpaEvaluator(str(policies_dir))
        context: dict[str, object] = {"tier": "critical", "findings_count": {}, "secrets_count": 0}

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "rego parse error"

        with patch("orchestrator.gate.opa.subprocess.run", return_value=mock_proc):
            decision = evaluator.evaluate([], context)

        assert not decision.passed
        assert "OPA evaluation error" in decision.reason

    def test_invalid_json_output_denies(self, tmp_path: Path) -> None:
        """Garbled OPA output → gate BLOCKED, not silently passed."""
        policies_dir = tmp_path / "gates"
        policies_dir.mkdir()
        (policies_dir / "test.rego").write_text("package gates\ndeny[msg] { msg := \"test\" }")

        evaluator = OpaEvaluator(str(policies_dir))
        context: dict[str, object] = {"tier": "critical", "findings_count": {}, "secrets_count": 0}

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "not valid json {{{}"

        with patch("orchestrator.gate.opa.subprocess.run", return_value=mock_proc):
            decision = evaluator.evaluate([], context)

        assert not decision.passed
        assert "invalid JSON" in decision.reason
