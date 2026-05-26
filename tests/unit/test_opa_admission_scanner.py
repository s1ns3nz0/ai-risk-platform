"""Tests for OpaAdmissionScanner — Gatekeeper / Kyverno violation parsing."""

from __future__ import annotations

import json
import os

import pytest

from orchestrator.controls.repository import ControlsRepository
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.scanners.opa_admission import OpaAdmissionScanner

BASELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "baselines")
TIER_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "tier-mappings.yaml")


@pytest.fixture
def mapper() -> ControlMapper:
    repo = ControlsRepository(baselines_dir=BASELINES_DIR, tier_mappings_path=TIER_MAPPINGS_PATH)
    repo.load_all()
    return ControlMapper(repo)


class TestOpaAdmissionNoViolations:
    def test_empty_violations_produces_no_findings(self, mapper: ControlMapper) -> None:
        """Zero admission violations is the satisfied path → no findings."""
        scanner = OpaAdmissionScanner(mapper)
        assert scanner.parse_output(json.dumps({"violations": []})) == []


class TestOpaAdmissionViolations:
    def test_gatekeeper_violation_produces_finding(self, mapper: ControlMapper) -> None:
        scanner = OpaAdmissionScanner(mapper)
        raw = json.dumps({
            "violations": [
                {
                    "policy": "K8sRequireImageSignature",
                    "engine": "gatekeeper",
                    "severity": "critical",
                    "resource": "Deployment/payment-api",
                    "namespace": "prod",
                    "message": "image does not have a verified signature",
                }
            ]
        })
        findings = scanner.parse_output(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.source == "opa-admission"
        assert f.severity == "critical"
        assert f.rule_id == "K8sRequireImageSignature"
        assert f.file == "prod/Deployment/payment-api"
        assert "gatekeeper" in f.message
        assert "K8sRequireImageSignature" in f.message

    def test_kyverno_violation_without_severity_defaults_to_high(self, mapper: ControlMapper) -> None:
        scanner = OpaAdmissionScanner(mapper)
        raw = json.dumps({
            "violations": [
                {
                    "policy": "disallow-host-namespace",
                    "engine": "kyverno",
                    "resource": "Pod/web",
                    "namespace": "default",
                    "message": "host namespace is not allowed",
                }
            ]
        })
        findings = scanner.parse_output(raw)

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].rule_id == "disallow-host-namespace"

    def test_unknown_severity_clamped_to_default(self, mapper: ControlMapper) -> None:
        """Garbage severity must not corrupt the gate counters."""
        scanner = OpaAdmissionScanner(mapper)
        raw = json.dumps({
            "violations": [
                {"policy": "x", "engine": "kyverno", "severity": "FATAL", "message": "bad"}
            ]
        })
        findings = scanner.parse_output(raw)

        assert findings[0].severity == "high"  # _DEFAULT_SEVERITY

    def test_multiple_violations_become_multiple_findings(self, mapper: ControlMapper) -> None:
        scanner = OpaAdmissionScanner(mapper)
        raw = json.dumps({
            "violations": [
                {"policy": "a", "engine": "gatekeeper", "message": "1"},
                {"policy": "b", "engine": "gatekeeper", "message": "2"},
                {"policy": "c", "engine": "kyverno",    "message": "3"},
            ]
        })
        assert len(scanner.parse_output(raw)) == 3


class TestOpaAdmissionInputShapes:
    def test_bare_list_accepted(self, mapper: ControlMapper) -> None:
        scanner = OpaAdmissionScanner(mapper)
        raw = json.dumps([
            {"policy": "x", "engine": "gatekeeper", "message": "fail"},
        ])
        assert len(scanner.parse_output(raw)) == 1

    def test_invalid_json_returns_empty(self, mapper: ControlMapper) -> None:
        scanner = OpaAdmissionScanner(mapper)
        assert scanner.parse_output("nope") == []
