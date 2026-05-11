"""Tests for scanner wrappers — parse_output() with fixture files."""

from __future__ import annotations

import json
import os

import pytest

from orchestrator.controls.repository import ControlsRepository
from orchestrator.scanners.checkov import CheckovScanner
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.scanners.gitleaks import GitleaksScanner
from orchestrator.scanners.grype import GrypeScanner
from orchestrator.scanners.semgrep import SemgrepScanner
from orchestrator.types import Finding

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "scanner-outputs")
BASELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "baselines")
TIER_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "tier-mappings.yaml")


@pytest.fixture
def mapper() -> ControlMapper:
    repo = ControlsRepository(baselines_dir=BASELINES_DIR, tier_mappings_path=TIER_MAPPINGS_PATH)
    repo.load_all()
    return ControlMapper(repo)


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path) as f:
        return f.read()


class TestCheckovParseOutput:
    def test_parses_failed_checks(self, mapper: ControlMapper) -> None:
        scanner = CheckovScanner(control_mapper=mapper)
        raw = _load_fixture("checkov_output.json")
        findings = scanner.parse_output(raw)

        assert len(findings) == 3
        for f in findings:
            assert isinstance(f, Finding)
            assert f.source == "checkov"

    def test_severity_mapping(self, mapper: ControlMapper) -> None:
        scanner = CheckovScanner(control_mapper=mapper)
        raw = _load_fixture("checkov_output.json")
        findings = scanner.parse_output(raw)

        by_rule = {f.rule_id: f for f in findings}
        assert by_rule["CKV_AWS_19"].severity == "high"
        assert by_rule["CKV_AWS_18"].severity == "medium"

    def test_file_and_line(self, mapper: ControlMapper) -> None:
        scanner = CheckovScanner(control_mapper=mapper)
        raw = _load_fixture("checkov_output.json")
        findings = scanner.parse_output(raw)

        by_rule = {f.rule_id: f for f in findings}
        assert by_rule["CKV_AWS_19"].file == "/s3.tf"
        assert by_rule["CKV_AWS_19"].line == 1


class TestCheckovMultiFrameworkOutput:
    def test_parses_list_format(self, mapper: ControlMapper) -> None:
        """Checkov outputs a list when scanning multiple frameworks."""
        scanner = CheckovScanner(control_mapper=mapper)
        multi_output = json.dumps([
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_19",
                            "check_name": "S3 encryption",
                            "file_path": "/main.tf",
                            "file_line_range": [10, 15],
                            "severity": "HIGH",
                        }
                    ]
                },
            },
            {
                "check_type": "secrets",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_SECRET_1",
                            "check_name": "Hardcoded secret",
                            "file_path": "/config.py",
                            "file_line_range": [3, 3],
                        }
                    ]
                },
            },
        ])
        findings = scanner.parse_output(multi_output)
        assert len(findings) == 2
        assert findings[0].rule_id == "CKV_AWS_19"
        assert findings[1].rule_id == "CKV_SECRET_1"

    def test_handles_empty_list(self, mapper: ControlMapper) -> None:
        scanner = CheckovScanner(control_mapper=mapper)
        findings = scanner.parse_output("[]")
        assert findings == []

    def test_handles_mixed_results(self, mapper: ControlMapper) -> None:
        """Some framework blocks may have no failed checks."""
        scanner = CheckovScanner(control_mapper=mapper)
        output = json.dumps([
            {"check_type": "terraform", "results": {"passed_checks": [], "failed_checks": []}},
            {"check_type": "secrets", "results": {"failed_checks": [
                {"check_id": "CKV_SECRET_2", "check_name": "Secret found", "file_path": "/app.py", "file_line_range": [1, 1]}
            ]}},
        ])
        findings = scanner.parse_output(output)
        assert len(findings) == 1
        assert findings[0].rule_id == "CKV_SECRET_2"


class TestCheckovFindingHasControlIds:
    def test_ckv_aws_19_has_control_ids(self, mapper: ControlMapper) -> None:
        scanner = CheckovScanner(control_mapper=mapper)
        raw = _load_fixture("checkov_output.json")
        findings = scanner.parse_output(raw)

        by_rule = {f.rule_id: f for f in findings}
        assert "PCI-DSS-3.5.1" in by_rule["CKV_AWS_19"].control_ids
        assert "FISC-実119" in by_rule["CKV_AWS_19"].control_ids


class TestSemgrepParseOutput:
    def test_parses_results(self, mapper: ControlMapper) -> None:
        scanner = SemgrepScanner(control_mapper=mapper)
        raw = _load_fixture("semgrep_output.json")
        findings = scanner.parse_output(raw)

        assert len(findings) == 3
        for f in findings:
            assert isinstance(f, Finding)
            assert f.source == "semgrep"

    def test_severity_mapping(self, mapper: ControlMapper) -> None:
        scanner = SemgrepScanner(control_mapper=mapper)
        raw = _load_fixture("semgrep_output.json")
        findings = scanner.parse_output(raw)

        by_rule = {f.rule_id: f for f in findings}
        # Semgrep ERROR → high, WARNING → medium
        assert by_rule["python.lang.security.injection.sql-injection"].severity == "high"
        assert by_rule[
            "python.lang.security.audit.hardcoded-password.hardcoded-password-default-arg"
        ].severity == "medium"


class TestSemgrepFindingHasControlIds:
    def test_sql_injection_maps_to_pci(self, mapper: ControlMapper) -> None:
        scanner = SemgrepScanner(control_mapper=mapper)
        raw = _load_fixture("semgrep_output.json")
        findings = scanner.parse_output(raw)

        by_rule = {f.rule_id: f for f in findings}
        sqli = by_rule["python.lang.security.injection.sql-injection"]
        assert "PCI-DSS-6.3.1" in sqli.control_ids
        assert "ASVS-V5.3.4" in sqli.control_ids


class TestGrypeParseOutput:
    def test_parses_matches(self, mapper: ControlMapper) -> None:
        scanner = GrypeScanner(control_mapper=mapper)
        raw = _load_fixture("grype_output.json")
        findings = scanner.parse_output(raw)

        assert len(findings) == 3
        for f in findings:
            assert isinstance(f, Finding)
            assert f.source == "grype"

    def test_severity_mapping(self, mapper: ControlMapper) -> None:
        scanner = GrypeScanner(control_mapper=mapper)
        raw = _load_fixture("grype_output.json")
        findings = scanner.parse_output(raw)

        by_rule = {f.rule_id: f for f in findings}
        assert by_rule["CVE-2023-50782"].severity == "critical"
        assert by_rule["CVE-2023-32681"].severity == "high"
        assert by_rule["CVE-2024-12345"].severity == "medium"

    def test_file_from_artifact_location(self, mapper: ControlMapper) -> None:
        scanner = GrypeScanner(control_mapper=mapper)
        raw = _load_fixture("grype_output.json")
        findings = scanner.parse_output(raw)

        for f in findings:
            assert f.file == "requirements.txt"


class TestGrypeFindingHasControlIds:
    def test_critical_cve_has_control_ids(self, mapper: ControlMapper) -> None:
        scanner = GrypeScanner(control_mapper=mapper)
        raw = _load_fixture("grype_output.json")
        findings = scanner.parse_output(raw)

        by_rule = {f.rule_id: f for f in findings}
        critical = by_rule["CVE-2023-50782"]
        assert "PCI-DSS-6.3.1" in critical.control_ids
        assert "ASVS-V14.2.1" in critical.control_ids


class TestGitleaksParseOutput:
    def test_parses_secrets(self, mapper: ControlMapper) -> None:
        scanner = GitleaksScanner(control_mapper=mapper)
        raw = _load_fixture("gitleaks_output.json")
        findings = scanner.parse_output(raw)

        assert len(findings) == 2
        for f in findings:
            assert isinstance(f, Finding)
            assert f.source == "gitleaks"
            assert f.severity == "critical"

    def test_rule_id_mapping(self, mapper: ControlMapper) -> None:
        scanner = GitleaksScanner(control_mapper=mapper)
        raw = _load_fixture("gitleaks_output.json")
        findings = scanner.parse_output(raw)

        rule_ids = {f.rule_id for f in findings}
        assert "aws-access-key-id" in rule_ids
        assert "generic-api-key" in rule_ids

    def test_finding_has_control_ids(self, mapper: ControlMapper) -> None:
        scanner = GitleaksScanner(control_mapper=mapper)
        raw = _load_fixture("gitleaks_output.json")
        findings = scanner.parse_output(raw)

        for f in findings:
            assert "PCI-DSS-3.6.1" in f.control_ids
            assert "ASVS-V2.10.1" in f.control_ids


class TestUnmappedRule:
    def test_unmapped_rule_returns_empty_control_ids(self, mapper: ControlMapper) -> None:
        scanner = SemgrepScanner(control_mapper=mapper)
        # Craft a raw output with an unknown rule
        raw = json.dumps({
            "results": [
                {
                    "check_id": "some.totally.unknown.rule",
                    "path": "foo.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "message": "Unknown rule",
                        "severity": "WARNING",
                        "metadata": {}
                    },
                }
            ],
            "errors": [],
        })
        findings = scanner.parse_output(raw)
        assert len(findings) == 1
        assert findings[0].control_ids == []
