"""Unit tests for DefectDojo client — no real API calls."""

from __future__ import annotations

from orchestrator.integrations.defectdojo import DefectDojoClient, finding_to_defectdojo
from orchestrator.types import Finding


def _make_finding(**overrides: object) -> Finding:
    defaults = {
        "source": "semgrep",
        "rule_id": "python.django.security.injection.sql-injection",
        "severity": "high",
        "file": "src/api/export.py",
        "line": 42,
        "message": "SQL injection detected",
        "control_ids": ["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
        "product": "payment-api",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestFindingToDefectdojoFormat:
    def test_required_fields_present(self) -> None:
        finding = _make_finding()
        result = finding_to_defectdojo(finding)

        assert finding.rule_id in result["title"]
        assert result["severity"] == "High"
        assert result["description"] == finding.message
        assert result["file_path"] == finding.file
        assert result["line"] == finding.line
        assert "hash_code" in result

    def test_severity_capitalized(self) -> None:
        for sev, expected in [
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Info"),
        ]:
            result = finding_to_defectdojo(_make_finding(severity=sev))
            assert result["severity"] == expected


class TestFindingHashDeterministic:
    def test_same_finding_same_hash(self) -> None:
        f1 = _make_finding()
        f2 = _make_finding()
        assert finding_to_defectdojo(f1)["hash_code"] == finding_to_defectdojo(f2)["hash_code"]

    def test_different_file_different_hash(self) -> None:
        f1 = _make_finding(file="a.py")
        f2 = _make_finding(file="b.py")
        assert finding_to_defectdojo(f1)["hash_code"] != finding_to_defectdojo(f2)["hash_code"]

    def test_different_line_different_hash(self) -> None:
        f1 = _make_finding(line=1)
        f2 = _make_finding(line=2)
        assert finding_to_defectdojo(f1)["hash_code"] != finding_to_defectdojo(f2)["hash_code"]


class TestFindingTagsIncludeControlIds:
    def test_control_ids_in_tags(self) -> None:
        finding = _make_finding(control_ids=["PCI-DSS-6.3.1", "ASVS-V5.3.4"])
        result = finding_to_defectdojo(finding)
        assert "PCI-DSS-6.3.1" in result["tags"]
        assert "ASVS-V5.3.4" in result["tags"]

    def test_empty_control_ids(self) -> None:
        finding = _make_finding(control_ids=[])
        result = finding_to_defectdojo(finding)
        assert result["tags"] == []


class TestHealthCheckReturnsFalseWhenDown:
    def test_health_check_connection_refused(self) -> None:
        client = DefectDojoClient(base_url="http://127.0.0.1:19999", api_key="test")
        assert client.health_check() is False
