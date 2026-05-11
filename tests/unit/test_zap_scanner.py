"""Tests for ZAP DAST scanner wrapper."""

import json
from unittest.mock import MagicMock

import pytest

from orchestrator.scanners.zap import ZapScanner


@pytest.fixture
def mapper() -> MagicMock:
    m = MagicMock()
    m.map_finding.return_value = ["PCI-DSS-6.2.4"]
    return m


@pytest.fixture
def scanner(mapper: MagicMock) -> ZapScanner:
    return ZapScanner(control_mapper=mapper)


SAMPLE_ZAP_OUTPUT = json.dumps({
    "site": [
        {
            "@name": "http://127.0.0.1:8080",
            "alerts": [
                {
                    "pluginid": "40018",
                    "alertRef": "40018",
                    "name": "SQL Injection",
                    "riskcode": "3",
                    "riskdesc": "High (Medium)",
                    "confidence": "2",
                    "cweid": "89",
                    "desc": "SQL injection may be possible",
                    "solution": "Use parameterized queries",
                    "instances": [
                        {
                            "uri": "http://127.0.0.1:8080/api/export",
                            "method": "GET",
                            "param": "query",
                            "evidence": "SQL error",
                        },
                    ],
                    "count": "1",
                },
                {
                    "pluginid": "40012",
                    "alertRef": "40012",
                    "name": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "riskdesc": "High (Medium)",
                    "confidence": "2",
                    "cweid": "79",
                    "desc": "XSS found",
                    "solution": "Encode output",
                    "instances": [
                        {
                            "uri": "http://127.0.0.1:8080/api/export",
                            "method": "GET",
                            "param": "query",
                            "evidence": "<script>",
                        },
                    ],
                    "count": "1",
                },
                {
                    "pluginid": "10021",
                    "alertRef": "10021",
                    "name": "X-Content-Type-Options Header Missing",
                    "riskcode": "1",
                    "riskdesc": "Low (Medium)",
                    "confidence": "2",
                    "cweid": "693",
                    "desc": "Missing header",
                    "solution": "Add header",
                    "instances": [
                        {
                            "uri": "http://127.0.0.1:8080/api/login",
                            "method": "POST",
                            "param": "",
                        },
                        {
                            "uri": "http://127.0.0.1:8080/api/payment/create",
                            "method": "POST",
                            "param": "",
                        },
                    ],
                    "count": "2",
                },
            ],
        }
    ]
})


class TestZapScanner:
    def test_parse_output_returns_findings(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        assert len(findings) >= 3

    def test_parse_output_severity_mapping(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        severities = {f.rule_id: f.severity for f in findings}
        assert severities["ZAP-40018"] == "high"  # SQL Injection
        assert severities["ZAP-40012"] == "high"  # XSS

    def test_parse_output_source_is_zap(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        assert all(f.source == "zap" for f in findings)

    def test_parse_output_rule_id_format(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        assert all(f.rule_id.startswith("ZAP-") for f in findings)

    def test_parse_output_includes_cwe(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        sqli = next(f for f in findings if f.rule_id == "ZAP-40018")
        assert "CWE-89" in sqli.message

    def test_parse_output_includes_uri(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        sqli = next(f for f in findings if f.rule_id == "ZAP-40018")
        assert "/api/export" in sqli.file

    def test_parse_output_deduplicates_instances(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        header_findings = [f for f in findings if f.rule_id == "ZAP-10021"]
        # Two instances with different URIs → two findings
        assert len(header_findings) == 2

    def test_parse_output_maps_controls(self, scanner: ZapScanner, mapper: MagicMock) -> None:
        scanner.parse_output(SAMPLE_ZAP_OUTPUT)
        mapper.map_finding.assert_called()

    def test_parse_output_invalid_json(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output("not json")
        assert findings == []

    def test_parse_output_empty_site(self, scanner: ZapScanner) -> None:
        findings = scanner.parse_output('{"site": []}')
        assert findings == []

    def test_name_is_zap(self, scanner: ZapScanner) -> None:
        assert scanner.name == "zap"

    def test_scan_json_file(self, scanner: ZapScanner, tmp_path: object) -> None:
        """scan() with a .json path should parse existing results."""
        import pathlib

        p = pathlib.Path(str(tmp_path)) / "zap-results.json"
        p.write_text(SAMPLE_ZAP_OUTPUT)
        findings = scanner.scan(str(p))
        assert len(findings) >= 3
