"""Tests for framework importer: OSCAL parser, generic parser, baseline generator."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from orchestrator.importer.oscal import ImportedControl, OscalParser
from orchestrator.importer.generic import GenericFrameworkParser
from orchestrator.importer.baseline import BaselineGenerator

FIXTURES = Path(__file__).parent.parent / "fixtures" / "oscal"


# ── OscalParser ──────────────────────────────────────────────


class TestOscalParserCatalog:
    """test_parse_oscal_catalog — 2개 컨트롤 파싱."""

    def test_parse_oscal_catalog(self) -> None:
        parser = OscalParser()
        controls = parser.parse_file(
            str(FIXTURES / "nist-800-53-sample.json"),
            framework_id="nist-800-53-r5",
        )
        assert len(controls) == 2
        assert all(isinstance(c, ImportedControl) for c in controls)

    def test_control_has_id_title_description(self) -> None:
        parser = OscalParser()
        controls = parser.parse_file(
            str(FIXTURES / "nist-800-53-sample.json"),
            framework_id="nist-800-53-r5",
        )
        ac1 = controls[0]
        assert ac1.id == "ac-1"
        assert ac1.title == "Policy and Procedures"
        assert ac1.description == "Develop and maintain access control policy."
        assert ac1.framework == "nist-800-53-r5"

    def test_control_properties_from_props(self) -> None:
        parser = OscalParser()
        controls = parser.parse_file(
            str(FIXTURES / "nist-800-53-sample.json"),
            framework_id="nist-800-53-r5",
        )
        ac1 = controls[0]
        assert ac1.properties.get("label") == "AC-1"
        # ac-2 has no props
        ac2 = controls[1]
        assert ac2.properties == {}


class TestOscalParserNestedGroups:
    """test_nested_groups — 중첩 그룹 처리."""

    def test_nested_groups(self) -> None:
        parser = OscalParser()
        controls = parser.parse_file(
            str(FIXTURES / "nested-groups-sample.json"),
            framework_id="nested-test",
        )
        ids = [c.id for c in controls]
        assert "outer-1" in ids
        assert "inner-1" in ids
        assert len(controls) == 2


class TestOscalParserSubControls:
    """controls 내 sub-controls(enhancements)도 포함."""

    def test_sub_controls_included(self) -> None:
        catalog = {
            "catalog": {
                "uuid": "sub-test",
                "metadata": {"title": "Sub Test", "version": "1.0"},
                "groups": [
                    {
                        "id": "ac",
                        "title": "Access Control",
                        "controls": [
                            {
                                "id": "ac-1",
                                "title": "Parent",
                                "parts": [
                                    {
                                        "name": "statement",
                                        "prose": "Parent control.",
                                    }
                                ],
                                "controls": [
                                    {
                                        "id": "ac-1.1",
                                        "title": "Enhancement One",
                                        "parts": [
                                            {
                                                "name": "statement",
                                                "prose": "First enhancement.",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }
        parser = OscalParser()
        controls = parser._parse_catalog(catalog["catalog"], "test-fw")
        ids = [c.id for c in controls]
        assert "ac-1" in ids
        assert "ac-1.1" in ids


class TestOscalParserUrl:
    """test_parse_url — URL 다운로드 mock."""

    @patch("orchestrator.importer.oscal.urlopen")
    def test_parse_url(self, mock_urlopen: MagicMock) -> None:
        sample_path = FIXTURES / "nist-800-53-sample.json"
        sample_data = sample_path.read_bytes()

        mock_response = MagicMock()
        mock_response.read.return_value = sample_data
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        parser = OscalParser()
        controls = parser.parse_url(
            "https://example.com/catalog.json",
            framework_id="nist-800-53-r5",
        )
        assert len(controls) == 2
        mock_urlopen.assert_called_once_with("https://example.com/catalog.json")


# ── BaselineGenerator ────────────────────────────────────────


class TestBaselineGenerator:
    """test_generate_baseline_yaml — YAML 출력 형식 검증."""

    def test_generate_baseline_yaml(self, tmp_path: Path) -> None:
        controls = [
            ImportedControl(
                id="AC-1",
                title="Policy and Procedures",
                description="Develop access control policy.",
                framework="nist-800-53-r5",
                properties={"label": "AC-1"},
            ),
        ]
        output = tmp_path / "nist-800-53-r5.yaml"
        gen = BaselineGenerator()
        result = gen.generate(controls, str(output))

        assert result == str(output)
        assert output.exists()

        data = yaml.safe_load(output.read_text())
        assert "controls" in data
        assert len(data["controls"]) == 1

        ctrl = data["controls"][0]["control"]
        assert ctrl["id"] == "AC-1"
        assert ctrl["title"] == "Policy and Procedures"
        assert ctrl["framework"] == "nist-800-53-r5"
        assert ctrl["description"] == "Develop access control policy."

    def test_generated_yaml_has_empty_verification_methods(
        self, tmp_path: Path
    ) -> None:
        controls = [
            ImportedControl(
                id="AC-2",
                title="Account Management",
                description="Manage accounts.",
                framework="nist-800-53-r5",
                properties={},
            ),
        ]
        output = tmp_path / "test.yaml"
        gen = BaselineGenerator()
        gen.generate(controls, str(output))

        data = yaml.safe_load(output.read_text())
        ctrl = data["controls"][0]["control"]
        assert ctrl["verification_methods"] == []

    def test_applicable_tiers_default(self, tmp_path: Path) -> None:
        controls = [
            ImportedControl(
                id="X-1",
                title="Test",
                description="Desc.",
                framework="fw",
                properties={},
            ),
        ]
        output = tmp_path / "test.yaml"
        gen = BaselineGenerator()
        gen.generate(controls, str(output))

        data = yaml.safe_load(output.read_text())
        ctrl = data["controls"][0]["control"]
        assert ctrl["applicable_tiers"] == ["high", "critical"]

    def test_applicable_tiers_custom(self, tmp_path: Path) -> None:
        controls = [
            ImportedControl(
                id="X-1",
                title="Test",
                description="Desc.",
                framework="fw",
                properties={},
            ),
        ]
        output = tmp_path / "test.yaml"
        gen = BaselineGenerator()
        gen.generate(controls, str(output), applicable_tiers=["low", "medium", "high", "critical"])

        data = yaml.safe_load(output.read_text())
        ctrl = data["controls"][0]["control"]
        assert ctrl["applicable_tiers"] == ["low", "medium", "high", "critical"]


# ── GenericFrameworkParser ────────────────────────────────────


class TestGenericFrameworkParserAsvs:
    """test_parse_asvs_json — ASVS JSON 파싱."""

    def test_parse_asvs_json_all_levels(self) -> None:
        parser = GenericFrameworkParser()
        controls = parser.parse_asvs_json(
            str(FIXTURES / "asvs-sample.json"), level=3
        )
        assert len(controls) == 3

    def test_parse_asvs_json_level_filter(self) -> None:
        parser = GenericFrameworkParser()
        controls = parser.parse_asvs_json(
            str(FIXTURES / "asvs-sample.json"), level=1
        )
        # Only V2.1.1 is required at L1
        assert len(controls) == 1
        assert controls[0].id == "V2.1.1"

    def test_parse_asvs_json_level2(self) -> None:
        parser = GenericFrameworkParser()
        controls = parser.parse_asvs_json(
            str(FIXTURES / "asvs-sample.json"), level=2
        )
        # V2.1.1 and V5.3.4 are required at L2
        assert len(controls) == 2
        ids = [c.id for c in controls]
        assert "V2.1.1" in ids
        assert "V5.3.4" in ids

    def test_asvs_control_fields(self) -> None:
        parser = GenericFrameworkParser()
        controls = parser.parse_asvs_json(
            str(FIXTURES / "asvs-sample.json"), level=3
        )
        v2 = next(c for c in controls if c.id == "V2.1.1")
        assert v2.title == "Password Security"
        assert v2.framework == "owasp-asvs"
        assert "12 characters" in v2.description


class TestGenericFrameworkParserGenericJson:
    """parse_generic_json — 커스텀 JSON 매핑."""

    def test_parse_generic_json(self, tmp_path: Path) -> None:
        data = [
            {
                "control_id": "CIS-1.1",
                "name": "Ensure MFA",
                "detail": "Multi-factor authentication enabled.",
            }
        ]
        f = tmp_path / "custom.json"
        f.write_text(json.dumps(data))

        parser = GenericFrameworkParser()
        controls = parser.parse_generic_json(
            str(f),
            framework_id="cis-v8",
            id_field="control_id",
            title_field="name",
            description_field="detail",
        )
        assert len(controls) == 1
        assert controls[0].id == "CIS-1.1"
        assert controls[0].title == "Ensure MFA"
        assert controls[0].framework == "cis-v8"
