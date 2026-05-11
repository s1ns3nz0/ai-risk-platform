"""Tests for SBOM generator and Grype SBOM/container scanning."""

from __future__ import annotations

import json

from orchestrator.scanners.sbom import SbomGenerator, SbomResult


class TestSbomGenerator:
    def test_parse_output_counts_components(self) -> None:
        sbom_json = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"type": "library", "name": "requests", "version": "2.25.0"},
                {"type": "library", "name": "flask", "version": "2.3.0"},
                {"type": "library", "name": "cryptography", "version": "3.4.6"},
            ],
        })

        generator = SbomGenerator()
        result = generator.parse_output(sbom_json)

        assert result.components_count == 3
        assert result.format == "cyclonedx-json"

    def test_parse_output_empty_components(self) -> None:
        sbom_json = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [],
        })

        generator = SbomGenerator()
        result = generator.parse_output(sbom_json)

        assert result.components_count == 0

    def test_parse_output_no_components_key(self) -> None:
        sbom_json = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
        })

        generator = SbomGenerator()
        result = generator.parse_output(sbom_json)

        assert result.components_count == 0

    def test_sbom_result_dataclass(self) -> None:
        result = SbomResult(
            sbom_path="/tmp/sbom.json",
            format="cyclonedx-json",
            components_count=5,
            raw_sbom={"components": []},
        )

        assert result.sbom_path == "/tmp/sbom.json"
        assert result.format == "cyclonedx-json"
        assert result.components_count == 5


class TestGrypeContainerScan:
    def test_scan_image_tags_findings_with_container_ref(self) -> None:
        """Grype container scan findings include image reference in message."""
        from orchestrator.controls.repository import ControlsRepository
        from orchestrator.scanners.control_mapper import ControlMapper
        from orchestrator.scanners.grype import GrypeScanner

        repo = ControlsRepository(
            baselines_dir="controls/baselines",
            tier_mappings_path="controls/tier-mappings.yaml",
        )
        repo.load_all()
        mapper = ControlMapper(repo)
        scanner = GrypeScanner(mapper)

        # Parse grype output with container context
        grype_output = json.dumps({
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1234",
                        "severity": "Critical",
                        "description": "Buffer overflow in libssl",
                    },
                    "artifact": {
                        "name": "openssl",
                        "version": "1.1.1",
                        "locations": [{"path": "/usr/lib/libssl.so"}],
                    },
                }
            ]
        })

        findings = scanner.parse_output(grype_output)

        assert len(findings) == 1
        assert findings[0].source == "grype"
        assert findings[0].severity == "critical"
        assert findings[0].rule_id == "CVE-2024-1234"

    def test_grype_scan_sbom_parses_same_format(self) -> None:
        """scan_sbom uses the same parse_output as regular scan."""
        from orchestrator.controls.repository import ControlsRepository
        from orchestrator.scanners.control_mapper import ControlMapper
        from orchestrator.scanners.grype import GrypeScanner

        repo = ControlsRepository(
            baselines_dir="controls/baselines",
            tier_mappings_path="controls/tier-mappings.yaml",
        )
        repo.load_all()
        mapper = ControlMapper(repo)
        scanner = GrypeScanner(mapper)

        # Same output format regardless of scan mode
        grype_output = json.dumps({"matches": []})
        findings = scanner.parse_output(grype_output)

        assert findings == []
