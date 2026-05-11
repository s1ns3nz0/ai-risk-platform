"""SBOM Generator — generates CycloneDX SBOM using Syft."""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SbomResult:
    """SBOM generation result."""

    sbom_path: str
    format: str  # "cyclonedx-json"
    components_count: int
    raw_sbom: dict[str, object]


class SbomGenerator:
    """Generates CycloneDX SBOM from a target directory or container image.

    Uses Syft CLI: https://github.com/anchore/syft
    SBOM is stored as an evidence artifact for compliance traceability.
    """

    def generate(self, target: str, output_dir: str = "output") -> SbomResult:
        """Generate a CycloneDX JSON SBOM.

        Args:
            target: directory path (e.g., "./sample-app") or container image (e.g., "nginx:latest")
            output_dir: directory to store the SBOM file

        Returns:
            SbomResult with path to the generated SBOM file
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Determine output filename
        safe_name = target.replace("/", "_").replace(":", "_").replace(".", "_")
        sbom_path = str(Path(output_dir) / f"sbom-{safe_name}.cdx.json")

        result = subprocess.run(
            ["syft", target, "-o", "cyclonedx-json", "--file", sbom_path],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            msg = f"Syft SBOM generation failed: {result.stderr}"
            raise SbomGenerationError(msg)

        with open(sbom_path) as f:
            sbom_data = json.load(f)

        components = sbom_data.get("components", [])

        logger.info(
            "SBOM generated: %s (%d components)", sbom_path, len(components)
        )

        return SbomResult(
            sbom_path=sbom_path,
            format="cyclonedx-json",
            components_count=len(components),
            raw_sbom=sbom_data,
        )

    def parse_output(self, raw_output: str) -> SbomResult:
        """Parse raw Syft JSON output (for testing with fixtures)."""
        sbom_data = json.loads(raw_output)
        components = sbom_data.get("components", [])

        return SbomResult(
            sbom_path="",
            format="cyclonedx-json",
            components_count=len(components),
            raw_sbom=sbom_data,
        )


class SbomGenerationError(Exception):
    pass
