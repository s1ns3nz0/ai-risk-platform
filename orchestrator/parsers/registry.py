"""Parser registry — auto-detects scanner type from result files.

Each parser extracts normalized Finding objects from a scanner's
output format. No scanner binaries required.

Supported formats (in priority order):
  1. SARIF 2.1.0 — universal format, works with ANY tool
     (Semgrep, Grype, Trivy, Bandit, Checkov, CodeQL, Snyk, Hadolint,
     Spotbugs, etc.)
  2. Native JSON — tool-specific parsers for non-SARIF output
     (Semgrep, Grype, Trivy, Gitleaks, Checkov, ZAP)

Aliases recognised at the HTTP layer (see server/app.py):
  grype-image    → grype     (same parser, different scan target)
  hadolint       → sarif     (hadolint emits SARIF natively)
  spotbugs       → sarif     (Spotbugs SARIF plugin output)
  trivy-sarif    → sarif     (when running `trivy --format sarif`)

Recommendation: Configure your scanners to output SARIF (--sarif flag).
This makes the platform truly tool-agnostic.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

# Scanner detection signatures — keys found in each scanner's JSON output
_SIGNATURES: dict[str, list[str]] = {
    "semgrep": ["results", "errors"],                  # Semgrep JSON has "results" array
    "grype": ["matches", "descriptor"],                 # Grype JSON has "matches" array
    "trivy": ["SchemaVersion", "ArtifactName", "Results"],  # Trivy native JSON
    "gitleaks": [],                                     # Gitleaks is a bare array of objects with "RuleID"
    "checkov": ["passed_checks", "failed_checks"],     # Checkov JSON
    "zap": ["site"],                                    # ZAP JSON has "site" array
}


def detect_scanner_from_content(data: object) -> str | None:
    """Detect scanner type from parsed JSON content (object or array).

    Single source of truth for inline (HTTP body) and file-based detection.
    """
    # Bare array → gitleaks format
    if isinstance(data, list):
        if data and isinstance(data[0], dict) and "RuleID" in data[0]:
            return "gitleaks"
        return None

    if not isinstance(data, dict):
        return None

    for scanner, keys in _SIGNATURES.items():
        if keys and all(k in data for k in keys):
            return scanner

    # SARIF — universal format
    if data.get("version") == "2.1.0" or "sarif" in str(data.get("$schema", "")):
        return "sarif"

    return None


def detect_scanner(file_path: str) -> str | None:
    """Detect which scanner produced a result file."""
    try:
        with open(file_path) as f:
            raw = f.read(8192)  # Read first 8KB for detection
        data = json.loads(raw if raw.strip().startswith("{") else "[" + raw.split("[", 1)[-1])
    except (json.JSONDecodeError, FileNotFoundError):
        return None
    return detect_scanner_from_content(data)


def parse_results_file(
    file_path: str,
    scanner_type: str | None,
    control_mapper: ControlMapper,
) -> list[Finding]:
    """Parse a single scanner result file into Findings.

    If scanner_type is None, auto-detects from file contents.
    """
    path = Path(file_path)
    if not path.exists():
        logger.warning("Result file not found: %s", file_path)
        return []

    raw = path.read_text()

    if scanner_type is None:
        scanner_type = detect_scanner(file_path)

    if scanner_type is None:
        logger.warning("Cannot detect scanner type for: %s", file_path)
        return []

    logger.info("Parsing %s as %s output", file_path, scanner_type)

    # Import the appropriate scanner's parse_output method
    if scanner_type == "semgrep":
        from orchestrator.scanners.semgrep import SemgrepScanner
        return SemgrepScanner(control_mapper).parse_output(raw)

    if scanner_type == "grype":
        from orchestrator.scanners.grype import GrypeScanner
        return GrypeScanner(control_mapper).parse_output(raw)

    if scanner_type == "gitleaks":
        from orchestrator.scanners.gitleaks import GitleaksScanner
        return GitleaksScanner(control_mapper).parse_output(raw)

    if scanner_type == "checkov":
        from orchestrator.scanners.checkov import CheckovScanner
        return CheckovScanner(control_mapper).parse_output(raw)

    if scanner_type == "zap":
        from orchestrator.scanners.zap import ZapScanner
        return ZapScanner(control_mapper).parse_output(raw)

    if scanner_type == "trivy":
        from orchestrator.scanners.trivy import TrivyScanner
        return TrivyScanner(control_mapper).parse_output(raw)

    if scanner_type == "sarif":
        from orchestrator.parsers.sarif import parse_sarif
        return parse_sarif(raw, control_mapper)

    logger.warning("Unsupported scanner type: %s", scanner_type)
    return []


def parse_results_directory(
    results_dir: str,
    control_mapper: ControlMapper,
) -> list[Finding]:
    """Parse all scanner result files in a directory.

    Auto-detects scanner type for each JSON file.
    Returns aggregated findings from all files.
    """
    results_path = Path(results_dir)
    if not results_path.is_dir():
        logger.error("Results directory not found: %s", results_dir)
        return []

    all_findings: list[Finding] = []
    json_files = sorted(results_path.glob("*.json"))

    if not json_files:
        logger.warning("No JSON files found in %s", results_dir)
        return []

    for json_file in json_files:
        scanner_type = detect_scanner(str(json_file))
        if scanner_type:
            findings = parse_results_file(str(json_file), scanner_type, control_mapper)
            all_findings.extend(findings)
            logger.info(
                "  %s → %s: %d findings",
                json_file.name, scanner_type, len(findings),
            )
        else:
            logger.debug("  %s → skipped (unknown format)", json_file.name)

    logger.info(
        "Parsed %d files → %d total findings from %s",
        len(json_files), len(all_findings), results_dir,
    )
    return all_findings
