"""Tests for delta assessment — incremental risk evaluation."""

from __future__ import annotations

from pathlib import Path

import yaml

from orchestrator.rmf.delta import (
    FindingDelta,
    compute_delta,
    format_delta_for_ai,
    save_baseline,
)
from orchestrator.types import Finding


def _make_finding(
    rule_id: str = "CVE-2023-50782",
    severity: str = "high",
    source: str = "grype",
    file: str = "requirements.txt",
) -> Finding:
    return Finding(
        source=source,
        rule_id=rule_id,
        severity=severity,
        file=file,
        line=0,
        message="test",
        control_ids=["PCI-DSS-6.3.1"],
        product="test",
    )


class TestComputeDelta:
    def test_no_baseline_all_new(self, tmp_path: Path) -> None:
        findings = [_make_finding("CVE-001"), _make_finding("CVE-002")]
        delta = compute_delta(findings, str(tmp_path / "nonexistent.yaml"))

        assert len(delta.new_findings) == 2
        assert len(delta.resolved_findings) == 0
        assert delta.unchanged_count == 0
        assert delta.has_changes

    def test_identical_findings_no_changes(self, tmp_path: Path) -> None:
        findings = [_make_finding("CVE-001"), _make_finding("CVE-002")]
        baseline_path = str(tmp_path / "baseline.yaml")

        save_baseline(findings, baseline_path)
        delta = compute_delta(findings, baseline_path)

        assert len(delta.new_findings) == 0
        assert len(delta.resolved_findings) == 0
        assert delta.unchanged_count == 2
        assert not delta.has_changes

    def test_new_finding_detected(self, tmp_path: Path) -> None:
        old = [_make_finding("CVE-001")]
        new = [_make_finding("CVE-001"), _make_finding("CVE-NEW")]
        baseline_path = str(tmp_path / "baseline.yaml")

        save_baseline(old, baseline_path)
        delta = compute_delta(new, baseline_path)

        assert len(delta.new_findings) == 1
        assert delta.new_findings[0].rule_id == "CVE-NEW"
        assert delta.unchanged_count == 1

    def test_resolved_finding_detected(self, tmp_path: Path) -> None:
        old = [_make_finding("CVE-001"), _make_finding("CVE-FIXED")]
        new = [_make_finding("CVE-001")]
        baseline_path = str(tmp_path / "baseline.yaml")

        save_baseline(old, baseline_path)
        delta = compute_delta(new, baseline_path)

        assert len(delta.resolved_findings) == 1
        assert delta.resolved_findings[0]["rule_id"] == "CVE-FIXED"

    def test_severity_change_detected(self, tmp_path: Path) -> None:
        old = [_make_finding("CVE-001", severity="medium")]
        new = [_make_finding("CVE-001", severity="critical")]
        baseline_path = str(tmp_path / "baseline.yaml")

        save_baseline(old, baseline_path)
        delta = compute_delta(new, baseline_path)

        assert len(delta.changed_severity) == 1
        assert delta.changed_severity[0]["old_severity"] == "medium"
        assert delta.changed_severity[0]["new_severity"] == "critical"


class TestSaveBaseline:
    def test_saves_yaml(self, tmp_path: Path) -> None:
        findings = [_make_finding("CVE-001"), _make_finding("CVE-002")]
        path = str(tmp_path / "baseline.yaml")

        save_baseline(findings, path)

        data = yaml.safe_load(Path(path).read_text())
        assert data["findings_count"] == 2
        assert len(data["findings"]) == 2

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        path = str(tmp_path / "deep" / "nested" / "baseline.yaml")
        save_baseline([_make_finding()], path)
        assert Path(path).exists()


class TestFormatDelta:
    def test_format_new_findings(self) -> None:
        delta = FindingDelta(
            new_findings=[_make_finding("CVE-NEW")],
            unchanged_count=5,
        )
        text = format_delta_for_ai(delta)

        assert "NEW FINDINGS (1)" in text
        assert "CVE-NEW" in text
        assert "UNCHANGED: 5" in text

    def test_format_resolved(self) -> None:
        delta = FindingDelta(
            resolved_findings=[{"rule_id": "CVE-FIXED", "source": "grype"}],
            unchanged_count=3,
        )
        text = format_delta_for_ai(delta)

        assert "RESOLVED FINDINGS (1)" in text
        assert "CVE-FIXED" in text

    def test_format_changed_severity(self) -> None:
        delta = FindingDelta(
            changed_severity=[{"rule_id": "CVE-001", "old_severity": "medium", "new_severity": "critical"}],
            unchanged_count=2,
        )
        text = format_delta_for_ai(delta)

        assert "CHANGED SEVERITY (1)" in text
        assert "medium → critical" in text

    def test_delta_summary(self) -> None:
        delta = FindingDelta(
            new_findings=[_make_finding("CVE-NEW")],
            resolved_findings=[{"rule_id": "CVE-FIXED", "source": "grype"}],
            changed_severity=[{"rule_id": "CVE-001", "old_severity": "low", "new_severity": "high"}],
            unchanged_count=10,
        )
        assert "1 new" in delta.summary
        assert "1 resolved" in delta.summary
        assert "1 changed severity" in delta.summary
        assert "10 unchanged" in delta.summary
