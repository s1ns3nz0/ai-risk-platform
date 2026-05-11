"""ControlMapper — maps scanner findings to Control IDs.

Mapping source is the Controls Repository's verification_methods field.
This mapping is deterministic — AI가 관여하지 않는다.
"""

from __future__ import annotations

import fnmatch

from orchestrator.controls.repository import ControlsRepository

# Severity ordering for threshold comparison
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class ControlMapper:
    """Scanner finding을 Control ID로 매핑한다."""

    def __init__(self, controls_repo: ControlsRepository) -> None:
        self._controls_repo = controls_repo
        self._build_index()

    def _build_index(self) -> None:
        """Controls Repository에서 scanner → rule/check 매핑 인덱스를 구축한다."""
        # checkov: check_id → [control_ids]
        self._checkov_map: dict[str, list[str]] = {}
        # semgrep: [(glob_pattern, control_id)]
        self._semgrep_patterns: list[tuple[str, str]] = []
        # grype: [(severity_threshold, control_id)]
        self._grype_thresholds: list[tuple[str, str]] = []
        # gitleaks: [control_id] (no rule filtering — any gitleaks finding maps)
        self._gitleaks_controls: list[str] = []
        # sbom: [control_id] (SBOM generation evidence — maps when SBOM is produced)
        self._sbom_controls: list[str] = []
        # zap: [(rule_pattern, control_id)] — similar to semgrep
        self._zap_patterns: list[tuple[str, str]] = []
        # zap: [(severity_threshold, control_id)] — fallback by severity
        self._zap_thresholds: list[tuple[str, str]] = []

        for control in self._controls_repo.controls.values():
            for vm in control.verification_methods:
                if vm.scanner == "checkov" and vm.check_ids:
                    for check_id in vm.check_ids:
                        self._checkov_map.setdefault(check_id, []).append(control.id)

                elif vm.scanner == "semgrep" and vm.rules:
                    for rule_pattern in vm.rules:
                        self._semgrep_patterns.append((rule_pattern, control.id))

                elif vm.scanner == "grype" and vm.severity_threshold:
                    self._grype_thresholds.append((vm.severity_threshold, control.id))

                elif vm.scanner == "gitleaks":
                    self._gitleaks_controls.append(control.id)

                elif vm.scanner == "sbom":
                    self._sbom_controls.append(control.id)

                elif vm.scanner == "zap":
                    if vm.rules:
                        for rule_pattern in vm.rules:
                            self._zap_patterns.append((rule_pattern, control.id))
                    elif vm.severity_threshold:
                        self._zap_thresholds.append((vm.severity_threshold, control.id))

    def map_finding(self, source: str, rule_id: str, severity: str | None = None) -> list[str]:
        """scanner name + rule_id → 해당하는 Control ID 목록.

        매핑이 없으면 빈 리스트 반환 (unmapped finding).
        """
        if source == "checkov":
            return list(self._checkov_map.get(rule_id, []))

        if source == "semgrep":
            return self._match_semgrep(rule_id)

        if source == "grype":
            return self._match_grype(severity)

        if source == "gitleaks":
            return list(self._gitleaks_controls)

        if source == "sbom":
            return list(self._sbom_controls)

        if source == "zap":
            return self._match_zap(rule_id, severity)

        return []

    def _match_semgrep(self, rule_id: str) -> list[str]:
        """Semgrep rule_id를 glob 패턴으로 매칭한다."""
        matched: list[str] = []
        seen: set[str] = set()
        for pattern, control_id in self._semgrep_patterns:
            if control_id not in seen and fnmatch.fnmatch(rule_id, pattern):
                matched.append(control_id)
                seen.add(control_id)
        return matched

    def _match_zap(self, rule_id: str, severity: str | None = None) -> list[str]:
        """ZAP alert를 rule pattern 또는 severity threshold로 매핑한다."""
        matched: list[str] = []
        seen: set[str] = set()
        # First try rule-based matching
        for pattern, control_id in self._zap_patterns:
            if control_id not in seen and fnmatch.fnmatch(rule_id, pattern):
                matched.append(control_id)
                seen.add(control_id)
        # If no rule match, fall back to severity threshold
        if not matched and severity:
            sev_level = _SEVERITY_ORDER.get(severity.lower(), 0)
            for threshold, control_id in self._zap_thresholds:
                threshold_level = _SEVERITY_ORDER.get(threshold.lower(), 0)
                if control_id not in seen and sev_level >= threshold_level:
                    matched.append(control_id)
                    seen.add(control_id)
        return matched

    def _match_grype(self, severity: str | None) -> list[str]:
        """Grype finding severity가 threshold 이상인 경우 매핑한다."""
        if severity is None:
            return []
        sev_level = _SEVERITY_ORDER.get(severity.lower(), 0)
        matched: list[str] = []
        seen: set[str] = set()
        for threshold, control_id in self._grype_thresholds:
            threshold_level = _SEVERITY_ORDER.get(threshold.lower(), 0)
            if control_id not in seen and sev_level >= threshold_level:
                matched.append(control_id)
                seen.add(control_id)
        return matched
