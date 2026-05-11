"""OSCAL JSON catalog parser → ImportedControl list."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.request import urlopen


@dataclass
class ImportedControl:
    """OSCAL에서 파싱된 컨트롤 (scanner 매핑 없음)."""

    id: str
    title: str
    description: str
    framework: str
    properties: dict[str, str] = field(default_factory=dict)


class OscalParser:
    """NIST OSCAL JSON catalog → ImportedControl 리스트.

    지원 소스:
    1. NIST SP 800-53 Rev 5 OSCAL JSON catalog
    2. NIST SP 800-171 Rev 2 OSCAL JSON (CMMC base)
    3. NIST CSF 2.0 OSCAL JSON
    4. 기타 OSCAL-compatible JSON catalog
    """

    def parse_file(self, path: str, framework_id: str) -> list[ImportedControl]:
        """로컬 OSCAL JSON 파일 파싱."""
        with open(path) as f:
            data = json.load(f)
        return self._parse_catalog(data["catalog"], framework_id)

    def parse_url(self, url: str, framework_id: str) -> list[ImportedControl]:
        """URL에서 OSCAL JSON 다운로드 + 파싱."""
        with urlopen(url) as resp:
            data = json.loads(resp.read())
        return self._parse_catalog(data["catalog"], framework_id)

    def _parse_catalog(
        self, catalog: dict[str, Any], framework_id: str
    ) -> list[ImportedControl]:
        """OSCAL catalog JSON → ImportedControl 리스트.

        재귀적으로 groups/controls를 탐색.
        controls 내 sub-controls(enhancements)도 포함.
        """
        controls: list[ImportedControl] = []
        for group in catalog.get("groups", []):
            self._collect_from_group(group, framework_id, controls)
        # Top-level controls (no group)
        for ctrl in catalog.get("controls", []):
            self._collect_control(ctrl, framework_id, controls)
        return controls

    def _collect_from_group(
        self,
        group: dict[str, Any],
        framework_id: str,
        result: list[ImportedControl],
    ) -> None:
        """Recursively collect controls from a group and its sub-groups."""
        for ctrl in group.get("controls", []):
            self._collect_control(ctrl, framework_id, result)
        for sub_group in group.get("groups", []):
            self._collect_from_group(sub_group, framework_id, result)

    def _collect_control(
        self,
        control: dict[str, Any],
        framework_id: str,
        result: list[ImportedControl],
    ) -> None:
        """Extract a single control and its sub-controls (enhancements)."""
        props: dict[str, str] = {}
        for prop in control.get("props", []):
            name = prop.get("name", "")
            value = prop.get("value", "")
            if name and value:
                props[name] = value

        result.append(
            ImportedControl(
                id=control["id"],
                title=control["title"],
                description=self._extract_description(control),
                framework=framework_id,
                properties=props,
            )
        )
        # Sub-controls (enhancements)
        for sub in control.get("controls", []):
            self._collect_control(sub, framework_id, result)

    def _extract_description(self, control: dict[str, Any]) -> str:
        """parts[name=statement].prose에서 설명 추출."""
        for part in control.get("parts", []):
            if part.get("name") == "statement":
                return str(part.get("prose", ""))
        return ""
