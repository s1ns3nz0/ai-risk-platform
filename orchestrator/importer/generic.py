"""Non-OSCAL framework parsers (ASVS JSON, CIS CSV, custom JSON)."""

from __future__ import annotations

import json
from typing import Any

from orchestrator.importer.oscal import ImportedControl


class GenericFrameworkParser:
    """비-OSCAL 소스 파싱. JSON/CSV 포맷.

    지원:
    - OWASP ASVS JSON (GitHub에서 다운로드)
    - 커스텀 JSON (id, title, description 필드)
    """

    def parse_asvs_json(
        self, path: str, level: int = 3
    ) -> list[ImportedControl]:
        """OWASP ASVS JSON → ImportedControl.

        level 파라미터로 L1/L2/L3 필터링.
        """
        with open(path) as f:
            data = json.load(f)

        level_key = f"L{level}"
        controls: list[ImportedControl] = []

        for req in data.get("requirements", []):
            if not req.get(level_key, {}).get("Required", False):
                continue
            controls.append(
                ImportedControl(
                    id=req["Shortcode"],
                    title=req.get("ShortName", ""),
                    description=req.get("Description", ""),
                    framework="owasp-asvs",
                    properties={},
                )
            )
        return controls

    def parse_generic_json(
        self,
        path: str,
        framework_id: str,
        id_field: str = "id",
        title_field: str = "title",
        description_field: str = "description",
    ) -> list[ImportedControl]:
        """커스텀 JSON 매핑."""
        with open(path) as f:
            data = json.load(f)

        items: list[dict[str, Any]]
        if isinstance(data, dict):
            items = data.get("controls") or data.get("items") or []
        else:
            items = data

        return [
            ImportedControl(
                id=item[id_field],
                title=item.get(title_field, ""),
                description=item.get(description_field, ""),
                framework=framework_id,
                properties={},
            )
            for item in items
        ]
