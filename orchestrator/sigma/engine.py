"""Custom Python Sigma matcher (~150 LOC target).

Supported (MVP-0):
- Field value equals
- Field value contains/startswith/endswith (via |modifier)
- AND/OR combinations in detection.condition
- Selection references (detection.selection → detection.condition: selection)

Not supported (future):
- aggregation (count, sum, etc.)
- near operator
- timeframe
- regex
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from orchestrator.sigma.models import SigmaMatch, SigmaRule


class SigmaEngine:
    """Custom Python Sigma matcher."""

    def __init__(self, rules_dir: str) -> None:
        self._rules_dir = Path(rules_dir)
        self._rules: list[SigmaRule] = []

    @property
    def rules(self) -> list[SigmaRule]:
        return list(self._rules)

    def load_rules(self) -> list[SigmaRule]:
        """Load all .yml files from rules_dir."""
        self._rules = []
        if not self._rules_dir.exists():
            return self._rules
        for path in sorted(self._rules_dir.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            rule = SigmaRule(
                id=data["id"],
                title=data["title"],
                description=data.get("description", ""),
                status=data.get("status", "experimental"),
                level=data.get("level", "medium"),
                logsource=data.get("logsource", {}),
                detection=data.get("detection", {}),
                tags=data.get("tags", []),
                control_ids=data.get("control_ids", []),
            )
            self._rules.append(rule)
        return self._rules

    def evaluate(self, log_entry: dict[str, object]) -> list[SigmaMatch]:
        """Evaluate a single log entry against all loaded rules."""
        matches: list[SigmaMatch] = []
        now = datetime.now(timezone.utc).isoformat()
        for rule in self._rules:
            detection = rule.detection
            condition = str(detection.get("condition", ""))
            if self._match_detection(detection, condition, log_entry):
                matches.append(SigmaMatch(rule=rule, log_entry=dict(log_entry), matched_at=now))
        return matches

    def evaluate_log_file(self, log_path: str) -> list[SigmaMatch]:
        """Evaluate each line of a JSONL log file."""
        matches: list[SigmaMatch] = []
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                matches.extend(self.evaluate(entry))
        return matches

    def _match_detection(
        self, detection: dict[str, object], condition: str, log_entry: dict[str, object]
    ) -> bool:
        """Evaluate a detection block's condition against a log entry."""
        # Parse condition: supports "sel1 and sel2", "sel1 or sel2", single "selection"
        tokens = condition.strip().split()
        if not tokens:
            return False

        if "and" in tokens:
            parts = condition.split(" and ")
            return all(
                self._match_selection(detection.get(p.strip(), {}), log_entry)  # type: ignore[arg-type]
                for p in parts
            )
        if "or" in tokens:
            parts = condition.split(" or ")
            return any(
                self._match_selection(detection.get(p.strip(), {}), log_entry)  # type: ignore[arg-type]
                for p in parts
            )

        # Single selection reference
        selection_name = tokens[0]
        selection = detection.get(selection_name, {})
        return self._match_selection(selection, log_entry)  # type: ignore[arg-type]

    def _match_selection(self, selection: dict[str, object], log_entry: dict[str, object]) -> bool:
        """Evaluate a single selection block."""
        if not selection:
            return False
        for key, expected in selection.items():
            # Parse modifiers: field|contains, field|startswith, field|endswith
            if "|" in key:
                field_name, modifier = key.split("|", 1)
            else:
                field_name = key
                modifier = ""

            actual = log_entry.get(field_name)
            if actual is None:
                return False

            actual_str = str(actual)

            # expected can be a list (any match) or a single value
            expected_values = expected if isinstance(expected, list) else [expected]

            if modifier == "contains":
                if not any(str(v) in actual_str for v in expected_values):
                    return False
            elif modifier == "startswith":
                if not any(actual_str.startswith(str(v)) for v in expected_values):
                    return False
            elif modifier == "endswith":
                if not any(actual_str.endswith(str(v)) for v in expected_values):
                    return False
            else:
                # Exact match
                if not any(actual_str == str(v) for v in expected_values):
                    return False
        return True
