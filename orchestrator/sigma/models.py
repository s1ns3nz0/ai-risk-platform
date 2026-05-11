"""Sigma rule data models."""

from __future__ import annotations

from dataclasses import dataclass, field

from orchestrator.types import Finding


@dataclass
class SigmaRule:
    """Sigma rule의 Python 표현."""

    id: str
    title: str
    description: str
    status: str  # "experimental", "test", "stable"
    level: str  # "critical", "high", "medium", "low", "informational"
    logsource: dict[str, str]
    detection: dict[str, object]
    tags: list[str] = field(default_factory=list)
    control_ids: list[str] = field(default_factory=list)


@dataclass
class SigmaMatch:
    """Sigma rule 매칭 결과."""

    rule: SigmaRule
    log_entry: dict[str, object]
    matched_at: str  # ISO timestamp

    def to_finding(self, product: str = "") -> Finding:
        """SigmaMatch를 Finding으로 변환. Evidence chain 연결용."""
        return Finding(
            source="sigma",
            rule_id=self.rule.id,
            severity=self.rule.level,
            file="",
            line=0,
            message=self.rule.title,
            control_ids=list(self.rule.control_ids),
            product=product,
        )
