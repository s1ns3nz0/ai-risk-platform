"""Scanner protocol — interface for all scanner wrappers."""

from __future__ import annotations

from typing import Protocol

from orchestrator.types import Finding


class Scanner(Protocol):
    """모든 scanner wrapper가 구현하는 인터페이스."""

    @property
    def name(self) -> str: ...

    def scan(self, target_path: str) -> list[Finding]: ...

    def parse_output(self, raw_output: str) -> list[Finding]: ...
