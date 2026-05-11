"""ScannerRunner — executes all scanners and aggregates results."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from orchestrator.types import Finding

if TYPE_CHECKING:
    from orchestrator.resilience.retry import RetryConfig, RetryResult
    from orchestrator.scanners.base import Scanner

logger = logging.getLogger(__name__)


class ScannerRunner:
    """모든 scanner를 실행하고 결과를 집계한다."""

    def __init__(
        self,
        scanners: list[Scanner],
        retry_config: RetryConfig | None = None,
    ) -> None:
        self._scanners = scanners
        self._retry_config = retry_config

    def run_all(self, target_path: str) -> list[Finding]:
        """모든 scanner를 순차 실행.

        각 scanner 실패 시 에러 로깅 후 계속 진행.
        MVP-0 failure policy: log and continue.

        retry_config가 설정되어 있어도 이 메서드는 list[Finding]만 반환.
        RetryResult가 필요하면 run_all_with_retry()를 사용.
        """
        if self._retry_config is not None:
            findings, _ = self.run_all_with_retry(target_path)
            return findings

        all_findings: list[Finding] = []
        for scanner in self._scanners:
            try:
                findings = scanner.scan(target_path)
                all_findings.extend(findings)
                logger.info("Scanner %s found %d findings", scanner.name, len(findings))
            except Exception:
                logger.exception(
                    "Scanner %s failed, continuing with remaining scanners",
                    scanner.name,
                )
        return all_findings

    def run_all_with_retry(
        self, target_path: str
    ) -> tuple[list[Finding], list[RetryResult]]:
        """Retry-enabled 실행. RetryResult 목록도 함께 반환."""
        from orchestrator.resilience.retry import RetryConfig, RetryEngine

        config = self._retry_config or RetryConfig()
        engine = RetryEngine(config=config)
        all_findings: list[Finding] = []
        retry_results: list[RetryResult] = []

        for scanner in self._scanners:
            findings, result = engine.execute_with_retry(
                scanner.name,
                lambda s=scanner: s.scan(target_path),  # type: ignore[misc]
            )
            all_findings.extend(findings)
            retry_results.append(result)
            if result.success:
                logger.info(
                    "Scanner %s found %d findings (attempts: %d)",
                    scanner.name,
                    len(findings),
                    result.attempts,
                )
            else:
                logger.warning(
                    "Scanner %s failed after %d attempts: %s",
                    scanner.name,
                    result.attempts,
                    result.error_message,
                )

        return all_findings, retry_results
