"""RetryEngine — scanner retry with configurable backoff."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from orchestrator.types import Finding

logger = logging.getLogger(__name__)


@dataclass
class RetryConfig:
    """Retry configuration from risk-profile.yaml failure_policy."""

    max_attempts: int = 3
    backoff_schedule: list[float] = field(default_factory=lambda: [10.0, 30.0, 60.0])
    total_timeout: float = 120.0  # hard cap in seconds


@dataclass
class RetryResult:
    """Result of a retry sequence."""

    scanner: str
    success: bool
    attempts: int
    total_time: float
    error_message: str


class RetryEngine:
    """Scanner retry engine with configurable backoff.

    핵심 규칙:
    - Max 3 attempts per scanner
    - Fixed backoff schedule [10s, 30s, 60s] (not exponential — predictable)
    - Hard cap 120s total per scanner
    - After all retries exhausted, scanner marked as failed
    - Failure handling delegated to FailureHandler (Step 1)
    """

    def __init__(self, config: RetryConfig | None = None) -> None:
        self._config = config or RetryConfig()

    def execute_with_retry(
        self,
        scanner_name: str,
        scan_fn: Callable[[], list[Finding]],
    ) -> tuple[list[Finding], RetryResult]:
        """Execute scan_fn with retry logic.

        Returns:
            (findings, RetryResult) — findings may be empty on failure
        """
        start = time.monotonic()
        last_error = ""

        for attempt in range(1, self._config.max_attempts + 1):
            try:
                findings = scan_fn()
                elapsed = time.monotonic() - start
                return findings, RetryResult(
                    scanner=scanner_name,
                    success=True,
                    attempts=attempt,
                    total_time=elapsed,
                    error_message="",
                )
            except Exception as exc:
                last_error = str(exc)
                elapsed = time.monotonic() - start
                logger.warning(
                    "Scanner %s attempt %d/%d failed: %s (%.1fs elapsed)",
                    scanner_name,
                    attempt,
                    self._config.max_attempts,
                    last_error,
                    elapsed,
                )

                # Check if we have more attempts and haven't exceeded timeout
                if attempt < self._config.max_attempts:
                    if elapsed >= self._config.total_timeout:
                        logger.warning(
                            "Scanner %s total timeout %.0fs exceeded after %d attempts",
                            scanner_name,
                            self._config.total_timeout,
                            attempt,
                        )
                        break
                    backoff_idx = min(attempt - 1, len(self._config.backoff_schedule) - 1)
                    backoff = self._config.backoff_schedule[backoff_idx]
                    time.sleep(backoff)

        total_time = time.monotonic() - start
        return [], RetryResult(
            scanner=scanner_name,
            success=False,
            attempts=min(attempt, self._config.max_attempts),
            total_time=total_time,
            error_message=last_error,
        )
