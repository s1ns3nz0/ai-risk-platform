"""Request/response schemas for the HTTP API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


Trigger = Literal["pre_merge", "pre_deploy", "periodic"]


class ScannerResultPayload(BaseModel):
    """Raw scanner output. Either inline JSON body or pre-detected scanner type."""

    scanner: str | None = Field(
        default=None,
        description=(
            "Scanner name. Native parsers: semgrep|grype|trivy|gitleaks|checkov|zap|spotbugs. "
            "Universal SARIF: sarif. "
            "Aliases route to canonical parsers — grype-image→grype, "
            "trivy-fs/-image/-config→trivy, trivy-sarif→sarif, "
            "hadolint/snyk/bandit/codeql/semgrep-sarif→sarif. "
            "Spotbugs accepts either SARIF (object/array) or raw/base64-encoded "
            "XML (string). When omitted, the parser auto-detects from content."
        ),
    )
    content: Any = Field(
        default=None,
        description=(
            "Scanner output. Typically a JSON object/array. "
            "Null is treated as 'no findings' (logged, not an error) — useful "
            "when a scanner produced an empty result file. "
            "Strings are accepted only for XML-emitting scanners (spotbugs)."
        ),
    )

    @field_validator("content")
    @classmethod
    def _content_shape_ok(cls, v: Any) -> Any:
        # Numbers, booleans, and other primitives are still rejected — they
        # can't represent scanner output meaningfully. None/dict/list/str pass.
        if v is None or isinstance(v, (dict, list, str)):
            return v
        raise ValueError("content must be a JSON object/array, a string (XML), or null")

    @field_validator("scanner")
    @classmethod
    def _scanner_allowed(cls, v: str | None) -> str | None:
        if v is None:
            return v
        # Canonical parsers + aliases recognised by the HTTP layer.
        allowed = {
            # canonical
            "semgrep", "grype", "trivy", "gitleaks", "checkov", "zap", "sarif",
            # grype variants
            "grype-image",
            # trivy variants
            "trivy-fs", "trivy-image", "trivy-config", "trivy-sarif",
            # SARIF-native tools
            "hadolint", "spotbugs", "snyk", "bandit", "codeql", "semgrep-sarif",
        }
        if v not in allowed:
            raise ValueError(f"scanner must be one of {sorted(allowed)}")
        return v


class ImportAssessRequest(BaseModel):
    """Submit pre-existing scanner results for assessment."""

    trigger: Trigger = "pre_merge"
    results: list[ScannerResultPayload] = Field(
        description="One entry per scanner result file.",
        min_length=1,
        max_length=64,
    )
    async_mode: bool = Field(
        default=False,
        description="Return 202 with a job ID instead of blocking. "
        "Recommended when BEDROCK_MODEL_ID is configured.",
    )


class ScanAssessRequest(BaseModel):
    """Run scanners on a path mounted into the server's filesystem, then assess."""

    target_path: str = Field(description="Absolute path on the server filesystem.")
    trigger: Trigger = "pre_merge"
    async_mode: bool = False


class GateSummary(BaseModel):
    passed: bool
    reason: str
    findings_count: dict[str, int]
    threshold_results: list[dict[str, Any]]


class AssessmentResponse(BaseModel):
    product: str
    tier: str
    mode: str
    duration_seconds: float
    findings_count: int
    gate: GateSummary
    sp800_30_report: dict[str, Any] | None
    sar: dict[str, Any] | None
    poam: dict[str, Any]
    authorization: dict[str, Any] | None


class ProductSummary(BaseModel):
    name: str
    description: str
    data_classification: list[str]
    jurisdiction: list[str]


class ProductListResponse(BaseModel):
    products: list[str]


class JobStatusResponse(BaseModel):
    job_id: str
    status: Literal["pending", "running", "completed", "failed"]
    progress: dict[str, Any] | None = None
    result: AssessmentResponse | None = None
    error_id: str | None = Field(
        default=None,
        description="Correlation ID for the failure — full traceback is in the server log.",
    )
    error_class: str | None = None


class JobAccepted(BaseModel):
    job_id: str
    status: Literal["pending", "running"] = "pending"


class ReloadResponse(BaseModel):
    products: int
    controls_baselines: int


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadyResponse(BaseModel):
    status: Literal["ready", "loading"]
    products_loaded: int
