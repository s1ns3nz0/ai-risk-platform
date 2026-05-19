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
    format: str | None = Field(
        default=None,
        description=(
            "Output format hint. When set to 'sarif', the content is parsed as "
            "SARIF 2.1.0 regardless of the scanner name. Useful for scanners "
            "that emit native JSON by default but can also emit SARIF "
            "(semgrep, gitleaks, grype, trivy, etc.)."
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
        # Per-framework variants (e.g. checkov-k8s, checkov-dockerfile,
        # trivy-cis, grype-sbom) are accepted and routed to the canonical
        # parser in app._SCANNER_ALIASES.
        allowed = {
            # canonical
            "semgrep", "grype", "trivy", "gitleaks", "checkov", "zap", "sarif",
            # grype variants
            "grype-image", "grype-sbom",
            # trivy variants
            "trivy-fs", "trivy-image", "trivy-config", "trivy-cis", "trivy-sarif",
            # checkov framework variants
            "checkov-k8s", "checkov-kubernetes", "checkov-dockerfile",
            "checkov-terraform", "checkov-cloudformation", "checkov-helm",
            "checkov-secrets",
            # SARIF-native tools
            "hadolint", "spotbugs", "spotbugs-xml", "snyk", "bandit", "codeql",
            "semgrep-sarif",
        }
        if v not in allowed:
            raise ValueError(f"scanner must be one of {sorted(allowed)}")
        return v


DevSecOpsPhase = Literal[
    "DEVELOP", "BUILD", "TEST", "RELEASE", "DELIVER", "DEPLOY", "OPERATE", "UNKNOWN",
]


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
    phase: DevSecOpsPhase | None = Field(
        default=None,
        description=(
            "DevSecOps phase that produced these results: DEVELOP, BUILD, TEST, "
            "RELEASE, DELIVER, DEPLOY, OPERATE. When set, overrides the "
            "trigger-derived default on every POA&M item's source_detail.phase. "
            "Falls back to the trigger mapping (pre_merge→BUILD, "
            "pre_deploy→DEPLOY, periodic→OPERATE) when omitted."
        ),
    )
    evidence_url: str = Field(
        default="",
        description=(
            "Pipeline run URL (e.g. GitHub Actions $GITHUB_SERVER_URL/.../runs/$GITHUB_RUN_ID). "
            "Stored on every generated POA&M item under source_detail.evidence_url so "
            "remediation tickets can link back to the originating CI run."
        ),
    )
    sbom: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional CycloneDX 1.4+ SBOM (parsed JSON). When supplied, every "
            "POA&M item whose finding has a `package` is correlated to a "
            "component and gets a `source_detail.sbom_ref` like "
            "`bom.json#components/pkg:maven/.../spring-core@6.1.6`."
        ),
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
    assessment_id: str = ""
    created_at: str = ""
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


# ---------------- POA&M update payloads (pipeline + operator-supplied) ----------------


class TicketUpdate(BaseModel):
    """Pipeline-supplied after creating the GitHub Issue / Jira ticket."""

    id: str = Field(description="External ticket id, e.g. SEC-202605-001")
    url: str = Field(default="", description="Browsable ticket URL")


class DelayUpdate(BaseModel):
    """Operator-supplied delay justification (manual)."""

    justification: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)


class RiskAcceptanceUpdate(BaseModel):
    """AO-supplied formal risk acceptance (manual)."""

    accepted_by: str = Field(min_length=1)
    justification: str = Field(min_length=1)
    compensating_controls: list[str] = Field(default_factory=list)


class VerificationUpdate(BaseModel):
    """Who verified the remediation (auto or manual)."""

    verified_by: str = Field(min_length=1, description='"automated" or person name')
    verified_at: str = Field(default="", description="ISO 8601; auto-stamped if omitted")


class AssessmentSummary(BaseModel):
    id: str
    product: str
    created_at: str


class AssessmentListResponse(BaseModel):
    assessments: list[AssessmentSummary]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadyResponse(BaseModel):
    status: Literal["ready", "loading"]
    products_loaded: int
