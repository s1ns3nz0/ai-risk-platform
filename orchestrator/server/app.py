"""FastAPI app — REST surface over the assessment pipeline.

Routes:
  GET  /healthz                              liveness (open)
  GET  /readyz                               readiness (open)
  GET  /v1/products                          list configured products
  GET  /v1/products/{name}                   product summary
  POST /v1/products/{name}/assess            import-mode: assess scanner results
  POST /v1/products/{name}/scan-assess       scan-mode: run scanners on a path then assess
  GET  /v1/jobs/{job_id}                     poll async assessment
  POST /v1/admin/reload                      re-read controls + products from disk

All /v1/* routes require `X-API-Key: $ORCHESTRATOR_API_KEY` when the env var is set.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.server.assess import (
    AssessmentResult,
    run_assessment,
    run_scanners,
)
from orchestrator.server.jobs import (
    InProcessBackend,
    Job,
    JobBackend,
    JobRegistry,
    JobRejected,
    RedisBackend,
    SqliteBackend,
    WorkerLoop,
)
from orchestrator.server.models import (
    AssessmentResponse,
    HealthResponse,
    ImportAssessRequest,
    JobAccepted,
    JobStatusResponse,
    ProductListResponse,
    ProductSummary,
    ReadyResponse,
    ReloadResponse,
    ScanAssessRequest,
    ScannerResultPayload,
)
from orchestrator.server.state import ServerState
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024


def create_app(
    state: ServerState,
    api_key: str | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    cors_origins: list[str] | None = None,
    job_backend: JobBackend | None = None,
    worker_concurrency: int = 2,
    replica_id: str | None = None,
    enable_janitor: bool = True,
    janitor_interval: float = 30.0,
    janitor_max_attempts: int = 3,
    heartbeat_ttl: int = 60,
) -> FastAPI:
    """Build a FastAPI app bound to a pre-loaded ServerState.

    `job_backend`:
      - None or InProcessBackend → closure-based, pod-local execution.
      - SqliteBackend → durable state, still pod-local execution.
      - RedisBackend → cross-replica state + cross-replica work pickup
                       (a WorkerLoop is started on this replica).
    """
    backend = job_backend or InProcessBackend()
    jobs = JobRegistry(
        max_workers=2,
        max_pending=32,
        ttl_seconds=3600,
        backend=backend,
    )

    # Register handlers so a WorkerLoop on this replica can execute descriptors
    # produced anywhere in the cluster.
    handlers = _build_handlers(state)
    worker: WorkerLoop | None = None
    if isinstance(backend, RedisBackend):
        worker = WorkerLoop(
            backend=backend,
            handlers=handlers,
            replica_id=replica_id,
            concurrency=worker_concurrency,
            ttl_seconds=3600,
            heartbeat_ttl=heartbeat_ttl,
            janitor_interval=janitor_interval,
            janitor_max_attempts=janitor_max_attempts,
            enable_janitor=enable_janitor,
        )

    @contextlib.asynccontextmanager
    async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
        if worker is not None:
            worker.start()
            logger.info("worker started replica_id=%s", worker.replica_id)
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()
            jobs.shutdown()

    app = FastAPI(
        title="AI Risk Assessment Platform",
        description="HTTP API for compliance-driven risk assessment.",
        version="0.1.0",
        lifespan=_lifespan,
    )
    app.state.jobs = jobs
    app.state.server_state = state
    app.state.api_key = api_key
    app.state.worker = worker

    if cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "X-API-Key", "X-Request-Id"],
        )

    # ---- middleware: payload size cap ----
    @app.middleware("http")
    async def _enforce_body_cap(request: Request, call_next):  # type: ignore[no-untyped-def]
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > max_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"request body exceeds {max_body_bytes} bytes"},
                    )
            except ValueError:
                pass
        return await call_next(request)

    # ---- middleware: request ID + structured access log ----
    @app.middleware("http")
    async def _request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = rid
        t0 = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
            logger.exception(
                "request failed rid=%s method=%s path=%s elapsed_ms=%s",
                rid, request.method, request.url.path, elapsed_ms,
            )
            raise
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        response.headers["X-Request-Id"] = rid
        logger.info(
            "rid=%s method=%s path=%s status=%s elapsed_ms=%s",
            rid, request.method, request.url.path, response.status_code, elapsed_ms,
        )
        return response

    # ---- auth dependency ----
    def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if api_key is None:
            return
        if x_api_key is None or not hmac.compare_digest(x_api_key, api_key):
            raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")

    auth = [Depends(require_api_key)]

    # ---------------- health ----------------

    @app.get("/healthz", response_model=HealthResponse)
    def healthz() -> HealthResponse:
        return HealthResponse()

    @app.get("/readyz", response_model=ReadyResponse)
    def readyz() -> ReadyResponse:
        try:
            products = state.list_products()
            _ = state.controls_repo
            return ReadyResponse(status="ready", products_loaded=len(products))
        except RuntimeError:
            return ReadyResponse(status="loading", products_loaded=0)

    # ---------------- products ----------------

    @app.get("/v1/products", response_model=ProductListResponse, dependencies=auth)
    def list_products() -> ProductListResponse:
        return ProductListResponse(products=state.list_products())

    @app.get("/v1/products/{name}", response_model=ProductSummary, dependencies=auth)
    def get_product(name: str) -> ProductSummary:
        cfg = _get_product_or_404(state, name)
        m = cfg.manifest
        return ProductSummary(
            name=cfg.name,
            description=m.description,
            data_classification=m.data_classification,
            jurisdiction=m.jurisdiction,
        )

    # ---------------- import-mode assess ----------------

    @app.post(
        "/v1/products/{name}/assess",
        response_model=None,
        responses={200: {"model": AssessmentResponse}, 202: {"model": JobAccepted}},
        dependencies=auth,
    )
    def assess_endpoint(name: str, req: ImportAssessRequest) -> Any:
        cfg = _get_product_or_404(state, name)
        _require_async_for_bedrock(state, req.async_mode)
        findings = _parse_payloads(req.results, state)
        if not findings:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No findings parsed from supplied scanner results",
            )

        # Distributed path: serialize a descriptor onto Redis. Any replica may execute.
        if isinstance(backend, RedisBackend) and req.async_mode:
            descriptor = {
                "type": "import-assess",
                "product": name,
                "trigger": req.trigger,
                "findings": [asdict(f) for f in findings],
            }
            return _accept_distributed(jobs, descriptor)

        # Local path (closure-based).
        def _do() -> AssessmentResult:
            return run_assessment(
                product=name,
                findings=findings,
                manifest=cfg.manifest,
                profile=cfg.profile,
                controls_repo=state.controls_repo,
                clients=state.clients,
                rego_dir=str(state.rego_dir),
                trigger=req.trigger,
            )
        return _run_sync_or_async(_do, async_mode=req.async_mode, jobs=jobs)

    # ---------------- scan-mode assess ----------------

    @app.post(
        "/v1/products/{name}/scan-assess",
        response_model=None,
        responses={200: {"model": AssessmentResponse}, 202: {"model": JobAccepted}},
        dependencies=auth,
    )
    def scan_assess_endpoint(name: str, req: ScanAssessRequest) -> Any:
        cfg = _get_product_or_404(state, name)
        _require_async_for_bedrock(state, req.async_mode)

        if not state.scan_roots:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="scan-mode disabled: no --scan-roots configured on this server",
            )

        target = Path(req.target_path)
        if not state.path_within_scan_roots(target):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="target_path is not within any configured scan root",
            )

        target_resolved = str(target.resolve())

        if isinstance(backend, RedisBackend) and req.async_mode:
            descriptor = {
                "type": "scan-assess",
                "product": name,
                "trigger": req.trigger,
                "target_path": target_resolved,
            }
            return _accept_distributed(jobs, descriptor)

        def _do() -> AssessmentResult:
            findings = run_scanners(target_resolved, state.controls_repo)
            return run_assessment(
                product=name,
                findings=findings,
                manifest=cfg.manifest,
                profile=cfg.profile,
                controls_repo=state.controls_repo,
                clients=state.clients,
                rego_dir=str(state.rego_dir),
                trigger=req.trigger,
            )
        return _run_sync_or_async(_do, async_mode=req.async_mode, jobs=jobs)

    # ---------------- jobs ----------------

    @app.get("/v1/jobs/{job_id}", response_model=JobStatusResponse, dependencies=auth)
    def get_job(job_id: str) -> JobStatusResponse:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        result_payload: AssessmentResponse | None = None
        if job.status == "completed" and isinstance(job.result, dict):
            result_payload = AssessmentResponse(**job.result)
        return JobStatusResponse(
            job_id=job.id,
            status=job.status,
            progress=job.progress or None,
            result=result_payload,
            error_id=job.error_id,
            error_class=job.error_class,
        )

    # ---------------- admin ----------------

    @app.post("/v1/admin/reload", response_model=ReloadResponse, dependencies=auth)
    def reload_state() -> ReloadResponse:
        counts = state.reload()
        return ReloadResponse(**counts)

    # ---------------- error handler ----------------

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, HTTPException):
            raise exc
        error_id = uuid.uuid4().hex
        rid = getattr(request.state, "request_id", None)
        logger.exception(
            "unhandled error rid=%s error_id=%s %s %s",
            rid, error_id, request.method, request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": "internal error",
                "error_id": error_id,
                "error_class": type(exc).__name__,
                "request_id": rid,
            },
            headers={"X-Request-Id": rid} if rid else None,
        )

    return app


# ---------------- handlers (used by WorkerLoop) ----------------


def _build_handlers(state: ServerState) -> dict[str, Any]:
    """Build the descriptor → handler map. Every replica registers the same
    set so any of them can drain the shared queue."""

    def import_assess(descriptor: dict[str, Any]) -> AssessmentResult:
        cfg = state.get_product(descriptor["product"])
        findings = [Finding(**fd) for fd in descriptor.get("findings", [])]
        return run_assessment(
            product=descriptor["product"],
            findings=findings,
            manifest=cfg.manifest,
            profile=cfg.profile,
            controls_repo=state.controls_repo,
            clients=state.clients,
            rego_dir=str(state.rego_dir),
            trigger=descriptor.get("trigger", "pre_merge"),
        )

    def scan_assess(descriptor: dict[str, Any]) -> AssessmentResult:
        cfg = state.get_product(descriptor["product"])
        target = Path(descriptor["target_path"])
        if not state.path_within_scan_roots(target):
            raise RuntimeError(f"target_path outside scan roots: {descriptor['target_path']}")
        findings = run_scanners(str(target.resolve()), state.controls_repo)
        return run_assessment(
            product=descriptor["product"],
            findings=findings,
            manifest=cfg.manifest,
            profile=cfg.profile,
            controls_repo=state.controls_repo,
            clients=state.clients,
            rego_dir=str(state.rego_dir),
            trigger=descriptor.get("trigger", "pre_merge"),
        )

    return {"import-assess": import_assess, "scan-assess": scan_assess}


# ---------------- helpers ----------------


def _get_product_or_404(state: ServerState, name: str):  # noqa: ANN202
    try:
        return state.get_product(name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"product not found: {name}") from None


def _require_async_for_bedrock(state: ServerState, async_mode: bool) -> None:
    if state.clients.mode == "bedrock" and not async_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="server is in bedrock (AI) mode; set async_mode=true and poll /v1/jobs/{id}",
        )


# Map externally-accepted scanner names to the canonical parser they route to.
# Trivy subcommands (fs/image/config) all produce the same JSON shape.
# grype-image is the same shape as grype. hadolint/spotbugs/snyk/bandit/codeql
# emit SARIF natively or via their official SARIF plugins.
_SCANNER_ALIASES: dict[str, str] = {
    "grype-image": "grype",
    "trivy-fs": "trivy",
    "trivy-image": "trivy",
    "trivy-config": "trivy",
    "trivy-sarif": "sarif",
    "hadolint": "sarif",
    "spotbugs": "sarif",
    "snyk": "sarif",
    "bandit": "sarif",
    "codeql": "sarif",
    "semgrep-sarif": "sarif",
}


def _parse_payloads(
    payloads: list[ScannerResultPayload],
    state: ServerState,
) -> list[Finding]:
    from orchestrator.parsers.registry import detect_scanner_from_content
    from orchestrator.parsers.sarif import parse_sarif

    mapper = ControlMapper(state.controls_repo)
    all_findings: list[Finding] = []

    for entry in payloads:
        raw = json.dumps(entry.content)
        scanner = entry.scanner or detect_scanner_from_content(entry.content)
        if scanner is None:
            continue
        # Resolve alias → canonical before dispatch, log so operators can see
        # which tool the caller said it was vs. which parser actually ran.
        canonical = _SCANNER_ALIASES.get(scanner, scanner)
        if canonical != scanner:
            logger.info("scanner alias resolved: %s → %s", scanner, canonical)
        scanner = canonical
        if scanner == "sarif":
            all_findings.extend(parse_sarif(raw, mapper))
            continue
        all_findings.extend(_parse_inline(scanner, raw, mapper))

    return all_findings


def _parse_inline(scanner: str, raw: str, mapper: ControlMapper) -> list[Finding]:
    if scanner == "semgrep":
        from orchestrator.scanners.semgrep import SemgrepScanner
        return SemgrepScanner(mapper).parse_output(raw)
    if scanner == "grype":
        from orchestrator.scanners.grype import GrypeScanner
        return GrypeScanner(mapper).parse_output(raw)
    if scanner == "trivy":
        from orchestrator.scanners.trivy import TrivyScanner
        return TrivyScanner(mapper).parse_output(raw)
    if scanner == "gitleaks":
        from orchestrator.scanners.gitleaks import GitleaksScanner
        return GitleaksScanner(mapper).parse_output(raw)
    if scanner == "checkov":
        from orchestrator.scanners.checkov import CheckovScanner
        return CheckovScanner(mapper).parse_output(raw)
    if scanner == "zap":
        from orchestrator.scanners.zap import ZapScanner
        return ZapScanner(mapper).parse_output(raw)
    return []


def _run_sync_or_async(fn: Any, async_mode: bool, jobs: JobRegistry) -> Any:
    if async_mode:
        def _wrapper(_job: Job) -> AssessmentResult:
            return fn()
        try:
            job = jobs.submit(_wrapper)
        except JobRejected as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc),
            ) from None
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content=JobAccepted(job_id=job.id, status="pending").model_dump(),
        )
    result: AssessmentResult = fn()
    return AssessmentResponse(**result.to_dict())


def _accept_distributed(jobs: JobRegistry, descriptor: dict[str, Any]) -> JSONResponse:
    try:
        job = jobs.submit_descriptor(descriptor)
    except JobRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc),
        ) from None
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=JobAccepted(job_id=job.id, status="pending").model_dump(),
    )


def api_key_from_env() -> str | None:
    key = os.environ.get("ORCHESTRATOR_API_KEY", "").strip()
    return key or None
