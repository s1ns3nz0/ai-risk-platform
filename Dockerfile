# Multi-stage build keeps the runtime image small and free of build tools.
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install runtime deps + the [server] extras into /install.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install --prefix=/install \
        fastapi 'uvicorn[standard]' pydantic pyyaml jsonschema click boto3 redis

COPY orchestrator ./orchestrator
COPY controls ./controls
COPY rego ./rego
COPY README.md ./
RUN pip install --prefix=/install --no-deps .

# ---- runtime ----
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/install/bin:$PATH \
    PYTHONPATH=/install/lib/python3.12/site-packages

# Site-packages and bundled assets from the builder stage.
COPY --from=builder /install /install
COPY --from=builder /build/orchestrator /app/orchestrator
COPY --from=builder /build/controls /app/controls
COPY --from=builder /build/rego /app/rego

WORKDIR /app

# Non-root. fsGroup in the K8s spec aligns with this.
RUN useradd --uid 10001 --no-create-home --shell /sbin/nologin orchestrator
USER 10001

EXPOSE 8000

# Probes are served unauthenticated by design (k8s probes can't send headers
# without extra config). Auth on /v1/* is unaffected.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2).status==200 else 1)"

# Import-only by default — operator must pass --scan-roots to enable scan-mode
# and must set ORCHESTRATOR_API_KEY in the environment for auth.
ENTRYPOINT ["python", "-m", "orchestrator", "serve", "--host", "0.0.0.0", "--port", "8000"]
