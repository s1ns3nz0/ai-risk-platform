# AI Risk Assessment Platform

Compliance-driven risk assessment engine for DevSecOps pipelines. Implements NIST SP 800-30 Rev 1 risk assessment methodology with AI-powered analysis via AWS Bedrock.

## What It Does

- Runs 5 security scanners (Semgrep, Grype, Gitleaks, Checkov, ZAP)
- Maps findings to compliance controls (SP 800-53, PCI DSS, SOC 2, ISO 27001)
- Conducts SP 800-30 risk assessment (AI or static fallback)
- Produces SAR, POA&M, and authorization decisions
- Enforces gates via YAML thresholds + OPA/Rego policies
- Exports dashboard-ready JSON

## Quick Start

```bash
# Install
pip install -e .

# Run assessment (static mode — no AWS required)
python -m orchestrator risk-assess /path/to/your/app \
  --product your-product \
  --output output

# Run assessment (AI mode — requires AWS Bedrock)
BEDROCK_MODEL_ID=jp.anthropic.claude-sonnet-4-6 \
AWS_DEFAULT_REGION=ap-northeast-1 \
python -m orchestrator risk-assess /path/to/your/app \
  --product your-product \
  --output output
```

## API Server Mode

For long-lived deployment (e.g. a pod that CI calls into), run the platform as
an HTTP service so controls baselines, Bedrock clients, and EPSS connections
are loaded **once at boot** instead of on every CI run.

```bash
pip install -e '.[server]'

# Auth on, scan-mode disabled (import-only)
ORCHESTRATOR_API_KEY=$(openssl rand -hex 32) \
  python -m orchestrator serve --host 0.0.0.0 --port 8000

# With scan-mode (server runs scanners on mounted workspaces)
ORCHESTRATOR_API_KEY=... \
  python -m orchestrator serve \
    --scan-roots /mnt/workspaces:/mnt/repos
```

### Endpoints

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET    | `/healthz`                                | Liveness (open) |
| GET    | `/readyz`                                 | Readiness (open) |
| GET    | `/v1/products`                            | List configured products |
| GET    | `/v1/products/{name}`                     | Product summary |
| POST   | `/v1/products/{name}/assess`              | Import scanner results, return assessment |
| POST   | `/v1/products/{name}/scan-assess`         | Run scanners on a path under `--scan-roots`, then assess |
| GET    | `/v1/jobs/{job_id}`                       | Poll an async job |
| POST   | `/v1/admin/reload`                        | Re-read controls + products from disk |

All `/v1/*` routes require `X-API-Key: $ORCHESTRATOR_API_KEY` when the env var is set.

### Sync vs async

- **Static mode** (no `BEDROCK_MODEL_ID`): assessments take <1s — sync responses are fine.
- **Bedrock mode**: per-finding AI calls take minutes. The server **requires** `async_mode: true` and returns a `202` with a `job_id`. Poll `/v1/jobs/{id}`.

### Job backends (single vs multi-replica)

| Backend | Survives restart? | Cross-replica polling? | Cross-replica execution? | Deps |
| ------- | ----------------- | ---------------------- | ------------------------ | ---- |
| `inprocess` (default) | No  | No  | No  | none |
| `sqlite` | Yes (one pod or shared PVC) | Yes, if PVC shared | No (pod-local) | none |
| `redis`  | Yes | Yes | **Yes** | Redis |

For ≥2 replicas behind a Service, use Redis:

```bash
python -m orchestrator serve \
  --job-backend redis --redis-url redis://redis.svc:6379/0 \
  --replica-id $POD_NAME --worker-concurrency 4
```

Each replica runs N worker threads that `BRPOPLPUSH` from a shared queue, so
work fans out across the cluster. On startup each replica reclaims anything
stranded in its own `processing:{replica-id}` list (recovers from prior crash).

Cross-replica recovery is handled by a **janitor** that runs on every replica:

- Each replica refreshes `heartbeat:{replica-id}` on a ticker (TTL `--heartbeat-ttl`, default 60s).
- A janitor sweep (every `--janitor-interval`, default 30s) scans `processing:*` keys.
- When a replica's heartbeat key has expired, the janitor drains its processing
  list, increments each descriptor's `attempts`, and pushes it back onto the
  shared queue — any live replica can pick it up next.
- After `--janitor-max-attempts` (default 3) the job is marked `failed` with
  `error_class: MaxRetriesExceeded`.
- Coordination via a `SET NX EX` lock so only one replica sweeps at a time
  (compare-and-delete release uses `WATCH/MULTI/EXEC`).
- Re-execution semantics are **at-least-once** — handlers should be idempotent.

### Environment variables

| Var | Purpose |
| --- | ------- |
| `ORCHESTRATOR_API_KEY`     | Enables auth on `/v1/*`. Strongly recommended. |
| `ORCHESTRATOR_SCAN_ROOTS`  | Colon-separated allowlist for `scan-assess` targets. |
| `ORCHESTRATOR_CORS_ORIGINS`| Comma-separated CORS origins. Off by default. |
| `ORCHESTRATOR_JOB_DB`      | SQLite path for `--job-backend sqlite`. |
| `ORCHESTRATOR_REDIS_URL`   | Redis URL for `--job-backend redis`. |
| `BEDROCK_MODEL_ID`         | Enables AI mode. |
| `AWS_DEFAULT_REGION`       | Bedrock region (default `ap-northeast-1`). |

### Docker

```bash
docker build -t ai-risk-platform .

docker run --rm -p 8000:8000 \
  -e ORCHESTRATOR_API_KEY=$(openssl rand -hex 32) \
  -v $(pwd)/controls/products:/app/controls/products:ro \
  ai-risk-platform
```

The default image runs **import-only** (no scanners baked in). Layer in
semgrep/grype/gitleaks/checkov if you need `scan-assess`.

### Kubernetes

See [docs/DEPLOY.md](docs/DEPLOY.md) for the full walkthrough. Quick start:

```bash
# Edit secret + product configs.
cp deploy/kubernetes/10-secret.example.yaml deploy/kubernetes/10-secret.yaml
cp deploy/kubernetes/11-configmap-products.example.yaml deploy/kubernetes/11-configmap-products.yaml

# Apply.
kubectl apply -f deploy/kubernetes/00-namespace.yaml
kubectl apply -f deploy/kubernetes/10-secret.yaml
kubectl apply -f deploy/kubernetes/11-configmap-products.yaml
kubectl apply -k deploy/kubernetes/
```

### Example call

```bash
curl -X POST http://localhost:8000/v1/products/payment-api/assess \
  -H "X-API-Key: $ORCHESTRATOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @semgrep-results-wrapped.json
```

Where the body is `{"results": [{"scanner": "semgrep", "content": <semgrep-json>}, ...]}`.

## Integration with Your CI/CD

Add to any project's GitHub Actions workflow:

```yaml
- name: Install AI Risk Platform
  run: pip install git+https://github.com/s1ns3nz0/ai-risk-platform.git

- name: Run Risk Assessment
  env:
    BEDROCK_MODEL_ID: ${{ secrets.BEDROCK_MODEL_ID }}
    AWS_DEFAULT_REGION: ap-northeast-1
  run: |
    python -m orchestrator risk-assess . \
      --product ${{ github.event.repository.name }} \
      --output output
```

## Project Configuration

Each project using this platform needs a product config directory:

```
your-project/
  controls/
    products/
      your-product/
        product-manifest.yaml    # System description, CIA levels, deployment
        risk-profile.yaml        # Frameworks, thresholds, risk appetite
        assets.yaml              # Asset register (optional)
```

See `examples/payment-api/` for a complete example.

## Architecture

```
orchestrator/
  scanners/       5 scanner wrappers (Semgrep, Grype, Gitleaks, Checkov, ZAP)
  assessor/       AI risk assessor (Bedrock Claude) + static fallback
  rmf/            SP 800-30 pipeline, SAR, POA&M, authorization engine
  gate/           YAML threshold + OPA/Rego gate evaluator
  controls/       Controls repository loader + mapper
  exporters/      Dashboard JSON exporter
  evidence/       JSONL evidence writer
  intelligence/   EPSS enrichment, threat modeling
  resilience/     Retry engine, failure policy, overrides

controls/         Compliance baselines (OSCAL-compatible YAML)
rego/             OPA gate policies
```

## Key Design Decisions

- **AI is advisory only** — gate decisions are deterministic (YAML + OPA)
- **Gate path is 100% local** — no network dependencies for pass/fail
- **Strategy pattern** — StaticRiskAssessor and BedrockRiskAssessor share the same interface
- **SP 800-30 methodology** — threat sources → events → likelihood → impact → risk
- **Parallel AI pipeline** — per-finding analysis via ThreadPoolExecutor + streaming

## Testing

```bash
make test          # pytest tests/unit/
make lint          # ruff + mypy
```
