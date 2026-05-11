# AI Risk Assessment Platform

Compliance-driven risk assessment engine for DevSecOps pipelines. Implements NIST SP 800-30 Rev 1 risk assessment methodology with AI-powered analysis via AWS Bedrock.

## What It Does

- Runs 5 security scanners (Semgrep, Grype, Gitleaks, Checkov, ZAP)
- Maps findings to compliance controls (SP 800-53, PCI DSS, ASVS, FISC)
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
