# Platform Architecture — Risk Assessment Flow

How the platform turns scanner output from a CI pipeline into a NIST SP 800-30 risk assessment, a gate decision, and an audit-ready evidence package. Focused on the sequence — not API surface, not configuration.

---

## 1. The two diagrams

- **Outer sequence** — what happens between the CI runner and the platform on a single `POST /v1/products/{name}/assess` call
- **Inner sequence** — what happens *inside* the SP 800-30 risk pipeline (4 stages, AWS Bedrock fan-out)

---

## 2. Outer sequence — CI request to evidence package

```mermaid
sequenceDiagram
    autonumber
    participant CI as CI Runner<br/>(GitHub Actions / GitLab / Jenkins)
    participant API as FastAPI<br/>(server/app.py)
    participant Parser as Scanner Parsers<br/>(importer/*)
    participant Jobs as Job Queue<br/>(in-process / Redis)
    participant Assess as run_assessment()<br/>(server/assess.py)
    participant VEX as VEX Filter<br/>(orchestrator/vex.py)
    participant Cat as Risk Assessor<br/>(Bedrock or Static)
    participant Ctrls as Controls Repository<br/>(OSCAL YAML)
    participant EPSS as EPSS Enricher
    participant Pipe as SP 800-30 Pipeline<br/>(rmf/pipeline.py)
    participant Gate as Gate Evaluator<br/>(YAML + OPA/Rego)
    participant Out as SAR + POA&M + Authorization
    participant Store as Persistence<br/>(SQLite / Redis / JSONL)

    CI->>API: POST /v1/products/payment-api/assess<br/>{ results: [...scanner JSON...], async_mode: true }
    API->>API: Validate API key, look up product
    API->>Parser: _parse_payloads(scanner bundles)
    Parser-->>API: Finding[] + submitted_scanners

    alt Bedrock mode (async)
        API->>Jobs: enqueue job descriptor
        API-->>CI: 202 Accepted { job_id }
        Note over Jobs: any replica picks job<br/>via BRPOPLPUSH
    else Static mode (sync)
        API->>Assess: run inline
    end

    Jobs->>Assess: handler(descriptor)
    Assess->>VEX: apply_vex(findings, vex_doc)
    VEX-->>Assess: suppressed CVEs + VexSummary
    Assess->>Cat: categorize(manifest) → FIPS 199 tier
    Cat-->>Assess: tier (low / moderate / high)
    Assess->>Ctrls: select_baseline(tier)
    Ctrls-->>Assess: Control[] (PCI / SOC 2 / ISO 27001)
    Assess->>EPSS: enrich(vulnerable findings)
    EPSS-->>Assess: EnrichedVulnerability[]

    Assess->>Pipe: pipeline.run(findings, vulns, manifest, controls, vex_summary)
    Note right of Pipe: see Inner Sequence
    Pipe-->>Assess: SP80030Report

    Assess->>Gate: ThresholdEvaluator + OpaEvaluator
    Gate-->>Assess: GateDecision (PASS / BLOCK + reasons)

    Assess->>Out: SARGenerator.generate(...)
    Assess->>Out: POAMGenerator.generate(...)
    Assess->>Out: AuthorizationEngine.decide(...)
    Out-->>Assess: SAR + POA&M items + ATO/DATO

    Assess->>Store: persist AssessmentRecord + JSONL audit entry
    Assess-->>Jobs: AssessmentResult
    Jobs-->>CI: GET /v1/jobs/{id} returns 200 + result<br/>(CI polls until ready)
```

### What each step exists for

| # | Step | Why it's there |
| - | --- | --- |
| 1 | CI POST | Single integration point — one HTTP call per build |
| 2 | Parser | Normalize 9+ scanner formats into one `Finding` shape |
| 3 | Sync/async fork | Bedrock calls take minutes — must not block the CI runner |
| 4 | VEX filter | Suppress CVEs the team already triaged as `not_affected` |
| 5 | Categorize | FIPS 199 tier determines which control baseline applies |
| 6 | Baseline select | Tier → PCI / SOC 2 / ISO 27001 controls in scope |
| 7 | EPSS enrich | Real-world exploit probability per CVE |
| 8 | SP 800-30 pipeline | Per-finding risk reasoning (see Inner Sequence) |
| 9 | Gate | Deterministic PASS / BLOCK — never depends on AI |
| 10 | SAR + POA&M | Auditor evidence + remediation plan |
| 11 | Authorize | ATO / DATO decision from gate + open POA&M count |
| 12 | Persist | AssessmentRecord for delta comparison + JSONL audit trail |

---

## 3. Inner sequence — SP 800-30 risk pipeline

This is what `pipeline.run()` does. Four stages — AI participates only in stages 2 and 3.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as run_assessment()
    participant Pipe as RiskAssessmentPipeline<br/>(rmf/pipeline.py)
    participant Static as StaticPipeline<br/>(fallback)
    participant Pool as ThreadPoolExecutor<br/>(max_workers=5)
    participant Haiku as Claude Haiku 4.5<br/>(Bedrock)
    participant Sonnet as Claude Sonnet 4.6<br/>(Bedrock)
    participant Ground as validate_grounding()<br/>(rmf/grounding.py)

    Caller->>Pipe: run(findings, vulns, manifest, controls, vex_summary)

    rect rgba(80,120,200,0.10)
        Note over Pipe: Stage 1 — GATHER (no AI)
        Pipe->>Pipe: Dedup by (scanner, rule_id, package, version)
        Pipe->>Pipe: Merge EPSS, controls, VEX status onto each finding
    end

    rect rgba(200,140,60,0.10)
        Note over Pipe,Haiku: Stage 2 — FILTER (Haiku 4.5)
        alt findings > 200
            Pipe->>Haiku: invoke(filter_prompt, max_tokens=1024)
            Haiku-->>Pipe: top-N finding indices + reasoning
        else findings ≤ 200
            Pipe->>Pipe: deterministic severity sort
        end
    end

    rect rgba(180,80,180,0.10)
        Note over Pipe,Sonnet: Stage 3 — ASSESS (Sonnet 4.6, ×5 parallel)
        Pipe->>Pool: submit per-finding tasks
        loop for each filtered finding (×5 in flight)
            Pool->>Sonnet: stream_with_cache(<br/>system_prompt[cached],<br/>user_prompt,<br/>max_tokens=32768)
            Sonnet-->>Pool: SP 800-30 JSON<br/>(threat_source, threat_event,<br/>likelihood, impact,<br/>risk_determination, risk_response)
            Pool->>Pool: detect stop_reason="max_tokens"<br/>→ raise BedrockTruncatedResponseError
            Pool->>Ground: validate_grounding(parsed)
            alt grounding fails or AI truncated/errored
                Pool->>Static: _static_assess_single_finding(finding)
                Static-->>Pool: deterministic SP 800-30 dict
                Note over Pool: mode=hybrid for this finding
            else grounding passes
                Note over Pool: mode=ai for this finding
            end
        end
        Pool-->>Pipe: per-finding result[]

        Pipe->>Sonnet: _synthesize_summary(per-finding results, vex_summary)<br/>stream_with_cache(max_tokens=32768)
        Sonnet-->>Pipe: executive_summary + cross-signal insights<br/>+ recommendations
    end

    rect rgba(80,180,120,0.10)
        Note over Pipe: Stage 4 — RESPOND (no AI)
        Pipe->>Pipe: Map risk_response items → RiskResponse dataclasses
        Pipe->>Pipe: Compute risk_score deterministically<br/>(scoring/risk.py — never AI-overridden)
        Pipe->>Pipe: Assemble SP80030Report
    end

    Pipe-->>Caller: SP80030Report (mode: ai / static / hybrid)
```

### Why this split exists

- **Stage 1 is deterministic** because the same scanner output must always dedupe to the same threat events — that's what makes POA&M items stable across runs (so they auto-close instead of duplicating).
- **Stage 2 uses Haiku** because triaging hundreds of findings to a critical top-N is shallow reasoning where speed and cost matter more than depth.
- **Stage 3 uses Sonnet, parallelized** because per-finding SP 800-30 reasoning is the deepest cognitive work — and the only step where Claude earns its keep.
- **Stage 4 is deterministic** because the *response type* (accept / avoid / mitigate / share / transfer) and the *risk score* must be reproducible by an auditor without re-running the model.

### Failure handling

| Failure | Behavior |
| --- | --- |
| Bedrock unreachable (whole pipeline) | Fall back to `StaticRiskAssessmentPipeline` (deterministic path) |
| Bedrock fails on a single finding | Per-finding static fallback; other findings keep using AI → `mode = "hybrid"` |
| Bedrock hits `max_tokens` | `BedrockTruncatedResponseError` raised; per-finding falls back to static (prevents mid-word descriptions persisting) |
| Grounding validation rejects AI output | Same as above — per-finding static fallback |
| Rate limit hit (100 invokes/hour/pod) | `BedrockRateLimitError` raised; per-finding static fallback |

The gate decision is **always** computed from the report, regardless of which path produced each finding's analysis.

---

## 4. The hard boundary — AI is advisory, deterministic engines decide

Two things never depend on an AI call:

1. **The gate decision** (`PASS` / `BLOCK`) — computed from YAML thresholds + OPA/Rego policies against the SP 800-30 report
2. **The risk score** (0–100) — computed deterministically in `scoring/risk.py` from likelihood × impact level scores

Claude writes the *narrative*: threat-event mapping, MITRE ATT&CK technique, likelihood/impact evidence, business-impact rationale, recommended response. Claude never writes the score or the gate verdict.

This is what makes the output legally defensible — an auditor can reproduce the gate decision and the numeric score from the raw findings + YAML config alone. The AI's contribution is the *why*.

---

## 5. Where the durable artifacts come from

After `run_assessment()` returns, three files are written to disk and S3 (via the dashboard publisher):

| Artifact | Generated by | Used for |
| --- | --- | --- |
| **`sp800-30.json`** | `SP80030Report` from `pipeline.run()` | Auditor read-out, dashboard render |
| **`sar.json`** | `SARGenerator.generate()` | Per-control assessment evidence |
| **`poam.json`** | `POAMGenerator.generate()` | Remediation tickets, auto-closes on next run |
| **`authorization.json`** | `AuthorizationEngine.decide()` | ATO / DATO record |
| **`evidence/*.jsonl`** | `evidence/jsonl.py` | Append-only audit trail |

These are the same artifacts a NIST-aligned federal authorization process would produce — generated automatically per build.
