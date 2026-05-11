# Compliance-Driven AI Risk Platform — Architecture Design

## 1. Overview

This document specifies the design of a centralized, in-house DevSecOps platform for regulated fintech organizations (crypto exchange, payment service, digital bank).

The platform inverts the default assumption of most Application Security Posture Management (ASPM) tools. Instead of aggregating scanner output first and mapping to compliance frameworks as an afterthought, this platform starts from the compliance framework (NIST CSF, CIS Controls, PCI DSS, FISC, OWASP ASVS) and derives the verification activities — SAST, DAST, IaC policy, SCA, runtime detection — from the applicable controls.

The AI layer, hosted on AWS Bedrock, is deliberately scoped to a **contextual translator** role. It never acts as a scanner, nor does it close policy gates. Deterministic rule engines (OPA/Rego, YAML thresholds, Checkov hard-fail) retain exclusive authority over block/allow decisions. This is a critical design constraint for auditability in regulated environments.

### Core thesis

> Risk drives controls. Controls drive verification. Verification produces evidence. Evidence is the compliance artifact. AI translates context between each of these layers without making final decisions.

---

## 2. Problem and Positioning

### Limitations of existing ASPM tools

Current ASPM platforms (Cycode, ArmorCode, Apiiro, Snyk AppRisk, Phoenix Security, Ox Security, Aikido, Jit, Invicti, CrowdStrike Falcon ASPM, Checkmarx One) share a common architectural pattern: they ingest findings from multiple scanners, correlate and deduplicate, apply risk scoring, and present a unified dashboard. The compliance mapping is a downstream report.

This pattern has two structural weaknesses relevant to regulated fintech:

1. **No design-time coupling.** Controls are checked after code is written. Security-by-design requires controls to be selected and bound to a product *before* implementation.
2. **Evidence chains are implicit.** Auditors asking "show me the evidence that PCI DSS 6.3.1 is satisfied for the payment API in Q3" receive aggregate reports, not traceable evidence chains with a single control identifier flowing through requirement, policy, scan, and runtime monitoring.

### This platform's distinguishing properties

- **Framework-first orchestration** — every verification activity is derived from a framework control
- **Control ID as the unifying primary key** — a single identifier links OSCAL catalog entries, scanner rules, findings, and evidence
- **AI as translator, never as gate** — all blocking decisions are made by deterministic rule engines
- **Auditor-ready by design** — a single query over the control ID produces a complete evidence pack

---

## 3. Target Roles

### Binance — Security Engineer (Python)

Emphasizes preventative security, automation-first controls, and building internal security platforms in Python. CI/CD pipelines, Kubernetes security, misconfiguration detection.

**Alignment:** Python-based orchestrator, internal platform built from scratch, automation of misconfiguration detection, detection engineering module.

### PayPay — Cloud Platform Engineer

AWS-centric cloud platform engineering with Terraform, GitHub Actions, ArgoCD, Wiz, Backstage. PCI DSS experience and AI/ML infrastructure.

**Alignment:** Terraform IaC policy gate, PCI DSS as first-class baseline, AI/ML infrastructure via Bedrock.

### Money Forward — Product Security Specialist, Digital Bank

Product security for SMBC-partnered digital bank. NIST CSF, CIS Controls, FISC, DevSecOps tooling.

**Alignment:** NIST CSF and CIS Controls as native baselines, FISC mapping, architecture review support.

---

## 4. Architecture

### Design Principles (validated through 11 rounds of Red Team review)

1. **Gate path is 100% local.** Gate decisions (pass/fail) depend only on local CLI scanner output + local YAML threshold evaluation. No external service (DefectDojo, Bedrock) can block the gate path.

2. **Evidence path is networked and recoverable.** Findings are written to JSONL (always, local) and optionally pushed to DefectDojo. If DefectDojo is down, findings are queued and reconciled later.

3. **AI never gates.** The `gate_recommendation` field from AI is advisory only. Actual PR blocking is performed by deterministic YAML thresholds and OPA/Rego policies.

4. **Strategy pattern for AI.** `StaticRiskAssessor` and `BedrockRiskAssessor` implement the same `RiskAssessor` protocol. The platform works without AI; AI adds cross-signal reasoning when configured.

5. **Orchestrator-centric integration.** No MCP servers, no Bedrock Agents. The Python orchestrator queries REST APIs directly and calls Bedrock InvokeModel API. This reduces complexity, improves testability, and eliminates unnecessary middleware.

### Layered View

```
+-----------------------------------------------------------+
|  Cross-cutting: Compliance Control Plane                   |
|  Controls Repository (OSCAL YAML) + Risk Assessment Engine |
|  Control ID traces through every phase                     |
+-----------------------------------------------------------+
       |             |             |             |
  +--------+   +----------+  +----------+  +-----------+
  |  Plan  |-->| Develop  |->|  Build   |->|   Test    |
  |        |   |          |  |          |  |           |
  | Risk   |   | Semgrep  |  | Grype    |  | Gate      |
  | Assess |   | Gitleaks |  | SBOM     |  | Decision  |
  | Select |   | Checkov  |  |          |  | (YAML +   |
  | Baseline|  |          |  |          |  |  OPA)     |
  +--------+   +----------+  +----------+  +-----------+
       |             |             |             |
  +--------+   +--------------------------------------+
  | Operate|   |            Monitor                    |
  |        |   | Sigma Engine · Polling · Re-assessment|
  +--------+   +--------------------------------------+
```

### Control Plane vs Verification Layer

**Control Plane** is the governance layer. It answers *"what must be true for this product?"*. Risk Assessment categorizes the product, which drives control baseline selection from the Controls Repository.

**Verification Layer** is the execution layer. It answers *"is it true?"*. Each scanner runs checks and produces findings tagged with Control IDs.

The Control Plane selects and configures the Verification Layer; the Verification Layer produces evidence that the Control Plane consumes.

---

## 5. Risk Assessment Methodology

### Core Framework: NIST RMF (SP 800-37 Rev 2)

The platform uses NIST RMF as its internal methodology. Users don't see RMF — they configure which compliance frameworks apply. The platform handles the lifecycle:

| RMF Step | Platform Component | Trigger |
|---|---|---|
| Prepare | `risk-profile.yaml`, `product-manifest.yaml` | One-time setup |
| Categorize | Risk Assessment Engine (design-time) | Product onboarding |
| Select | Controls Repository baseline lookup | After categorization |
| Implement | Pipeline configuration | After control selection |
| Assess | Scanner execution + risk scoring | Every PR, build, deploy |
| Authorize | YAML threshold + OPA gate | Pre-merge, pre-deploy |
| Monitor | Sigma detection + polling + re-assessment | Continuous |

### Risk Scoring

```
Risk = Likelihood × Impact

Likelihood = f(
  finding_severity_distribution,    # critical/high/medium/low ratio
  pci_scope_ratio,                  # PCI-scoped finding percentage
  secrets_detected                  # boolean (presence increases likelihood)
)

Impact = f(
  data_classification,              # PCI > PII-financial > PII-general > public
  control_coverage,                 # required controls vs covered ratio
  jurisdiction_sensitivity          # JP(FISC) > EU(GDPR) > other
)
```

Every factor is recorded with evidence for audit traceability.

### AI's Role in Risk Assessment

| Without AI (Static) | With AI (Bedrock) |
|---|---|
| Deterministic categorization from data classification | AI reads product description, suggests tier + ATT&CK threat profile |
| Template narrative: "Found N critical findings..." | Cross-signal narrative connecting findings to business context |
| Deterministic risk score | Same score + AI explanation of *why* the score matters |
| Manual gap analysis | AI identifies missing controls and recommends remediation |

**The deterministic score is always authoritative.** AI cannot override it. AI adds narrative and recommendations on top.

---

## 6. AI Strategy

### Model Selection

| Task | Model | Rationale |
|---|---|---|
| Risk assessment reasoning | Claude Sonnet 4.6 | Cross-signal reasoning required |
| Signal filtering (MVP tier) | Claude Haiku 4.5 | Fast, cheap summarization |
| No AI mode | — | StaticRiskAssessor |

### Three AI Value Patterns

These are the specific capabilities AI provides that static analysis cannot:

1. **Contextual blast radius analysis.** AI reads PR diff + existing findings + product context simultaneously. "This S3 bucket is in the same VPC as the payment database. Combined with Finding #1234 (permissive IAM), this creates a lateral movement path to PCI cardholder data."

2. **VEX exploitability reasoning.** AI performs reachability analysis combining CVE details with codebase. "CVE-2025-XXXX affects lodash.merge but this codebase only uses lodash.get. The vulnerable function is not in any execution path. EPSS score 0.03. Recommend VEX status: not_affected."

3. **Semantic security review.** AI catches logic-level issues that pattern-matching scanners miss. "This PR changes JWT validation from RS256 to HS256. This is a cryptographic downgrade violating ASVS-V3.5.1."

### Two-Stage Pipeline (MVP tier)

For large signal sets that exceed context limits:

```
Stage 1: FILTER (Haiku — fast, cheap)
  Input: raw signals (all findings, full diff)
  Output: relevant findings in full + background summary

Stage 2: REASON (Sonnet — accurate)
  Input: filtered signals + product manifest + controls
  Output: risk assessment with cross-signal insights
```

Key insight: **filter before summarize.** Don't summarize 200 findings — filter to the 5-10 that overlap with the current change, pass those in full, summarize the rest.

---

## 7. Gating Design

### Two Additive Layers

```
YAML Thresholds (fast path) → evaluated first
   If blocked: stop, report which threshold failed
   If passed: continue

OPA/Rego Policies (detailed path) → evaluated second
   If any policy denies: stop, report which policy
   If all pass: PROCEED
```

Both must pass. No ambiguity.

### Failure Policy (MVP tier)

| Risk Tier | Scan Failure | Override |
|---|---|---|
| CRITICAL | Block | 2 approvers, 4h SCA deferred |
| HIGH | Block | 1 approver, 8h SCA deferred |
| MEDIUM | Warn and proceed | Logged |
| LOW | Warn and proceed | Logged |

### "AI Doesn't Gate" Principle

When an auditor asks "why was this PR blocked?", the answer must be a human-readable policy reference:

```
BLOCKED: max_critical_findings violated — found 3, limit 0 (control: PCI-DSS-6.3.1)
```

Never an AI inference.

---

## 8. Scanner Integration

### MVP-0 Scanners (gate path — all local CLI)

| Scanner | Category | Gate? | Control Examples |
|---|---|---|---|
| Checkov | IaC | Yes | PCI-DSS-1.3.1, FISC-実119 |
| Semgrep | SAST | Yes | PCI-DSS-6.3.1, ASVS-V5.3.4 |
| Grype | SCA | Yes | PCI-DSS-6.3.1, ASVS-V14.2.1 |
| Gitleaks | Secrets | Yes | PCI-DSS-3.5.1, ASVS-V2.10.1 |

### Future Scanners (planned, not yet implemented)

| Scanner | Category | Gate? | Notes |
|---|---|---|---|
| CodeQL | SAST (semantic) | Yes | Custom queries for fintech |
| ZAP | DAST | Tier-dependent | Requires running target |
| Dependency-Track | SCA enrichment | No (enrichment only) | EPSS, VEX, policy engine |

### Control ID Mapping

Every scanner finding is tagged with Control IDs via `ControlMapper`:

```python
Finding(
    source="checkov",
    rule_id="CKV_AWS_19",
    severity="high",
    control_ids=["PCI-DSS-3.5.1", "FISC-実119"],  # mapped from controls YAML
    product="payment-api"
)
```

The mapping is deterministic — defined in Controls Repository YAML, not by AI.

---

## 9. Detection Engineering

### Custom Sigma Engine (144 LOC)

Purpose-built Python Sigma matcher for 3-5 detection rules. Not a full SIEM — demonstrates the architecture.

Supported: field matching, `|contains`/`|startswith`/`|endswith` modifiers, AND/OR conditions.

### Rules

| Rule | ATT&CK | Control ID |
|---|---|---|
| Brute force login | T1110 | PCI-DSS-10.2.1 |
| SQL injection attempt | T1190 | PCI-DSS-6.3.1, ASVS-V5.3.4 |
| Data exfiltration | T1048 | PCI-DSS-10.2.1 |
| Privilege escalation | T1078 | FISC-実121 |

Each rule is tagged with ATT&CK technique IDs and Control IDs, enabling coverage dashboards.

---

## 10. Evidence Chain

### Data Flow

```
Gate Path (100% local):
  Scanner CLI → Findings → YAML Threshold + OPA → PASS/FAIL

Evidence Path (networked, recoverable):
  Findings → JSONL (always) → DefectDojo (if available) → AI narrative (if Bedrock)
```

### Evidence Export

`orchestrator export --control PCI-DSS-6.3.1 --product payment-api`

Produces a JSON report with:
- Control definition (from OSCAL YAML)
- All findings mapped to that control
- Scanners that verified it
- Coverage status (full / partial / none)
- Risk assessments referencing it

**Control ID is the primary key.** A single query traces from framework requirement through scanner finding to evidence artifact.

---

## 11. End-to-End Scenario

### Payment API — QR Code Payment Confirmation (PCI + FISC scope)

**Step 1 — Categorization (RMF Step 2)**
Product manifest declares: PCI data, PII-financial, Japan jurisdiction.
Risk tier: CRITICAL.

**Step 2 — Baseline Selection (RMF Step 3)**
13 controls auto-selected: PCI-DSS (6) + ASVS (4) + FISC (3).

**Step 3 — Scanning (RMF Step 5)**
Checkov: 20 IaC findings. Grype: 20 dependency CVEs. Gitleaks: 1 hardcoded key.

**Step 4 — Gate (RMF Step 6)**
BLOCKED: critical findings + secrets in PCI scope. Zero tolerance policy.

**Step 5 — Risk Assessment**
Score: 9.0/10. Static narrative or AI cross-signal analysis.

**Step 6 — Detection**
Sigma rules match 5 attack patterns in application logs.

**Step 7 — Evidence Export**
75% control coverage. JSON report with full traceability.

---

## 12. Technology Stack

| Layer | Component | Role |
|---|---|---|
| Orchestrator | Python 3.11+ | CLI, integration, orchestration |
| Controls | OSCAL YAML + JSON Schema | Framework source of truth |
| SAST | Semgrep | Code vulnerability detection |
| IaC scanning | Checkov | Infrastructure policy checking |
| SCA | Grype (gate) + Syft (SBOM) | Supply chain analysis |
| Secrets | Gitleaks | Credential detection |
| Policy engine | YAML thresholds + OPA/Rego | Deterministic gate decisions |
| Detection | Custom Sigma engine | Runtime detection |
| AI | AWS Bedrock (Claude Sonnet 4.6) | Context translation |
| Evidence | JSONL + DefectDojo | Finding storage and triage |

### Explicitly not used

- MCP servers (orchestrator queries APIs directly)
- Bedrock Agents (orchestrator constructs prompts)
- Trivy, KICS (Checkov sufficient for IaC)
- Wazuh (custom Sigma engine instead)
- SQLite (evidence is generated artifact, not DB)

---

## 13. Testing Strategy

| Layer | What | How |
|---|---|---|
| Unit | Pure functions, scoring, parsing | pytest, <1s |
| Contract | API response parsing | Recorded responses, no live services |
| E2E | Full demo flow | `make demo` with real or fixture data |

170+ unit tests. mypy strict mode. ruff linting.

---

## 14. Architecture Decision Records

See [ADR.md](ADR.md) for the 9 key decisions:

1. NIST RMF as internal methodology
2. Orchestrator-centric (no MCP/Bedrock Agents)
3. Gate path 100% local
4. AI never gates
5. Grype gates, DT enriches
6. MVP-0 → MVP layering
7. Custom Python Sigma engine
8. Evidence as generated artifact
9. SBOM generation with Syft + Grype SBOM/container scanning

Each ADR includes rationale, tradeoffs, and what was explicitly rejected.

---

## 15. Future Work

| Extension | Description |
|---|---|
| Dependency-Track | SCA enrichment with EPSS scores, VEX workflow, policy engine |
| CodeQL | Custom semantic queries for fintech (hardcoded creds, negative payment, PII logging) |
| ZAP (DAST) | Dynamic application security testing against running targets |
| Failure policy | Retry logic, override mechanism, SLA tracking per risk tier |
| Two-stage AI | Haiku filter → Sonnet reason pipeline for large finding sets |
| D3FEND mapping | Defensive countermeasure mapping bridging ATT&CK threats to controls |
| Container signing | Image signing with cosign/Sigstore (scanning already implemented) |
| DORA metrics | Deployment frequency, lead time, MTTR, change failure rate |
| Backstage plugin | Developer self-service + auditor view UI |

---

*This document was developed through 11 rounds of adversarial Red Team review (81+ findings raised and resolved) to validate architectural consistency, compliance fidelity, and implementation feasibility.*
