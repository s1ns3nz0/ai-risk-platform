# AI Risk Assessment Platform

### Stop drowning in scanner findings. Ship code that's already been risk-assessed against NIST SP 800-30 — by the time your pull request opens.

---

## The Problem

**The threat landscape never stops moving — and your CI/CD pipeline already knows it.**

Every week brings a new zero-day, a new supply-chain compromise, a new exploitation technique. To keep up, modern engineering teams have wired five, six, sometimes nine security scanners directly into their pipelines: Semgrep for SAST, Grype and Trivy for SCA, Gitleaks for secrets, Checkov for IaC, ZAP for DAST, kube-bench for cluster posture, SpotBugs for Java. Every push triggers all of them. The pipeline generates **mountains of evidence** — and that's exactly where the problem starts.

Ask yourself, honestly:

- **Are you actually leveraging every result your scanners produce?** Or are most of them piling up in a dashboard nobody reads, getting auto-closed when they age out, or filtered to "critical only" because anything else is unmanageable?
- **When risk-assessment time comes around, can you use all of those results?** Or does someone manually export CSVs, deduplicate by hand, and stitch findings together with a compliance framework on the side — losing fidelity at every step?
- **And how long does that take?** A single thorough SP 800-30 risk assessment, done properly by a human analyst, takes *days to weeks* per system. By the time it's finished, the code has shipped three more releases and the threat model is already out of date.

The deeper failures stack up fast:

- **Security teams drown in noise.** A typical pull request produces 200+ findings. Most are noise. The dangerous ones get buried.
- **Compliance teams can't trace.** Auditors ask *"which control did this finding violate?"* and nobody has an answer. Spreadsheets get maintained by hand.
- **Merges either get waved through or blocked indiscriminately.** Without a defensible risk score, the gate is "block on critical" — too coarse to be useful, too noisy to trust.
- **The pipeline doesn't know what the business cares about.** A SQL injection in a static marketing page and a SQL injection in the cardholder-data store get treated the same.

The result: scanners run, reports pile up, real risk slips through, and the security team becomes a bottleneck instead of a partner — exactly when emerging threats demand you move *faster*, not slower.

---

## The Solution

**An AI risk platform that lives inside your pipeline — and runs a NIST SP 800-30 risk assessment on every single push.**

Not quarterly. Not before a release. **Every push.** The same scanner output your pipeline is already producing gets fed into a long-lived service that reasons about *every finding* against the federal SP 800-30 methodology, returns a deterministic ship-or-block decision, and emits an auditor-ready evidence package — in roughly the time it takes to run your unit tests.

Concretely, on every commit the platform:

1. **Ingests every result from every scanner** — nothing left on the table, nothing summarized away
2. **Maps each finding to the compliance controls it touches** (PCI-DSS, SOC 2, ISO 27001)
3. **Reasons about each finding using AWS Bedrock (Claude Sonnet 4.6 + Haiku 4.5)** against the full NIST SP 800-30 methodology — threat source, threat event, likelihood, impact, risk
4. **Decides** PASS or BLOCK using a deterministic policy gate (no AI on the gate path)
5. **Emits** a Security Assessment Report and a Plan of Action & Milestones — on every build

What used to be a quarterly compliance exercise — weeks of human effort, already stale by the time it finished — becomes a **30-second step in your pipeline**, repeated automatically every time anyone pushes code.

---

## How It Works In Your Pipeline

The integration is intentionally trivial. One step in your workflow:

```yaml
- name: Risk Assessment
  run: |
    curl -X POST https://risk-platform.internal/v1/products/payment-api/assess \
      -H "X-API-Key: ${{ secrets.RISK_API_KEY }}" \
      -d @scanner-results.json \
      --fail-with-body
```

That's it. The platform takes it from there.

### What that one call does, in plain English

> *Your CI job hands the platform a bundle of scanner output and a product name. The platform looks up which compliance frameworks that product is in scope for. It deduplicates the findings, enriches each vulnerability with its real-world exploit probability (EPSS), and routes the top critical findings through Claude on AWS Bedrock — which reasons about each one as a NIST SP 800-30 risk scenario: who would attack this, how, how likely is it, what's the business impact, what's the risk level. The platform then runs the result through your gate policy (a YAML file you wrote once) and writes back a single answer: ship or block, plus an auditor-ready evidence package.*

### Why "one HTTP call" instead of "pip install in CI"

Because installing the platform in every CI runner means re-loading control baselines, re-connecting to Bedrock, and re-warming caches on every commit. We made it a long-lived service so the controls, Bedrock client, and EPSS data **load once at boot**. A 5-minute CI step becomes a 30-second network call. Multiply that by thousands of builds a week — the cost difference is significant.

### When the gate says BLOCK, the build fails

The response carries the gate decision. `--fail-with-body` makes the CI step exit non-zero. The merge is blocked. The SAR and POA&M attach as build artifacts. Developers get a precise reason — *"BLOCKED: 2 critical findings in PCI-DSS scope, violating PCI-DSS-6.3.1"* — not a wall of CVE IDs.

---

## The Engine: AWS Bedrock + Claude

The hardest part of risk assessment isn't running scanners. It's **reasoning** about what a finding means in the context of *this specific system* — its data classification, its exposure, its compliance scope, its real-world exploit conditions. That's the part humans are slow at and rule engines are bad at. It's what Claude on Bedrock is built for.

### Why Bedrock, specifically

- **Managed Claude on AWS** — no separate vendor, no separate billing, no data leaving your AWS account
- **Region-pinned (`ap-northeast-1`)** for jurisdictions with data-residency requirements (this was originally built for Japanese financial workloads)
- **Prompt caching cuts cost ~40%** — the methodology and control baseline are loaded into Bedrock's ephemeral cache once, then every per-finding call reuses it
- **No data ever trains a model** — Bedrock's enterprise terms keep your code and findings out of any training set

### Two Claude models, two jobs

| Model | What it does |
| --- | --- |
| **Haiku 4.5** | Fast, cheap triage. Takes thousands of findings and picks the top 200 worth deep analysis. |
| **Sonnet 4.6** | Deep reasoning. Walks every selected finding through the full SP 800-30 methodology in parallel (5 at a time). |

A typical 200-finding assessment finishes in about **2 minutes** instead of the ~30 minutes a serial single-model approach would take.

### What Claude is allowed to do — and what it isn't

This is the most important design decision in the product:

- **Claude writes the narrative.** Threat events, MITRE ATT&CK mapping, business impact rationale, recommended response — that's where AI reasoning earns its keep.
- **Claude does not write the score.** The 0–100 risk score is computed deterministically from a published matrix. Same inputs → same score, every time. Reproducible by an auditor without re-running the model.
- **Claude does not decide PASS or BLOCK.** That comes from a YAML threshold file plus an OPA/Rego policy. The gate runs entirely locally and is unchanged whether Bedrock is up, down, or slow.

If Bedrock is unreachable, the platform falls back to a deterministic static assessor — the build still ships, the gate still works, the audit trail is still complete. **AI is advisory; the controls are load-bearing.**

This is what makes the output legally defensible. An auditor can reproduce the gate decision from the raw findings and the YAML config alone. The AI's contribution is the *why* — the readable, traceable SP 800-30 narrative that turns "CRITICAL severity from Semgrep" into "high-likelihood adversarial threat against cardholder data, violating PCI-DSS-6.3.1."

---

## The Methodology: NIST SP 800-30, Applied Per Finding

**Why NIST SP 800-30?** Because it's the framework U.S. federal systems use for authorization decisions — and the same logic underwrites how serious enterprises talk about risk. Most scanners stop at "severity: high." NIST SP 800-30 forces you to answer *high to whom, doing what, with what impact on which CIA dimension.* That's the difference between a triage queue and a defensible risk position.

For every finding, Claude walks the full SP 800-30 reasoning chain:

1. **Who would attack this?** *(threat source: adversarial, accidental, structural, environmental)*
2. **How would they attack it?** *(threat event, mapped to MITRE ATT&CK techniques)*
3. **What's the vulnerability?** *(the scanner finding itself, plus EPSS exploit probability)*
4. **How likely is it to actually happen?** *(initiation likelihood × impact likelihood, modulated by EPSS and exposure)*
5. **What's the impact if it does?** *(scored against the system's FIPS 199 confidentiality / integrity / availability ratings — declared once in a product manifest)*
6. **What's the overall risk?** *(likelihood × impact → ordinal level + a 0–100 score)*

The product manifest is the secret ingredient. Two systems can have the exact same SQL injection finding, but one is in `confidentiality=high` PCI scope and the other is in a `confidentiality=low` internal dashboard. **NIST SP 800-30 forces the platform to score them differently** — context-aware impact, not just scanner-aware severity. That's how real risk gets surfaced without false-positive fatigue.

### What an SP 800-30 narrative actually reads like

> *Threat event TE-002: SQL injection via `/v1/checkout`, MITRE T1190. Adversarial source, capability high, EPSS 0.42. The vulnerability reaches the cardholder data store (FIPS 199 Confidentiality = High, per product manifest). Initiation likelihood **high**, impact likelihood **high** → overall **high**. Impact: confidentiality **high**, integrity **moderate**, availability **low**. Controls violated: PCI-DSS-6.3.1, PCI-DSS-6.4.3, SOC2-CC6.1. **Risk score 78 / High.** Recommended response: **mitigate** — parameterize the query, add WAF rule, deadline 7 days, owner: payments-team.*

That's not a paragraph a security engineer wrote. That's the output of one CI run. It flows straight into the SAR and the POA&M, with the file:line citation back to the original scanner finding intact.

### Anti-hallucination is non-negotiable

The platform validates every AI-produced field against ground truth:
- Every CVE referenced by Claude must exist in the input findings
- Every control ID must exist in the loaded baseline
- Every risk level must be one of the five SP 800-30 ordinals

Invalid references are rejected and the finding silently falls back to the static path. Claude is never trusted to invent identifiers — only to reason about real ones.

---

## What You Walk Away With

Every CI run produces three durable artifacts, regardless of whether the gate passed or blocked:

- **Gate Decision** — the immediate yes/no your pipeline needs, with the exact threshold that fired and the control IDs it tied to
- **Security Assessment Report (SAR)** — auditor evidence, per-control: was it satisfied, by which scanner, with what residual risk
- **Plan of Action & Milestones (POA&M)** — every open risk with a deadline (critical=7d, high=30d, medium=90d, low=180d), an owner, and a path to closure. Closes itself automatically on the next run when the finding is gone.

Plus an authorization decision — ATO (Authority to Operate) or DATO (Denied) — produced deterministically from gate result plus open POA&M count. The same decision a federal authorizing official would render, generated automatically per build.

---

## Why This Matters

**For security teams:** stop being the bottleneck. The gate runs in CI, not in your inbox. You spend your time on the risks the AI flagged as high-likelihood-high-impact, not triaging 200 medium-severity findings per PR.

**For compliance teams:** every commit produces an audit-ready evidence package. The SAR you used to assemble by hand at quarter-end is generated automatically on every build. The POA&M closes itself when the finding gets fixed.

**For engineering teams:** clear, specific, context-aware feedback. *"BLOCKED: SQL injection in cardholder data path, violates PCI-DSS-6.3.1, fix in 7 days"* — not *"73 high-severity findings, please review."*

**For leadership:** you can demonstrate, on demand, that every production deploy was risk-assessed against a recognized federal methodology — with a defensible score that doesn't depend on an AI being available.

---

## In One Sentence

A NIST-grade risk-assessment engine that turns your CI/CD pipeline's noisy scanner output into a deterministic ship/block decision and an audit-ready evidence package — using AWS Bedrock to do the reasoning your security team doesn't have time for.
