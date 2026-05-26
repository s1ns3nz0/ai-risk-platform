# Deliver-Phase Scanner Integration Guide

**For the agent / team owning `payment-api`'s CI/CD pipeline.**

This guide tells you exactly what to add to the deliver job so the AI Risk Platform's SAR coverage stops showing ~18% on the DELIVER phase. The platform side (`ai-risk-platform`) is already deployed with the new scanner adapters — you only need to send the bundles.

---

## TL;DR

Add two HTTP POST calls to your **deliver** stage:

1. `cosign` bundle — proves the artifact you're about to ship is signed + has the expected attestations
2. `opa-admission` bundle — proves the cluster's admission gate accepted the manifest

Both POST to the existing `/v1/products/{product}/assess` endpoint, just with `"phase": "DELIVER"` and the new scanner names.

---

## Why this is needed

SAR coverage = `satisfied_controls / total_controls × 100`. A control is `satisfied` only when **the scanner that verifies it** is registered in the assessment's `submitted_scanners` set **and** has zero findings for that control. On the deliver phase today:

- The platform expects deliver-time scanners (`cosign`, `opa-admission`) for ~half of the deliver-mapped controls
- The CI submits SAST/SCA/IaC scanners only → those deliver-mapped controls all fall into `not-assessed`
- → 18% coverage

Once you start posting cosign + opa-admission bundles, those controls flip to `satisfied` (or `other-than-satisfied` if a verification fails — which is also useful signal). Expect deliver coverage to jump into the 70-90% range.

---

## Where to integrate in your pipeline

Per the DoD DevSecOps 6-phase model, the **DELIVER** phase is the bridge between artifact build (RELEASE) and runtime deploy (DEPLOY). Concretely, it covers:

- Signing the artifact and publishing signatures
- Publishing attestations (SBOM, provenance)
- Letting the admission controller validate the deploy manifest before it reaches the cluster

So in your GitHub Actions workflow, add a `deliver` job that runs **after** the build/push job and **before** the actual `kubectl apply` / Argo sync. Cosign verification runs on the just-published image; admission policy results come either from a dry-run admission check (`kubectl --dry-run=server apply`) or from the audit feed of Gatekeeper/Kyverno after the apply.

---

## Bundle #1 — cosign

### What the CI must do

1. Sign the image at build time (you may already do this):
   ```bash
   cosign sign --yes "$IMAGE@$DIGEST"
   ```
2. Generate and sign attestations:
   ```bash
   cosign attest --yes --predicate sbom.cdx.json --type cyclonedx "$IMAGE@$DIGEST"
   cosign attest --yes --predicate provenance.json --type slsaprovenance "$IMAGE@$DIGEST"
   ```
3. **In the deliver job**, verify everything you'll deploy:
   ```bash
   cosign verify --certificate-identity-regexp ".*@example.com" \
                 --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                 "$IMAGE@$DIGEST" > sig.json
   cosign verify-attestation --type cyclonedx \
                 --certificate-identity-regexp ".*@example.com" \
                 --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                 "$IMAGE@$DIGEST" > att-sbom.json
   cosign verify-attestation --type slsaprovenance \
                 --certificate-identity-regexp ".*@example.com" \
                 --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                 "$IMAGE@$DIGEST" > att-slsa.json
   ```
4. Normalize results into the platform's expected bundle shape (see below) and POST.

### Expected bundle shape

The platform does **NOT** parse raw `cosign verify` JSON. It expects a normalized bundle:

```json
{
  "verifications": [
    {
      "subject": "ghcr.io/jccompany/payment-api@sha256:abc123...",
      "type": "image-signature",
      "verified": true,
      "issuer": "https://token.actions.githubusercontent.com",
      "subject_identity": "https://github.com/jccompany/payment-api/.github/workflows/release.yml@refs/tags/v1.2.3",
      "digest": "sha256:abc123..."
    },
    {
      "subject": "ghcr.io/jccompany/payment-api@sha256:abc123...",
      "type": "attestation",
      "attestation_type": "cyclonedx",
      "verified": true
    },
    {
      "subject": "ghcr.io/jccompany/payment-api@sha256:abc123...",
      "type": "attestation",
      "attestation_type": "slsaprovenance",
      "verified": true
    }
  ]
}
```

**Field rules:**

| Field | Required | Notes |
| --- | --- | --- |
| `subject` | yes | Image or artifact reference, ideally pinned to digest |
| `type` | yes | `"image-signature"` or `"attestation"` |
| `attestation_type` | when type=attestation | `"cyclonedx"`, `"slsaprovenance"`, `"spdx"`, etc. |
| `verified` | yes | Boolean. `true` = control satisfied, `false` = high-severity finding |
| `error` | when verified=false | Human-readable reason — gets surfaced into the SAR / POA&M |
| `issuer`, `subject_identity`, `digest` | optional | Metadata for the audit trail |

A bundle with **all `verified: true`** produces zero findings → the cosign-mapped controls flip to `satisfied`. **One `verified: false`** produces a high-severity finding tagged with rule id `cosign.signature.missing` or `cosign.attestation.missing`.

### Bash → bundle conversion sketch

```bash
jq -n \
  --arg subj "$IMAGE@$DIGEST" \
  --argjson sig "$(jq 'length > 0' sig.json)" \
  --argjson sbom "$(jq 'length > 0' att-sbom.json)" \
  --argjson slsa "$(jq 'length > 0' att-slsa.json)" \
  '{verifications: [
     {subject: $subj, type: "image-signature", verified: $sig},
     {subject: $subj, type: "attestation", attestation_type: "cyclonedx",     verified: $sbom},
     {subject: $subj, type: "attestation", attestation_type: "slsaprovenance", verified: $slsa}
  ]}' > cosign-bundle.json
```

For failures, set `verified: false` and fill `error` with `cosign`'s stderr.

---

## Bundle #2 — opa-admission

### What the CI must do

You have two collection paths — pick whichever fits your cluster:

**Option A: Pre-deploy dry-run (preferred for blocking)**

```bash
# Capture admission decisions WITHOUT actually deploying
kubectl apply --dry-run=server -f manifests/ 2> admission-stderr.log || true
# Parse blocked admissions from stderr into structured violations
```

**Option B: Post-apply audit feed (always available, non-blocking)**

For Gatekeeper:
```bash
kubectl get constraints -A -o json | \
  jq '[.items[] | select(.status.violations) | .status.violations[]
       | {policy: .kind, engine: "gatekeeper", message, resource: (.kind+"/"+.name), namespace}]' \
  > gatekeeper-violations.json
```

For Kyverno:
```bash
kubectl get policyreport -A -o json | \
  jq '[.items[].results[] | select(.result == "fail")
       | {policy: .policy, engine: "kyverno", message, severity: .severity,
          resource: (.resources[0].kind + "/" + .resources[0].name),
          namespace: .resources[0].namespace}]' \
  > kyverno-violations.json
```

### Expected bundle shape

```json
{
  "violations": [
    {
      "policy": "K8sRequireImageSignature",
      "engine": "gatekeeper",
      "severity": "critical",
      "resource": "Deployment/payment-api",
      "namespace": "prod",
      "message": "image ghcr.io/jccompany/payment-api:v1.2.3 does not have a verified Sigstore signature"
    },
    {
      "policy": "disallow-host-namespace",
      "engine": "kyverno",
      "severity": "high",
      "resource": "Pod/web-7d9c",
      "namespace": "prod",
      "message": "spec.hostNetwork is set to true"
    }
  ]
}
```

**Field rules:**

| Field | Required | Notes |
| --- | --- | --- |
| `policy` | yes | Constraint name (Gatekeeper) or Policy name (Kyverno) |
| `engine` | yes | `"gatekeeper"`, `"kyverno"`, `"kyverno-policyreport"` |
| `message` | yes | Human-readable violation text |
| `severity` | optional | `critical` / `high` / `medium` / `low` — defaults to `high` if omitted |
| `resource` | optional | `Kind/Name` of the offending object |
| `namespace` | optional | k8s namespace |
| `rule_id` | optional | Override for the platform-side rule id (defaults to `policy`) |

**Empty `violations: []` is the success case** — it credits `opa-admission` in the submitted-scanners set and flips its mapped controls to `satisfied`. Do NOT skip the POST when there are zero violations; the platform needs the empty bundle as positive evidence the check ran.

---

## How to POST

Both bundles go to the same endpoint that the rest of your deliver job already calls. Just add them to the `results` array:

```bash
curl -X POST "$RISK_PLATFORM_URL/v1/products/payment-api/assess" \
  -H "X-API-Key: $RISK_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @- <<EOF
{
  "trigger": "pre_deploy",
  "phase": "DELIVER",
  "async_mode": true,
  "commit": "$GITHUB_SHA",
  "evidence_url": "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID",
  "results": [
    {"scanner": "cosign",        "content": $(cat cosign-bundle.json)},
    {"scanner": "opa-admission", "content": $(cat opa-admission-bundle.json)}
  ]
}
EOF
```

**Key request fields:**

- `"phase": "DELIVER"` — this labels the assessment under the deliver phase on the dashboard
- `"trigger": "pre_deploy"` — semantic trigger, also drives POA&M deadline math
- `"async_mode": true` — required when Bedrock is enabled on the platform (it is, in production)

The response is `202 Accepted` with a `job_id`; poll `/v1/jobs/{job_id}` if you want to fail the CI step on a BLOCK gate. If you just want the dashboard updated and don't need the deliver job to block, fire-and-forget is fine.

---

## Recognised aliases

These all collapse to the canonical scanner names so you can be more readable:

| Submit as | Routes to |
| --- | --- |
| `cosign`, `cosign-verify`, `cosign-attestation`, `sigstore` | `cosign` |
| `opa-admission`, `gatekeeper`, `kyverno`, `admission-policy` | `opa-admission` |

---

## What "good" looks like after integration

| Phase | Coverage target after this change |
| --- | --- |
| BUILD | unchanged (~90%+) |
| TEST | unchanged |
| RELEASE | unchanged (~92%) |
| **DELIVER** | **~70-90%** ← the goal |
| DEPLOY | unchanged (limited automation today) |

A few deliver-time controls remain not-assessed by design — true process controls like quarterly CISO review. Those are expected to stay manual and are NOT in scope for this integration.

---

## Failure modes to test

Before you ship this to prod, prove the negative path works:

1. **Push an unsigned image** to a staging registry → cosign bundle should report `verified: false` → SAR should mark the supply-chain controls as `other-than-satisfied`, POA&M item created, gate flips to BLOCK on a strict profile.
2. **Apply a manifest that violates a constraint** (e.g. privileged pod) → opa-admission bundle should report a violation → same flow.
3. **Send zero violations / all-verified** → platform should mark the relevant controls as `satisfied` and bump coverage.

If any of these don't behave as described, the bug is on the platform side — flag it back to me (ai-risk-platform repo).

---

## Reference — platform-side commit

These adapters were added in `ai-risk-platform` Phase A. The relevant code lives at:

- `orchestrator/scanners/cosign.py` — bundle parser
- `orchestrator/scanners/opa_admission.py` — bundle parser
- `orchestrator/server/app.py:_SCANNER_ALIASES` — name aliases
- `orchestrator/server/app.py:_parse_inline` — routing
- `orchestrator/server/models.py:_scanner_allowed` — input validation
- `orchestrator/rmf/poam.py:_SCAN_TYPE / _SCANNER_CONTROL_MAP / _SCANNER_FRAMEWORK_MAP` — POA&M metadata
- `controls/baselines/{soc2-2017, iso27001, pci-dss-4.0}.yaml` — control → scanner mappings

If you need a new alias added (e.g. you're using `slsa-verifier` or `kyverno-cli` natively), open an issue against `ai-risk-platform` with a sample bundle and I'll wire it up.
