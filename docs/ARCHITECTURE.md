# 아키텍처

## Core Thesis
> Compliance가 프로세스를 결정한다. AI가 컨텍스트를 해석한다. 오픈소스 도구가 실행한다.

## 내부 방법론: NIST RMF
플랫폼은 내부적으로 NIST RMF (SP 800-37 Rev 2) 라이프사이클을 따른다.
사용자에게는 프레임워크 선택 인터페이스만 노출한다.

```
RMF Step 1 (Prepare)    → risk-profile.yaml, product-manifest.yaml
RMF Step 2 (Categorize) → Risk Assessment Engine (design-time)
RMF Step 3 (Select)     → Controls Repository baseline lookup
RMF Step 4 (Implement)  → Pipeline configuration (which scanners, which policies)
RMF Step 5 (Assess)     → Scanner execution + AI risk scoring
RMF Step 6 (Authorize)  → YAML threshold + OPA gate + AI narrative
RMF Step 7 (Monitor)    → Sigma detection + polling + re-assessment
```

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│  Cross-cutting: Compliance Control Plane                     │
│  Controls Repository (OSCAL YAML) + Risk Assessment Engine   │
│  Control ID traces through every phase                       │
└─────────────────────────────────────────────────────────────┘
        ↕               ↕               ↕               ↕
  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
  │  Plan    │ →  │ Develop  │ →  │  Build   │ →  │  Test    │
  │          │    │ & Build  │    │ Artifact │    │          │
  │ Risk     │    │ Semgrep  │    │ Grype    │    │ Gate     │
  │ Assess   │    │ Gitleaks │    │ SBOM     │    │ Decision │
  │ Baseline │    │ Checkov  │    │          │    │          │
  │ Select   │    │          │    │          │    │          │
  └──────────┘    └──────────┘    └──────────┘    └──────────┘
        ↕               ↕               ↕               ↕
  ┌──────────┐    ┌──────────────────────────────────────────┐
  │ Operate  │    │              Monitor                      │
  │          │    │  Sigma Engine · Polling · Re-assessment    │
  └──────────┘    └──────────────────────────────────────────┘
```

## 데이터 흐름

### Gate Path (100% 로컬, 외부 서비스 무의존)
```
Scanner CLI (Checkov, Semgrep, Grype, Gitleaks)
  → Findings (JSON)
    → YAML Threshold Evaluator → pass/fail
    → OPA/Rego (MVP tier) → pass/fail
    → Gate Decision: PASS or BLOCKED (with specific reason)
```

### Evidence Path (네트워크, recoverable)
```
Findings
  → JSONL append (always, local file)
  → DefectDojo API (MVP tier, if available)
  → AI Narrative (if Bedrock configured)
  → Evidence Export (on demand, generated artifact)
```

## 디렉토리 구조
```
compliance-ai-risk-platform/
├── CLAUDE.md
├── AGENTS.md
├── Makefile
├── .env.example
├── .github/workflows/ci.yml
├── docs/
│   ├── PRD.md
│   ├── ARCHITECTURE.md
│   ├── ADR.md
│   └── architecture-design.md        # Full design document
├── controls/                          ← OSCAL YAML (핵심 폴더)
│   ├── baselines/
│   │   ├── pci-dss-4.0.yaml          # 6 controls (Sec 1, 3, 6, 10)
│   │   ├── asvs-5.0-L3.yaml          # 4 controls (V2, V3, V5, V14)
│   │   └── fisc-safety.yaml          # 3 controls
│   ├── products/
│   │   └── payment-api/
│   │       ├── product-manifest.yaml
│   │       ├── risk-profile.yaml
│   │       └── risk-assessments/
│   └── tier-mappings.yaml
├── orchestrator/                      ← Python ~2,000 LOC (MVP-0)
│   ├── __main__.py                    # CLI entry point
│   ├── cli.py                         # CLI commands (init, assess, export, demo)
│   ├── assessor/
│   │   ├── interface.py               # RiskAssessor protocol
│   │   ├── static.py                  # StaticRiskAssessor
│   │   ├── bedrock.py                 # BedrockRiskAssessor
│   │   ├── bedrock_client.py          # boto3 wrapper
│   │   └── prompts.py                 # Prompt templates
│   ├── scanners/
│   │   ├── base.py                    # Scanner protocol
│   │   ├── checkov.py
│   │   ├── semgrep.py
│   │   ├── grype.py
│   │   ├── gitleaks.py
│   │   ├── control_mapper.py          # Rule → Control ID mapping
│   │   └── runner.py                  # ScannerRunner (log-and-continue)
│   ├── gate/
│   │   └── threshold.py               # YAML threshold evaluator
│   ├── controls/
│   │   ├── models.py                  # Control, VerificationMethod
│   │   ├── repository.py              # Controls YAML loader
│   │   └── baseline.py                # Tier → baseline selection
│   ├── evidence/
│   │   ├── jsonl.py                   # JSONL writer
│   │   └── export.py                  # Evidence report generator
│   ├── sigma/
│   │   ├── models.py                  # SigmaRule, SigmaMatch
│   │   └── engine.py                  # Python Sigma matcher (144 LOC)
│   ├── config/
│   │   ├── manifest.py                # Product manifest parser
│   │   ├── profile.py                 # Risk profile parser
│   │   └── schemas/                   # JSON Schema files
│   ├── demo.py                        # E2E demo runner
│   └── scoring/
│       └── risk.py                    # Likelihood × Impact calculation
├── sigma/
│   └── rules/                         ← Sigma detection rules (3-5)
├── rego/                              ← OPA policies (MVP tier)
│   └── gates/
├── tests/
│   ├── unit/
│   ├── contract/
│   └── conftest.py
├── output/                            ← Generated (gitignored)
│   ├── findings.jsonl
│   └── evidence/
└── scripts/
    ├── execute.py                     # Harness executor (existing)
    ├── test_execute.py                # Harness tests (existing)
    └── ensure-initialized.sh          # Docker auto-init
```

## 패턴

### Strategy Pattern — AI 통합
```python
class RiskAssessor(Protocol):
    def categorize(self, manifest: ProductManifest) -> RiskTier: ...
    def assess(self, findings: list[Finding], context: AssessmentContext) -> RiskReport: ...

class StaticRiskAssessor:    # 룩업 테이블 기반, AI 불필요
class BedrockRiskAssessor:   # Claude Sonnet API 호출
```

### Finding → Control ID 태깅
모든 scanner output은 Control ID로 태깅된다:
```python
Finding(
    source="semgrep",
    rule_id="python.django.security.injection.sql-injection",
    severity="high",
    file="src/api/export.py",
    line=42,
    control_ids=["PCI-DSS-6.3.1", "ASVS-V5.3.4"],  # ← 핵심
    product="payment-api"
)
```

### Gate 결정 흐름
```
Findings → YAML Threshold Check
             │
             ├── critical_findings > 0 in PCI scope? → BLOCK
             ├── secrets_detected > 0? → BLOCK
             ├── high_findings > threshold? → BLOCK
             └── all pass? → PROCEED
```

## 상태 관리
- **Stateless orchestrator** — 모든 상태는 파일에 저장
- Findings: JSONL (로컬 파일)
- Risk assessments: YAML (git 추적)
- Controls: YAML (git 추적)
- Configuration: YAML (git 추적)
- DefectDojo: PostgreSQL (Docker volume, MVP tier)

## 모델 선택 (Bedrock)
| 작업 | 모델 | 이유 |
|------|------|------|
| Risk assessment reasoning | Claude Sonnet 4.6 | Cross-signal reasoning 필요 |
| Finding explanation | Claude Sonnet 4.6 | 도메인 지식 필요 |
| Signal filtering (MVP tier) | Claude Haiku 4.5 | 빠르고 저렴한 요약 |
| No AI mode | — | StaticRiskAssessor 사용 |

## MVP-0 → MVP 확장 경로
```
MVP-0 (먼저 구현)              MVP (레이어 추가)
─────────────────              ──────────────────
4 scanners                     + CodeQL, ZAP, cdxgen
YAML threshold gate            + OPA/Rego policies
JSONL only                     + DefectDojo + reconciliation
Single Sonnet call             + Haiku→Sonnet two-stage
Log and continue               + Failure policy + override
JSON export                    + Markdown export
CLI questionnaire init         + AI-assisted init
```
