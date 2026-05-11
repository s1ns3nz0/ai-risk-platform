# PRD: Compliance-Driven AI Risk Platform

## 목표
컴플라이언스 프레임워크를 single source of truth로 취급하여 DevSecOps 활동을 결정하고, AI가 scanner 결과를 cross-signal reasoning으로 해석하는 오픈소스 참조 구현체를 만든다.

## 사용자
1. **Security Engineer** — AI-driven DevSecOps 플랫폼을 자체 구축하려는 보안 엔지니어
2. **Platform Engineer** — 규제 환경(핀테크)에서 CI/CD 보안을 자동화하려는 플랫폼 엔지니어
3. **Auditor** — 컨트롤 ID로 증적 체인을 추적하려는 감사인

## 핵심 가치 제안
> Compliance가 프로세스를 결정한다. AI가 컨텍스트를 해석한다. 오픈소스 도구가 실행한다.

기존 ASPM 도구와 차별점:
- Scanner output first가 아니라 **Framework first** — 컨트롤이 어떤 검증 활동을 수행할지 결정
- Control ID가 모든 계층을 관통하는 **primary key** — 단일 쿼리로 감사 증적 생성
- AI는 gate가 아니라 **translator** — 차단 결정은 deterministic rule engine이 수행
- Bedrock 없이도 동작, Bedrock이 있으면 **10x 강화**

## 핵심 기능

### MVP-0 (먼저 구현, ~2,000 LOC)
1. **Risk Assessment Engine** — 제품 카테고리화 + 리스크 스코어링 (RMF Step 2, 5)
2. **Controls Repository** — OSCAL YAML 기반 컨트롤 카탈로그, tier별 baseline 자동 선택 (13 controls: PCI-DSS 6, ASVS 4, FISC 3)
3. **IaC Policy Gate** — Checkov 스캔 + YAML threshold gate
4. **SAST Integration** — Semgrep 스캔, Control ID 태깅
5. **SCA Integration** — Grype 로컬 스캔, SBOM 기반 취약점 분석
6. **Secrets Scanning** — Gitleaks 통합
7. **Evidence Export** — JSONL 기반 findings → JSON 증적 보고서 생성
8. **Dual-mode AI** — StaticRiskAssessor (no AI) / BedrockRiskAssessor (Sonnet)
9. **orchestrator init** — CLI 질문 모드 + AI 지원 모드로 product-manifest/risk-profile 생성
10. **Detection Engine** — Python Sigma matcher (~150 LOC), 3-5 rules, JSON 로그 분석

### MVP (MVP-0 위에 레이어)
11. **CodeQL** — custom semantic query (hardcoded creds, negative payment, PII logging)
12. **DAST** — ZAP 통합
13. **Dependency-Track** — SCA 보강 (EPSS, VEX, policy engine)
14. **DefectDojo** — finding triage UI + evidence source of truth
15. **Two-stage AI** — Haiku 필터링 → Sonnet reasoning (selective summarization)
16. **OPA/Rego** — complex gate policies (additive with YAML thresholds)
17. **Failure Policy** — tier별 fail-closed/warn, override mechanism, retry, reconciliation
18. **Polling Watcher** — `orchestrator watch` for continuous monitoring triggers
19. **Markdown Evidence** — auditor-facing evidence pack export

## 리스크 평가 방법론
- **Core framework:** NIST RMF (SP 800-37 Rev 2) — 내부 방법론, 외부에 노출하지 않음
- **Threat taxonomy:** MITRE ATT&CK — 제품 onboarding 시 threat profile 생성
- **Risk scoring:** Likelihood × Impact (SP 800-30 aligned), factor별 evidence 기록
- **Risk criteria:** risk-profile.yaml에서 조직별 risk tolerance 정의

## AI의 역할 (Static YAML을 넘어서는 가치)
AI는 static YAML mapping이 할 수 없는 **cross-signal reasoning**을 수행:
1. **Contextual blast radius** — PR diff + 기존 findings + 제품 컨텍스트를 연결하여 리스크 판단
2. **VEX exploitability** — CVE + 코드베이스 분석으로 실제 도달 가능성 평가
3. **Semantic security review** — 패턴 매칭이 놓치는 논리적 보안 이슈 탐지 (예: 암호화 다운그레이드)

## Gate 설계
- Gate path는 100% 로컬 (scanner CLI → YAML threshold → pass/fail)
- Evidence path는 네트워크 (JSONL → DefectDojo → AI narrative)
- **AI는 절대 gate하지 않는다** — AI는 서술하고, OPA/YAML이 차단한다

## E2E 시나리오 (payment-api)
1. Design-time risk assessment → AI가 제품 카테고리화, risk tier 결정
2. Baseline selection → tier에 따라 PCI DSS + FISC + ASVS 컨트롤 자동 선택
3. IaC scan → Checkov가 Terraform 스캔, threshold gate 평가
4. SAST + SCA + Secrets → Semgrep + Grype + Gitleaks 실행, Control ID 태깅
5. Pre-merge assessment → 모든 findings 종합, risk score 계산, gate 결정
6. Runtime detection → Sigma rules가 실제 로그에서 공격 패턴 탐지, 재평가 트리거
7. Evidence export → Control ID로 증적 체인 조회, 보고서 생성

## MVP 제외 사항
- MCP 서버 (orchestrator가 REST API 직접 호출)
- Bedrock Agents (orchestrator가 InvokeModel API 직접 호출)
- Trivy, KICS (Checkov으로 충분)
- Wazuh (custom Python Sigma engine으로 대체)
- Backstage plugin (CLI only)
- SQLite evidence DB (evidence는 generated artifact)
- Local demo mode (Docker minimum)
- Background job scheduler
- D3FEND mapping (future scope)
- Multi-tenant, production hardening

## Sample App (별도 레포)
- Python FastAPI, 5 endpoints (health, login, payment create, payment confirm, export)
- 5 planted vulnerabilities: hardcoded AWS key, PII logging, negative payment, weak JWT (HS256), SQLi
- Terraform: S3 without encryption, overly-permissive IAM, public security group
- requirements.txt: known CVE versions (old cryptography, old requests)
- JSON structured logs + simulate-traffic.py
- 127.0.0.1 binding only
