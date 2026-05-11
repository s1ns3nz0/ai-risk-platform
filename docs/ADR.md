# Architecture Decision Records

## 철학
Compliance가 프로세스를 결정한다. MVP-0 우선 구현. 복잡성은 검증된 이후에만 추가한다.

---

### ADR-001: NIST RMF를 내부 방법론으로 채택
**결정**: NIST RMF (SP 800-37 Rev 2)를 리스크 평가의 내부 방법론으로 사용. 외부에는 프레임워크 선택 인터페이스만 노출.
**이유**: RMF의 7단계 라이프사이클이 DevSecOps 파이프라인과 자연스럽게 매핑됨. 타겟 역할(Binance, PayPay, Money Forward)은 미국 연방기관이 아니므로 RMF 자체를 브랜딩하지 않음.
**트레이드오프**: 사용자가 RMF를 인식하지 못하므로 방법론의 학술적 근거가 덜 드러남.

### ADR-002: Orchestrator-centric 아키텍처 (MCP/Bedrock Agent 제거)
**결정**: MCP 서버와 Bedrock Agent를 사용하지 않음. Python orchestrator가 REST API를 직접 호출하고 Bedrock InvokeModel API로 AI를 호출.
**이유**: Orchestrator가 신호를 수집하면 MCP 서버는 불필요한 중간 레이어. 테스트 용이성, 복잡성 감소, 의존성 제거.
**트레이드오프**: Bedrock Agent의 자율적 tool 선택 기능을 포기. AI가 볼 수 있는 데이터를 orchestrator가 결정.

### ADR-003: Gate path는 100% 로컬
**결정**: Gate 결정(PASS/FAIL)은 로컬 CLI 도구 + YAML threshold 평가만으로 수행. DefectDojo, DT, Bedrock이 없어도 gate가 동작.
**이유**: DevSecOps에서 보안 도구의 장애가 개발을 멈추면 안 됨. 반대로 스캔 없이 배포하면 컴플라이언스 위반. Gate를 로컬로 분리하면 두 문제를 모두 해결.
**트레이드오프**: Evidence path (DefectDojo sync, AI narrative)가 실패해도 gate는 통과할 수 있음 — 증적 기록에 일시적 gap 발생 가능.

### ADR-004: AI는 gate하지 않는다
**결정**: AI의 gate_recommendation은 advisory only. 실제 차단은 YAML threshold + OPA/Rego가 수행.
**이유**: 규제 감사에서 "왜 이 PR이 차단되었나?"에 대한 답은 사람이 읽을 수 있는 정책 참조여야 한다. AI inference가 아니라. PCI DSS, FISC 감사 생존을 위한 핵심 설계 제약.
**트레이드오프**: AI가 높은 리스크를 감지해도 정책 위반이 아니면 차단할 수 없음. Social gate (PR comment)로만 작용.

### ADR-005: Grype가 SCA gate, Dependency-Track은 enrichment만
**결정**: SCA gate 결정은 Grype (로컬 CLI)가 수행. Dependency-Track은 EPSS, VEX, 정책 엔진으로 evidence를 보강하지만 gate하지 않음.
**이유**: Gate path의 100% 로컬 원칙 유지. DT가 다운되어도 SCA gate는 동작. Grype와 DT의 취약점 DB 차이는 존재하지만, gate 일관성이 더 중요.
**트레이드오프**: DT의 더 정교한 정책 엔진이 gate 결정에 참여하지 못함. Grype가 놓치는 취약점은 DT enrichment에서만 발견 가능.

### ADR-006: MVP-0 → MVP 레이어링 전략
**결정**: MVP-0 (4 scanners, single AI call, JSONL, ~2,000 LOC)를 먼저 구현. MVP는 그 위에 레이어.
**이유**: Red Team Round 4에서 48개 컴포넌트의 복잡성 발견. Correct한 결정들의 합이 unbuildable한 시스템을 만들 수 있음. MVP-0는 core thesis를 증명하는 최소 구현.
**트레이드오프**: MVP-0는 DefectDojo, OPA, CodeQL, ZAP, failure policy가 없어 production-ready가 아님. 하지만 아키텍처를 이해하고 확장하기 충분.

### ADR-007: Custom Python Sigma Engine
**결정**: Wazuh, chainsaw, sigma-cli 대신 custom Python Sigma matcher (~150 LOC)를 구현.
**이유**: 3-5개 규칙만 필요. Full SIEM은 과잉. chainsaw는 Windows EVTX 전용. sigma-cli는 변환 도구이지 실행 엔진이 아님. Custom engine은 포트폴리오 가치 + Python-only 의존성.
**트레이드오프**: Full Sigma specification을 지원하지 않음 (aggregation, near operator 등). 기본 field matching만 가능.

### ADR-008: Evidence는 Generated Artifact (DB 없음)
**결정**: SQLite나 별도 DB 없이, evidence report는 DefectDojo API + Controls Repository에서 실시간 생성하는 artifact. MVP-0에서는 JSONL에서 직접 생성.
**이유**: 두 개의 DB를 동기화하는 복잡성 제거. DefectDojo가 source of truth, JSONL이 백업. Evidence는 point-in-time snapshot이면 충분.
**트레이드오프**: Historical trend 분석이 어려움. 매번 생성하므로 대량 finding 시 느릴 수 있음.

### ADR-009: SBOM 생성에 Syft 선택 + Grype로 SBOM 스캔
**결정**: Syft로 CycloneDX JSON SBOM을 생성하고, Grype가 SBOM을 스캔하여 취약점을 탐지. 컨테이너 이미지 스캔도 Grype로 수행. SBOM 생성 자체를 PCI-DSS-6.3.2 컨트롤의 evidence로 기록.
**이유**: Syft와 Grype는 동일 조직(Anchore)이 유지보수하여 호환성이 높음. cdxgen 대비 Syft는 컨테이너 이미지 SBOM도 지원. 별도 SCA 도구를 추가하지 않고 Grype 하나로 directory/SBOM/container 세 가지 스캔 모드를 통합.
**트레이드오프**: cdxgen이 더 많은 언어 에코시스템을 지원. Dependency-Track의 정책 엔진(EPSS, VEX)을 활용하지 못함 — MVP tier에서 추가 예정.

### ADR-010: Failure Policy — Tier-Based Scan Failure Handling
**결정**: Scanner 실패 시 tier별 정책 적용. Critical/High는 fail-closed + override 가능. Medium/Low는 warn-and-proceed.
**이유**: 보안 도구 장애가 개발을 멈추면 안 되지만, 스캔 없이 배포하면 컴플라이언스 위반. Tier별 정책으로 두 문제를 모두 해결.
**트레이드오프**: Override 메커니즘이 남용될 수 있음. Demo 모드에서는 --force-override로 제한. Production에서는 GitHub PR review 통합 필요.

### ADR-011: Component-Based Threat Modeling with EPSS
**결정**: SBOM 컴포넌트 + EPSS enriched CVEs + product manifest를 기반으로 위협 모델 자동 생성. Static mode (template 기반) 먼저 구현, AI mode는 이후 추가.
**이유**: 위협 모델이 실제 애플리케이션 컴포넌트에 기반하면 추상적인 위협 목록이 아닌 구체적인 공격 시나리오를 도출할 수 있음. EPSS로 실제 exploit 가능성을 반영.
**트레이드오프**: Static mode는 template 기반이므로 컨텍스트 깊이가 제한적. AI mode 추가 시 Bedrock 비용 발생.

### ADR-012: Framework Import from OSCAL + Keyword-Based Scanner Suggestion
**결정**: NIST OSCAL JSON catalog에서 컨트롤을 자동 import하고, 키워드 매칭으로 scanner mapping을 제안. 제안은 인간이 반드시 검토 후 승인.
**이유**: 새 프레임워크 추가 시 110+ 컨트롤을 수동으로 YAML에 작성하는 것은 비현실적. OSCAL import + keyword suggestion으로 초기 작업의 70%를 자동화하면서, 정확성은 인간 검토로 보장.
**트레이드오프**: 키워드 매칭은 30% 정도의 컨트롤에 대해 제안을 못함 (물리적 보안, 인적 절차 등 자동화 불가 영역). 이런 컨트롤은 verification_methods: []로 남겨져 수동 매핑 또는 "not-automatable" 표시 필요.

### ADR-013: Full NIST RMF Assessment with SP 800-30 + SAR + POA&M
**결정**: SP 800-30 4-phase risk assessment + SAR + POA&M + Authorization decision을 단일 `risk-assess` 명령으로 통합. AI (Bedrock Sonnet)는 Phase 2 (Conduct)에서 threat/vulnerability/likelihood/impact 분석을 수행하고, Phase 3 (Communicate)에서 보고서를 생성. SAR/POA&M/Authorization은 deterministic.
**이유**: RMF는 risk assessment만이 아니라 assessment 후 활동 (SAR, POA&M, ATO decision)까지 포함해야 완전한 프로세스. SP 800-30의 4-phase를 따르면 감사인이 방법론을 추적할 수 있음.
**트레이드오프**: Full SP 800-30 보고서는 길고 복잡함. 대부분의 개발자는 요약만 필요. executive_summary를 제공하되 전체 보고서도 export.
