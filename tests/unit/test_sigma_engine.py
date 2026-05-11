"""Tests for the custom Python Sigma engine."""

from __future__ import annotations

import os

import pytest

from orchestrator.sigma.engine import SigmaEngine
from orchestrator.sigma.models import SigmaMatch
from orchestrator.types import Finding

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "sigma", "rules")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample-logs")


@pytest.fixture
def engine() -> SigmaEngine:
    e = SigmaEngine(rules_dir=RULES_DIR)
    e.load_rules()
    return e


def test_load_rules(engine: SigmaEngine) -> None:
    """4개 rule YAML 로드 확인."""
    assert len(engine.rules) == 4
    ids = {r.id for r in engine.rules}
    assert ids == {"bf-001", "sqli-001", "exfil-001", "privesc-001"}


def test_match_brute_force(engine: SigmaEngine) -> None:
    """login_failed 이벤트 → brute_force rule 매칭."""
    entry = {"event_type": "login_failed", "username": "admin", "ip": "192.168.1.100"}
    matches = engine.evaluate(entry)
    assert len(matches) == 1
    assert matches[0].rule.id == "bf-001"


def test_match_sql_injection(engine: SigmaEngine) -> None:
    """SQL 키워드 포함 path → sql_injection rule 매칭."""
    entry = {"event_type": "api_request", "path": "/api/export?id=1 OR 1=1", "method": "GET"}
    matches = engine.evaluate(entry)
    assert len(matches) == 1
    assert matches[0].rule.id == "sqli-001"


def test_no_match_normal_request(engine: SigmaEngine) -> None:
    """정상 요청 → 매칭 없음."""
    entry = {"event_type": "api_request", "path": "/api/payment", "method": "POST", "status": 200}
    matches = engine.evaluate(entry)
    assert len(matches) == 0


def test_match_returns_sigma_match(engine: SigmaEngine) -> None:
    """SigmaMatch에 rule, log_entry, timestamp 포함."""
    entry = {"event_type": "login_failed", "username": "admin", "ip": "10.0.0.1"}
    matches = engine.evaluate(entry)
    assert len(matches) == 1
    m = matches[0]
    assert isinstance(m, SigmaMatch)
    assert m.rule.id == "bf-001"
    assert m.log_entry == entry
    assert m.matched_at  # ISO timestamp string


def test_evaluate_log_file(engine: SigmaEngine) -> None:
    """fixture 로그 파일 → 여러 매칭 결과."""
    log_path = os.path.join(LOGS_DIR, "access.jsonl")
    matches = engine.evaluate_log_file(log_path)
    # 2 login_failed (bf-001), 1 sqli (sqli-001), 1 data_export (exfil-001) = 4
    assert len(matches) == 4
    rule_ids = [m.rule.id for m in matches]
    assert rule_ids.count("bf-001") == 2
    assert rule_ids.count("sqli-001") == 1
    assert rule_ids.count("exfil-001") == 1


def test_rule_has_control_ids(engine: SigmaEngine) -> None:
    """매칭된 rule에 control_ids 포함."""
    entry = {"event_type": "login_failed", "username": "admin", "ip": "10.0.0.1"}
    matches = engine.evaluate(entry)
    assert matches[0].rule.control_ids == ["PCI-DSS-10.2.1", "FISC-実127"]


def test_rule_has_attack_tags(engine: SigmaEngine) -> None:
    """매칭된 rule에 ATT&CK tag 포함."""
    entry = {"event_type": "login_failed", "username": "admin", "ip": "10.0.0.1"}
    matches = engine.evaluate(entry)
    tags = matches[0].rule.tags
    assert "attack.t1110" in tags
    assert "attack.brute_force" in tags


def test_sigma_match_to_finding(engine: SigmaEngine) -> None:
    """SigmaMatch.to_finding()이 올바른 Finding 반환."""
    entry = {"event_type": "data_export", "username": "user1", "records_count": 50000}
    matches = engine.evaluate(entry)
    assert len(matches) == 1
    finding = matches[0].to_finding(product="payment-api")
    assert isinstance(finding, Finding)
    assert finding.source == "sigma"
    assert finding.rule_id == "exfil-001"
    assert finding.severity == "critical"
    assert finding.product == "payment-api"
    assert "PCI-DSS-10.2.1" in finding.control_ids


def test_contains_modifier(engine: SigmaEngine) -> None:
    """|contains 매칭 테스트."""
    # UNION SELECT should match
    entry = {"event_type": "api_request", "path": "/api?q=UNION SELECT * FROM users"}
    matches = engine.evaluate(entry)
    assert len(matches) == 1
    assert matches[0].rule.id == "sqli-001"

    # DROP TABLE should match
    entry2 = {"event_type": "api_request", "path": "/api?q=DROP TABLE users"}
    matches2 = engine.evaluate(entry2)
    assert len(matches2) == 1
    assert matches2[0].rule.id == "sqli-001"

    # Normal path should not match
    entry3 = {"event_type": "api_request", "path": "/api/normal"}
    matches3 = engine.evaluate(entry3)
    assert len(matches3) == 0
