"""Tests for the kube-bench / cis-java CIS-text parser."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from orchestrator.parsers.cis_text import parse_cis_text

KUBE_BENCH_OUTPUT = """\
[INFO] 4 Worker Node Security Configuration
[INFO] 4.1 Worker Node Configuration Files
[PASS] 4.1.1 Ensure that the kubelet service file permissions are set to 600 or more restrictive
[PASS] 4.1.2 Ensure that the kubelet service file ownership is set to root:root
[FAIL] 4.1.3 Ensure that the proxy kubeconfig file permissions are set to 600 or more restrictive
[PASS] 4.1.4 Ensure that the proxy kubeconfig file ownership is set to root:root
[WARN] 4.1.5 Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root

== Summary node ==
18 checks PASS
1 checks FAIL
5 checks WARN
0 checks INFO

== Summary total ==
42 checks PASS
11 checks FAIL
12 checks WARN
1 checks INFO
"""


CIS_JAVA_OUTPUT = """\
=== CIS Java Runtime Environment Benchmark ===
[PASS] 1.1 java.security exists at /opt/java/openjdk/conf/security/java.security
[PASS] 1.2 TLS 1.0/1.1 disabled: jdk.tls.disabledAlgorithms includes TLSv1, TLSv1.1
[FAIL] 1.3 SHA-1 disabled: SHA1 NOT in jdk.certpath.disabledAlgorithms
[PASS] 1.4 Unlimited crypto policy: crypto.policy=unlimited
[PASS] 2.1 Default HTTPS protocol: jdk.tls.client.protocols=TLSv1.2,TLSv1.3

=== Summary ===
PASS: 4
FAIL: 1
"""


@pytest.fixture
def mapper() -> MagicMock:
    m = MagicMock()
    m.map_finding.return_value = []  # force fallback to scanner default controls
    return m


class TestKubeBench:
    def test_only_fail_and_warn_become_findings(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        # 1 FAIL + 1 WARN; PASS and INFO must not generate findings.
        assert len(findings) == 2
        sources = {f.source for f in findings}
        assert sources == {"kube-bench"}

    def test_fail_is_high_severity(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        fails = [f for f in findings if f.rule_id == "4.1.3"]
        assert len(fails) == 1
        assert fails[0].severity == "high"

    def test_warn_is_medium_severity(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        warns = [f for f in findings if f.rule_id == "4.1.5"]
        assert len(warns) == 1
        assert warns[0].severity == "medium"

    def test_rule_id_extracted(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        ids = {f.rule_id for f in findings}
        assert ids == {"4.1.3", "4.1.5"}

    def test_message_includes_status_and_description(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        msg = next(f.message for f in findings if f.rule_id == "4.1.3")
        assert "[FAIL]" in msg
        assert "proxy kubeconfig" in msg

    def test_control_fallback_applied(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        for f in findings:
            assert f.control_ids == ["CM-6", "SI-7"]

    def test_summary_block_does_not_produce_findings(self, mapper: MagicMock) -> None:
        # The summary blocks contain "11 checks FAIL" — make sure that doesn't
        # leak into findings as a phantom rule.
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        for f in findings:
            assert "checks" not in f.rule_id.lower()


class TestCisJava:
    def test_only_fail_becomes_finding(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(CIS_JAVA_OUTPUT, "cis-java", mapper)
        assert len(findings) == 1
        assert findings[0].rule_id == "1.3"
        assert findings[0].source == "cis-java"

    def test_fail_is_medium_severity(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(CIS_JAVA_OUTPUT, "cis-java", mapper)
        assert findings[0].severity == "medium"

    def test_control_fallback_applied(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(CIS_JAVA_OUTPUT, "cis-java", mapper)
        assert findings[0].control_ids == ["CM-6", "SC-13"]


class TestEdgeCases:
    def test_unknown_scanner_returns_empty(self, mapper: MagicMock) -> None:
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "bogus-scanner", mapper)
        assert findings == []

    def test_empty_input(self, mapper: MagicMock) -> None:
        assert parse_cis_text("", "kube-bench", mapper) == []

    def test_only_passes(self, mapper: MagicMock) -> None:
        text = "[PASS] 1.1 ok\n[PASS] 1.2 also ok\n"
        assert parse_cis_text(text, "kube-bench", mapper) == []

    def test_mapper_lookup_wins_over_fallback(self, mapper: MagicMock) -> None:
        mapper.map_finding.return_value = ["AC-3"]
        findings = parse_cis_text(KUBE_BENCH_OUTPUT, "kube-bench", mapper)
        for f in findings:
            assert f.control_ids == ["AC-3"]
