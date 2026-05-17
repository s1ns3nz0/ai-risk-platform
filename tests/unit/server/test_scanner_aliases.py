"""Scanner aliases + new scanners (trivy, hadolint, spotbugs, grype-image)."""

from __future__ import annotations


def _wrap(scanner: str, content):
    return {"results": [{"scanner": scanner, "content": content}], "async_mode": False}


# ---- Trivy native JSON ----

_TRIVY_SAMPLE = {
    "SchemaVersion": 2,
    "ArtifactName": "alpine:3.18",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.4)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-12345",
                    "PkgName": "libssl3",
                    "InstalledVersion": "3.0.10-r0",
                    "FixedVersion": "3.0.12-r0",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSL critical",
                    "Description": "Critical bug in libssl3",
                },
                {
                    "VulnerabilityID": "CVE-2024-55555",
                    "PkgName": "busybox",
                    "InstalledVersion": "1.36",
                    "FixedVersion": "",
                    "Severity": "LOW",
                    "Title": "busybox info leak",
                },
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "CauseMetadata": {"StartLine": 5},
                }
            ],
        },
    ],
}


def test_trivy_native_accepted_and_parsed(client):
    r = client.post("/v1/products/payment-api/assess", json=_wrap("trivy", _TRIVY_SAMPLE))
    assert r.status_code == 200, r.text
    body = r.json()
    # 2 vulns + 1 misconfig = 3 trivy findings.
    assert body["findings_count"] == 3


def test_trivy_autodetected_when_scanner_omitted(client):
    payload = {
        "results": [{"content": _TRIVY_SAMPLE}],  # no `scanner` field
        "async_mode": False,
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 3


def test_trivy_sarif_alias_routes_to_sarif(client):
    """trivy-sarif → sarif parser."""
    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "trivy", "rules": [{"id": "CVE-2024-1", "shortDescription": {"text": "v"}}]}},
                "results": [
                    {
                        "ruleId": "CVE-2024-1",
                        "level": "error",
                        "message": {"text": "vuln"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "alpine"}}}],
                    }
                ],
            }
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=_wrap("trivy-sarif", sarif_doc))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


# ---- Aliases for existing parsers ----


def test_grype_image_alias_routes_to_grype(client):
    grype_doc = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "High",
                    "description": "Critical lib bug",
                },
                "artifact": {"name": "libfoo", "version": "1.2.3", "locations": [{"path": "lib/foo"}]},
            }
        ],
        "descriptor": {"name": "grype", "version": "0.74.0"},
    }
    r = client.post("/v1/products/payment-api/assess", json=_wrap("grype-image", grype_doc))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


def test_hadolint_alias_routes_to_sarif(client):
    """Hadolint emits SARIF natively. Caller can use `hadolint` as a label."""
    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Hadolint",
                        "rules": [{"id": "DL3008", "shortDescription": {"text": "Pin apt versions"}}],
                    }
                },
                "results": [
                    {
                        "ruleId": "DL3008",
                        "level": "warning",
                        "message": {"text": "apt-get install needs pinned versions"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 10}}}
                        ],
                    }
                ],
            }
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=_wrap("hadolint", sarif_doc))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


def test_spotbugs_alias_routes_to_sarif(client):
    """Spotbugs SARIF plugin emits SARIF — same alias treatment."""
    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SpotBugs",
                        "rules": [{"id": "EI_EXPOSE_REP", "shortDescription": {"text": "Exposes internal rep"}}],
                    }
                },
                "results": [
                    {
                        "ruleId": "EI_EXPOSE_REP",
                        "level": "warning",
                        "message": {"text": "may expose internal state"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "Foo.java"}, "region": {"startLine": 33}}}
                        ],
                    }
                ],
            }
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=_wrap("spotbugs", sarif_doc))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


# ---- New aliases added in the red-team fix ----


def test_trivy_fs_alias_routes_to_trivy(client):
    r = client.post("/v1/products/payment-api/assess", json=_wrap("trivy-fs", _TRIVY_SAMPLE))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 3


def test_trivy_image_alias_routes_to_trivy(client):
    r = client.post("/v1/products/payment-api/assess", json=_wrap("trivy-image", _TRIVY_SAMPLE))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 3


def test_snyk_alias_routes_to_sarif(client):
    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Snyk", "rules": [{"id": "SNYK-JS-1", "shortDescription": {"text": "x"}}]}},
                "results": [
                    {
                        "ruleId": "SNYK-JS-1",
                        "level": "error",
                        "message": {"text": "dep vuln"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package.json"}}}],
                    }
                ],
            }
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=_wrap("snyk", sarif_doc))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


def test_bandit_alias_routes_to_sarif(client):
    sarif_doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit", "rules": [{"id": "B101", "shortDescription": {"text": "x"}}]}},
                "results": [
                    {
                        "ruleId": "B101",
                        "level": "warning",
                        "message": {"text": "assert used"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
                    }
                ],
            }
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=_wrap("bandit", sarif_doc))
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


# ---- Validation: truly unknown names still rejected ----


def test_unknown_scanner_still_rejected(client):
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_wrap("totally-made-up-scanner", _TRIVY_SAMPLE),
    )
    assert r.status_code == 422


# ---- T2 regression: gate must count Trivy secrets ----


def test_t2_trivy_secret_triggers_secrets_gate_block(client):
    """payment-api's risk-profile sets max_secrets_detected=0 in the critical
    tier. A Trivy-detected secret must be counted by the gate predicate."""
    trivy_secret_only = {
        "SchemaVersion": 2,
        "ArtifactName": ".env",
        "Results": [
            {
                "Target": ".env",
                "Class": "secret",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Severity": "CRITICAL",
                        "StartLine": 7,
                        "Title": "AWS Access Key ID",
                    }
                ],
            }
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=_wrap("trivy", trivy_secret_only))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings_count"] == 1
    assert body["gate"]["passed"] is False
    # T2 proof: the secrets-detected threshold fired with actual=1.
    secret_check = next(
        t for t in body["gate"]["threshold_results"]
        if t["name"] == "max_secrets_detected"
    )
    assert secret_check["actual"] == 1
    assert secret_check["passed"] is False
