package gates

deny[msg] {
    input.context.tier == "critical"
    some i
    input.findings[i].source == "checkov"
    input.findings[i].rule_id == "CKV_AWS_24"
    msg := sprintf("Network segmentation violation: %s at %s (PCI-DSS-1.3.1)", [input.findings[i].rule_id, input.findings[i].file])
}
