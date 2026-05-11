package gates

deny[msg] {
    input.context.tier == "critical"
    some i
    input.findings[i].severity == "critical"
    some j
    startswith(input.findings[i].control_ids[j], "PCI-DSS")
    msg := sprintf("Critical finding in PCI scope: %s (control: %s)", [input.findings[i].rule_id, input.findings[i].control_ids[j]])
}
