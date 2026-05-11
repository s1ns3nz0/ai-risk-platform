package gates

deny[msg] {
    input.context.tier == "critical"
    input.context.findings_count.high > 5
    msg := sprintf("High severity findings (%d) exceed threshold for critical tier (max: 5)", [input.context.findings_count.high])
}

deny[msg] {
    input.context.tier == "high"
    input.context.findings_count.high > 10
    msg := sprintf("High severity findings (%d) exceed threshold for high tier (max: 10)", [input.context.findings_count.high])
}
