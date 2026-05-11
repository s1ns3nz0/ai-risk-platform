package gates

deny[msg] {
    input.context.secrets_count > 0
    msg := sprintf("Secrets detected: %d findings from gitleaks", [input.context.secrets_count])
}
