"""Application configuration with intentional credential exposure.

This is a FIXTURE for demo/testing purposes only.
All credentials are fake and intentionally detectable by security scanners.
"""

# Vulnerability: Hardcoded AWS credentials (gitleaks detection)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DATABASE_URL = "postgresql://localhost:5432/payments"
