"""Sample payment API application with intentional vulnerabilities.

This is a FIXTURE for demo/testing purposes only.
All credentials are fake and intentionally detectable by security scanners.
"""

import logging
import sqlite3

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

# Vulnerability: Hardcoded AWS access key (gitleaks detection)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# Vulnerability: Weak JWT secret (semgrep detection)
JWT_SECRET = "secret"

logger = logging.getLogger(__name__)


@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    # Vulnerability: PII logging (semgrep detection)
    logger.info(f"Login attempt for user: {username}, password: {password}")

    token = jwt.encode({"user": username}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.route("/api/payment", methods=["POST"])
def create_payment():
    amount = request.json.get("amount")
    user_id = request.json.get("user_id")

    # Vulnerability: SQL injection (semgrep detection)
    conn = sqlite3.connect("payments.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE id = '" + user_id + "'"  # noqa: S608
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"status": "created", "amount": amount})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
