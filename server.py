"""
server.py
---------
INTENTIONALLY VULNERABLE Flask server for SQL Injection testing.
DO NOT deploy this in any real environment.

Endpoint:  POST /api/v1/login
           Body (JSON): { "username": "...", "password": "..." }

Also accepts the Part D verification input format:
  POST /verify
  Body (JSON): {
    "target":                 "...",
    "finding":                "sql_injection",
    "parameter":              "username",
    "payloads":               ["...", ...],
    "baseline_response_hash": "..."
  }
"""

import sqlite3
import hashlib
import json
import time
import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "users.db"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def response_hash(data: dict) -> str:
    serialised = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialised.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerable Login Endpoint  (FIND-0042)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/v1/login", methods=["POST"])
def login():
    """
    VULNERABLE: username is injected directly into the SQL string.
    This is the endpoint under test for FIND-0042.
    """
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")

    conn = get_db()
    cursor = conn.cursor()

    # ── INTENTIONAL SQL INJECTION SINK ──────────────────────────────────────
    query = f"SELECT * FROM users WHERE username = '{username}'"
    # ────────────────────────────────────────────────────────────────────────

    t_start = time.time()
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        # Error-based injection: leak the exception message
        return jsonify({
            "status":  "error",
            "message": str(e),
            "query":   query          # intentional — simulates verbose error mode
        }), 500
    t_end = time.time()

    conn.close()

    if not rows:
        return jsonify({
            "status":       "fail",
            "message":      "Invalid credentials",
            "records_returned": 0
        }), 401

    # Return all matched rows (injection may return many)
    users_out = []
    for row in rows:
        users_out.append({
            "id":       row["id"],
            "username": row["username"],
            "email":    row["email"],
            "role":     row["role"],
            "ssn":      row["ssn"],
            "balance":  row["balance"],
        })

    return jsonify({
        "status":           "ok",
        "message":          "Login successful",
        "records_returned": len(users_out),
        "users":            users_out,
        "response_time_s":  round(t_end - t_start, 4)
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Safe Baseline Endpoint  (fixed version for comparison)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/v1/login/safe", methods=["POST"])
def login_safe():
    """Parameterised version — used to generate the baseline response hash."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        resp = {"status": "fail", "message": "Invalid credentials", "records_returned": 0}
        return jsonify(resp), 401

    if row["password"] != hash_password(password):
        resp = {"status": "fail", "message": "Invalid credentials", "records_returned": 0}
        return jsonify(resp), 401

    resp = {
        "status":           "ok",
        "message":          "Login successful",
        "records_returned": 1,
        "users":            [{"id": row["id"], "username": row["username"], "role": row["role"]}]
    }
    return jsonify(resp), 200


# ─────────────────────────────────────────────────────────────────────────────
# Second-Order Injection: register + trigger
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/v1/register", methods=["POST"])
def register():
    """Stores username as-is (no sanitisation). Used for TC-10 second-order test."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "test")
    email    = body.get("email", "test@test.com")

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (?,?,?)",
            (username, hash_password(password), email)
        )
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "fail", "message": "Username already exists"}), 409
    conn.close()
    return jsonify({"status": "ok", "user_id": user_id, "message": "Registered"}), 201


@app.route("/api/v1/lookup", methods=["POST"])
def lookup():
    """
    SECOND-ORDER SINK: fetches a stored username and injects it back into SQL.
    Used for TC-10.
    """
    body     = request.get_json(silent=True) or {}
    user_id  = body.get("user_id", 0)

    conn = get_db()
    cursor = conn.cursor()

    # Step 1: fetch stored username (safe read)
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "fail", "message": "User not found"}), 404

    stored_username = row["username"]

    # Step 2: VULNERABLE — stored value re-injected without parameterisation
    second_query = f"SELECT * FROM users WHERE username = '{stored_username}'"
    try:
        cursor.execute(second_query)
        results = [dict(r) for r in cursor.fetchall()]
    except sqlite3.OperationalError as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e), "query": second_query}), 500

    # Step 3: write to audit_log (stacked-query target)
    cursor.execute(
        "INSERT INTO audit_log (entry) VALUES (?)",
        (f"Lookup triggered for user_id={user_id}",)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "status":   "ok",
        "stored_username": stored_username,
        "second_query":    second_query,
        "records":  results
    }), 200


@app.route("/api/v1/audit-log", methods=["GET"])
def audit_log():
    """Read the audit_log table — used to verify stacked-query side effects."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"status": "ok", "entries": rows}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Part D — /verify  (accepts the exact JSON format from the brief)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])
def verify():
    """
    Accepts the Part D config block and runs each payload against
    /api/v1/login, returning a structured remediation report.

    Input JSON:
    {
        "target":                 "http://localhost:5000/api/v1/login",
        "finding":                "sql_injection",
        "parameter":              "username",
        "payloads":               ["' OR '1'='1", ...],
        "baseline_response_hash": "<sha256>"
    }
    """
    config  = request.get_json(silent=True) or {}
    payloads = config.get("payloads", [])
    parameter = config.get("parameter", "username")
    baseline_hash = config.get("baseline_response_hash", "")
    finding  = config.get("finding", "sql_injection")
    target   = config.get("target", "N/A")

    results = []
    failed  = 0

    for idx, payload in enumerate(payloads, start=1):
        tc_id = f"TC-{idx:02d}"
        body  = {parameter: payload, "password": "irrelevant"}

        t0 = time.time()
        try:
            conn = get_db()
            cursor = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{payload}'"
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
            status_code = 200 if rows else 401
            resp_body   = {
                "status":           "ok" if rows else "fail",
                "records_returned": len(rows),
                "users":            [dict(r) for r in rows]
            }
        except sqlite3.OperationalError as e:
            status_code = 500
            resp_body   = {"status": "error", "message": str(e)}
        elapsed = round(time.time() - t0, 4)

        r_hash     = response_hash(resp_body)
        hash_match = (r_hash == baseline_hash) if baseline_hash else None

        # Anomaly detection
        anomalies = []
        if elapsed > 4.0:
            anomalies.append(f"Timing anomaly ({elapsed}s > 4s threshold)")
        if status_code >= 500:
            anomalies.append(f"Server error (HTTP {status_code})")
        if resp_body.get("records_returned", 0) > 1:
            anomalies.append(f"Multiple records returned ({resp_body['records_returned']})")
        if hash_match is False:
            anomalies.append("Response hash mismatch")
        if resp_body.get("status") == "ok" and "OR" in payload.upper():
            anomalies.append("Auth bypass — login succeeded with injection payload")

        passed = len(anomalies) == 0
        if not passed:
            failed += 1

        results.append({
            "tc_id":       tc_id,
            "payload":     payload,
            "status_code": status_code,
            "elapsed_s":   elapsed,
            "hash_match":  hash_match,
            "anomalies":   anomalies,
            "result":      "PASS" if passed else "FAIL"
        })

    verdict = "REMEDIATION PASSED" if failed == 0 else "REMEDIATION FAILED"

    report = {
        "finding":    finding,
        "target":     target,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "test_cases": results,
        "summary": {
            "total":  len(results),
            "passed": len(results) - failed,
            "failed": failed,
            "verdict": verdict
        }
    }

    return jsonify(report), 200


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "db": os.path.exists(DB_PATH)}), 200


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print(f"[!] Database '{DB_PATH}' not found. Run 'python seed_db.py' first.")
        exit(1)
    print("[*] Starting VULNERABLE server on http://localhost:5000")
    print("[*] Endpoints:")
    print("      POST /api/v1/login        — vulnerable login")
    print("      POST /api/v1/login/safe   — parameterised baseline")
    print("      POST /api/v1/register     — second-order setup")
    print("      POST /api/v1/lookup       — second-order trigger")
    print("      GET  /api/v1/audit-log    — audit log reader")
    print("      POST /verify              — Part D verification input")
    print("      GET  /health              — health check")
    print()
    app.run(host="0.0.0.0", port=5000, debug=False)
