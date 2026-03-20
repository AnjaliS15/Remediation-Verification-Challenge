"""
attack.py
---------
Automated SQL Injection Remediation Verification Script
Covers all 12 test cases from Part B of Challenge 1.

Usage:
    python attack.py [--host http://localhost:5000] [--output results.json]

Output:
    - Formatted remediation report to stdout
    - Timestamped JSON evidence file with SHA-256 hash (bonus requirement)
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

TIMING_THRESHOLD = 4.0   # seconds

# ─────────────────────────────────────────────────────────────────────────────
# Test Case Definitions  (matches Part B table exactly)
# ─────────────────────────────────────────────────────────────────────────────

TEST_CASES = [
    {
        "tc_id":    "TC-01",
        "category": "Classic OR Bypass",
        "payload":  "' OR '1'='1",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Basic OR tautology — should return multiple records if vulnerable",
        "pass_conditions": ["records_returned == 0", "status_code == 401"],
    },
    {
        "tc_id":    "TC-02",
        "category": "Classic Comment Termination",
        "payload":  "admin'--",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Comment truncation to bypass password check",
        "pass_conditions": ["records_returned <= 1", "no session bypass"],
    },
    {
        "tc_id":    "TC-03",
        "category": "Blind Boolean — True Condition",
        "payload":  "' AND 1=1--",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Boolean true — response should match baseline (TC-04) if fixed",
        "pass_conditions": ["response matches false-condition response"],
    },
    {
        "tc_id":    "TC-04",
        "category": "Blind Boolean — False Condition",
        "payload":  "' AND 1=2--",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Boolean false — identical to TC-03 response if fixed",
        "pass_conditions": ["response identical to TC-03"],
    },
    {
        "tc_id":    "TC-05",
        "category": "Time-Based Blind",
        # SQLite uses randomblob for sleep simulation since it lacks SLEEP()
        "payload":  "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) x, (SELECT 1 UNION SELECT 2 UNION SELECT 3) y, (SELECT 1 UNION SELECT 2 UNION SELECT 3) z, users) > 0--",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Time-based blind via cartesian join on users table",
        "pass_conditions": [f"response_time < {TIMING_THRESHOLD}s"],
    },
    {
        "tc_id":    "TC-06",
        "category": "Error-Based",
        "payload":  "' AND 1=CAST((SELECT username FROM users LIMIT 1) AS INTEGER)--",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Type-cast error forces DB to leak data in error message",
        "pass_conditions": ["no DB error in response", "no username in response body"],
    },
    {
        "tc_id":    "TC-07",
        "category": "Encoding Bypass (URL double-encode)",
        # Sent as literal string — server receives %27 which it may decode
        "payload":  "%27 OR %271%27=%271",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "URL-encoded quote to evade character-stripping sanitiser",
        "pass_conditions": ["records_returned == 0", "status_code == 401"],
    },
    {
        "tc_id":    "TC-08",
        "category": "Input Sanitisation — Double Quote Strip",
        "payload":  "'' OR 1=1--",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Two consecutive quotes: if sanitiser strips one, the second completes the injection",
        "pass_conditions": ["records_returned == 0", "status_code == 401"],
    },
    {
        "tc_id":    "TC-09",
        "category": "Input Sanitisation — Keyword Obfuscation",
        "payload":  "' /**/OR/**/ '1'='1",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "Inline comments around OR bypass keyword-stripping sanitisers",
        "pass_conditions": ["records_returned == 0", "status_code == 401"],
    },
    {
        "tc_id":    "TC-10",
        "category": "Second-Order Injection",
        "payload":  "admin'--",
        "endpoint": "/api/v1/register + /api/v1/lookup",
        "method":   "second_order",
        "description": "Register payload as username, trigger lookup — stored value re-injected",
        "pass_conditions": ["lookup returns only registered user", "no privilege escalation"],
    },
    {
        "tc_id":    "TC-11",
        "category": "WAF-Bypass (Comment Fragmentation)",
        "payload":  "'/*!OR*/1=1--",
        "endpoint": "/api/v1/login",
        "method":   "login",
        "description": "MySQL version-comment syntax bypasses WAF pattern matching",
        "pass_conditions": ["records_returned == 0", "status_code == 401"],
    },
    {
        "tc_id":    "TC-12",
        "category": "Stacked Query / Side Effect",
        # SQLite supports multiple statements via executescript but not via execute;
        # we probe for INSERT into audit_log
        "payload":  "'; INSERT INTO audit_log(entry) VALUES('TC12_PWNED');--",
        "endpoint": "/api/v1/login",
        "method":   "login_then_audit",
        "description": "Stacked query attempts INSERT into audit_log as side effect",
        "pass_conditions": ["audit_log contains no TC12_PWNED entry"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────

def post_login(host: str, payload: str) -> dict:
    url = host + "/api/v1/login"
    body = {"username": payload, "password": "irrelevant"}
    t0 = time.time()
    try:
        resp = requests.post(url, json=body, timeout=30)
        elapsed = round(time.time() - t0, 3)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return {"status_code": resp.status_code, "elapsed_s": elapsed, "body": data}
    except requests.exceptions.Timeout:
        elapsed = round(time.time() - t0, 3)
        return {"status_code": 0, "elapsed_s": elapsed, "body": {}, "error": "timeout"}
    except requests.exceptions.ConnectionError as e:
        return {"status_code": 0, "elapsed_s": 0, "body": {}, "error": str(e)}


def post_register(host: str, username: str) -> dict:
    url = host + "/api/v1/register"
    t0  = time.time()
    resp = requests.post(url, json={"username": username, "password": "test", "email": "so@test.com"}, timeout=10)
    return {"status_code": resp.status_code, "elapsed_s": round(time.time() - t0, 3), "body": resp.json()}


def post_lookup(host: str, user_id: int) -> dict:
    url = host + "/api/v1/lookup"
    t0  = time.time()
    resp = requests.post(url, json={"user_id": user_id}, timeout=10)
    return {"status_code": resp.status_code, "elapsed_s": round(time.time() - t0, 3), "body": resp.json()}


def get_audit_log(host: str) -> list:
    url = host + "/api/v1/audit-log"
    try:
        resp = requests.get(url, timeout=10)
        return resp.json().get("entries", [])
    except Exception:
        return []


def response_hash(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Baseline
# ─────────────────────────────────────────────────────────────────────────────

def get_baseline(host: str) -> str:
    """Sends a known-bad credential and records the hash of the response body."""
    result = post_login(host, "nonexistent_user_xyz_baseline")
    h = response_hash(result["body"])
    return h


# ─────────────────────────────────────────────────────────────────────────────
# Test runners
# ─────────────────────────────────────────────────────────────────────────────

def run_login_test(host: str, tc: dict, baseline_hash: str) -> dict:
    result = post_login(host, tc["payload"])
    body   = result["body"]
    sc     = result["status_code"]
    elapsed = result["elapsed_s"]
    r_hash  = response_hash(body)
    hash_match = (r_hash == baseline_hash)

    anomalies = []

    if elapsed > TIMING_THRESHOLD:
        anomalies.append(f"Timing anomaly ({elapsed}s > {TIMING_THRESHOLD}s threshold)")

    records = body.get("records_returned", 0)
    if records > 1:
        anomalies.append(f"Multiple records returned ({records}) — possible auth bypass")
    elif records == 1 and sc == 200:
        anomalies.append("Single record returned on injection payload — suspicious")

    if sc == 200 and body.get("status") == "ok":
        anomalies.append("Login succeeded with injection payload")

    if sc >= 500 or body.get("status") == "error":
        error_msg = body.get("message", "")
        anomalies.append(f"Server error / error-based leak: {error_msg[:120]}")

    if not hash_match:
        anomalies.append("Response hash deviates from baseline")

    # TC-07 specific: check if URL-encoded quote got decoded
    if tc["tc_id"] == "TC-07" and records > 0:
        anomalies.append("Encoded payload was decoded and executed — sanitiser bypass confirmed")

    passed = len(anomalies) == 0
    return {
        "tc_id":       tc["tc_id"],
        "category":    tc["category"],
        "payload":     tc["payload"],
        "description": tc["description"],
        "status_code": sc,
        "elapsed_s":   elapsed,
        "hash_match":  hash_match,
        "records_returned": records,
        "anomalies":   anomalies,
        "result":      "PASS" if passed else "FAIL",
    }


def run_second_order_test(host: str, tc: dict) -> dict:
    """TC-10: register a malicious username, then trigger lookup."""
    so_username = f"second_order_test_{int(time.time())}'--"
    reg = post_register(host, so_username)

    anomalies = []

    if reg["status_code"] not in (201, 409):
        anomalies.append(f"Register failed unexpectedly: HTTP {reg['status_code']}")
        return _tc_result(tc, anomalies, 0, 0, reg["status_code"])

    user_id = reg["body"].get("user_id")
    if not user_id and reg["status_code"] == 409:
        # Already registered — try to find it
        anomalies.append("Username already existed (re-run scenario)")
        return _tc_result(tc, anomalies, 0, 0, 409)

    lookup = post_lookup(host, user_id)
    body   = lookup["body"]

    records = len(body.get("records", []))
    if records > 1:
        anomalies.append(f"Second-order injection returned {records} records — stored payload executed")

    if body.get("status") == "error":
        anomalies.append(f"Error-based second-order leak: {body.get('message', '')[:120]}")

    # Check if stored username appears in second_query with unescaped quote
    second_q = body.get("second_query", "")
    if "'" in second_q.replace(f"'{so_username.split(chr(39))[0]}", ""):
        anomalies.append("Stored payload was re-injected into query without escaping")

    passed = len(anomalies) == 0
    return _tc_result(tc, anomalies, lookup["elapsed_s"], records, lookup["status_code"])


def run_login_then_audit(host: str, tc: dict, baseline_hash: str) -> dict:
    """TC-12: run login, then check audit_log for side-effect INSERT."""
    login_result = run_login_test(host, tc, baseline_hash)

    # Check audit log for the sentinel value
    entries = get_audit_log(host)
    pwned_entries = [e for e in entries if "TC12_PWNED" in str(e.get("entry", ""))]

    if pwned_entries:
        login_result["anomalies"].append(
            f"Stacked query executed — audit_log contains {len(pwned_entries)} injected row(s)"
        )
        login_result["result"] = "FAIL"

    return login_result


def _tc_result(tc: dict, anomalies: list, elapsed: float, records: int, sc: int) -> dict:
    passed = len(anomalies) == 0
    return {
        "tc_id":            tc["tc_id"],
        "category":         tc["category"],
        "payload":          tc["payload"],
        "description":      tc["description"],
        "status_code":      sc,
        "elapsed_s":        elapsed,
        "hash_match":       None,
        "records_returned": records,
        "anomalies":        anomalies,
        "result":           "PASS" if passed else "FAIL",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Report renderer
# ─────────────────────────────────────────────────────────────────────────────

def print_report(results: list, baseline_hash: str, host: str, timestamp: str):
    total  = len(results)
    failed = sum(1 for r in results if r["result"] == "FAIL")
    verdict = "REMEDIATION PASSED" if failed == 0 else "REMEDIATION FAILED"

    SEP = "=" * 45

    print(f"\n{SEP}")
    print("===== REMEDIATION VERIFICATION REPORT =====")
    print(f"{SEP}")
    print(f"Finding  : sql_injection (FIND-0042)")
    print(f"Target   : {host}/api/v1/login")
    print(f"Timestamp: {timestamp}")
    print(f"{SEP}\n")

    for r in results:
        tc_id   = r["tc_id"]
        payload = r["payload"]
        sc      = r["status_code"]
        elapsed = r["elapsed_s"]
        hm      = "YES" if r.get("hash_match") is True else ("N/A" if r.get("hash_match") is None else "NO")
        result  = r["result"]

        # Build the anomaly reason string for FAIL lines
        reason = ""
        if r["anomalies"]:
            reason = " -- " + r["anomalies"][0]

        print(f"[{tc_id}] Payload: {payload}")
        print(f"Status : {sc} | Time: {elapsed}s | Hash Match: {hm}")

        if result == "PASS":
            print(f"Result : {GREEN}{BOLD}PASS{RESET}")
        else:
            print(f"Result : {RED}{BOLD}FAIL{reason}{RESET}")

        print()

    print(SEP)
    verdict_colour = GREEN if failed == 0 else RED
    print(f"{verdict_colour}{BOLD}===== VERDICT: {verdict} ====={RESET}")
    print(f"Failed Tests: {failed} / {total}")
    print(f"{SEP}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Evidence file writer (bonus)
# ─────────────────────────────────────────────────────────────────────────────

def save_evidence(results: list, baseline_hash: str, host: str, timestamp: str, output_path: str):
    total  = len(results)
    failed = sum(1 for r in results if r["result"] == "FAIL")

    evidence = {
        "finding":        "sql_injection",
        "finding_id":     "FIND-0042",
        "target":         host + "/api/v1/login",
        "timestamp":      timestamp,
        "baseline_hash":  baseline_hash,
        "test_cases":     results,
        "summary": {
            "total":   total,
            "passed":  total - failed,
            "failed":  failed,
            "verdict": "REMEDIATION PASSED" if failed == 0 else "REMEDIATION FAILED",
        }
    }

    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    file_bytes = open(output_path, "rb").read()
    sha256     = hashlib.sha256(file_bytes).hexdigest()

    print(f"  {GREEN}[+] Evidence saved : {output_path}{RESET}")
    print(f"  {GREEN}[+] SHA-256        : {sha256}{RESET}\n")

    return sha256


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SQLi Remediation Verification — FIND-0042")
    parser.add_argument("--host",   default="http://localhost:5000", help="Server base URL")
    parser.add_argument("--output", default="", help="Output JSON file path (auto-timestamped if empty)")
    args = parser.parse_args()

    host = args.host.rstrip("/")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Timestamped output file
    ts_slug   = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = args.output or f"evidence_{ts_slug}.json"

    print(f"\n{BOLD}[*] Connecting to {host}{RESET}")

    # Health check
    try:
        hc = requests.get(host + "/health", timeout=5)
        if hc.status_code != 200:
            print(f"{RED}[!] Health check failed — is the server running?{RESET}")
            sys.exit(1)
        print(f"{GREEN}[+] Server reachable. DB present: {hc.json().get('db')}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Cannot reach server: {e}{RESET}")
        sys.exit(1)

    # Baseline
    print(f"[*] Capturing baseline response hash...")
    baseline_hash = get_baseline(host)
    print(f"{GREEN}[+] Baseline hash: {baseline_hash[:32]}...{RESET}\n")

    results = []
    for tc in TEST_CASES:
        method = tc.get("method", "login")
        if method == "second_order":
            r = run_second_order_test(host, tc)
        elif method == "login_then_audit":
            r = run_login_then_audit(host, tc, baseline_hash)
        else:
            r = run_login_test(host, tc, baseline_hash)
        results.append(r)

    print_report(results, baseline_hash, host, timestamp)
    save_evidence(results, baseline_hash, host, timestamp, out_path)


if __name__ == "__main__":
    main()
