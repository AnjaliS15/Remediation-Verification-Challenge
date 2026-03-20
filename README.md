# Remediation-Verification-Challenge
A hands-on security automation project built as part of a Remediation Verification Engineer assessment. The goal of this project is to simulate what a real remediation verification pipeline does — take a reported vulnerability, build a target environment that reproduces it, and automate the process of proving whether a fix actually works or not.

The vulnerability in scope is a SQL Injection on a login endpoint (POST /api/v1/login), reported as finding FIND-0042. The client claims to have fixed it using input sanitization. This project challenges that claim by building the vulnerable server from scratch, seeding it with realistic data, and running a structured attack suite that covers 12 distinct injection categories — from classic OR bypasses to second-order injection and WAF evasion techniques.

**How to Run**
You need two terminals open in the same project directory.

Step 1 — Seed the database (run once):
python3 seed_db.py
Step 2 — Start the vulnerable server (Terminal 1):
python3 server.py
Step 3 — Run the attack script (Terminal 2):
python3 attack.py
To point the attack script at a different host:
python3 attack.py --host http://localhost:5000

**Script Descriptions**

**1. seed_db.py**
   
Creates the SQLite database file users.db from scratch and populates it with two tables:

users — 10 records with realistic fields: username, SHA-256 hashed password, email, role, SSN, and account balance. Includes an admin account and a mix of regular users and moderators.
audit_log — An empty table used as a side-effect target for stacked query injection tests (TC-12).

If users.db already exists it is deleted and recreated, so every run starts from a clean state. This script must be run before starting the server.

**2. server.py**
   
An intentionally vulnerable Flask web server that replicates a real-world SQL injection scenario. It runs on http://localhost:5000 and exposes the several endpoints.

**3. attack.py**

The automated remediation verification script. It connects to the target server, captures a baseline response hash, fires 12 SQL injection payloads across 6 attack categories, detects anomalies, and prints a structured verification report to the terminal.

**Disclaimer:**
This project is built entirely for educational and assessment purposes. All vulnerable code is intentional and clearly labelled. Do not use any part of this project against systems you do not own or have explicit written permission to test.
