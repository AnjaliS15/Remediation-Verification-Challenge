"""
seed_db.py
----------
Creates and seeds the vulnerable demo database (users.db) with 10 user records.
Run this FIRST before starting the server.
"""

import sqlite3
import hashlib
import os

DB_PATH = "users.db"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def seed():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[*] Removed existing {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # --- Users table (the injectable one) ---
    cursor.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email    TEXT,
            role     TEXT DEFAULT 'user',
            ssn      TEXT,
            balance  REAL DEFAULT 0.0
        )
    """)

    # --- Audit log (for second-order injection testing) ---
    cursor.execute("""
        CREATE TABLE audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            entry     TEXT,
            logged_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # --- Seed data: 10 user records ---
    users = [
        ("admin",       hash_password("SuperSecret!99"),  "admin@corp.internal",  "admin", "SSN-001-ADMIN",  99999.99),
        ("alice",       hash_password("alice123"),        "alice@example.com",    "user",  "SSN-002-ALICE",  1200.50),
        ("bob",         hash_password("bobpass"),         "bob@example.com",      "user",  "SSN-003-BOB",    340.00),
        ("charlie",     hash_password("charlie!"),        "charlie@example.com",  "user",  "SSN-004-CHARL",  87.25),
        ("diana",       hash_password("diana@99"),        "diana@example.com",    "mod",   "SSN-005-DIANA",  5000.00),
        ("eve",         hash_password("evepass"),         "eve@example.com",      "user",  "SSN-006-EVE",    0.00),
        ("frank",       hash_password("fr@nk2024"),       "frank@example.com",    "user",  "SSN-007-FRANK",  450.75),
        ("grace",       hash_password("gracepass"),       "grace@example.com",    "user",  "SSN-008-GRACE",  2200.00),
        ("heidi",       hash_password("heidi#1"),         "heidi@example.com",    "mod",   "SSN-009-HEIDI",  1500.00),
        ("mallory",     hash_password("m@llory!"),        "mallory@example.com",  "user",  "SSN-010-MALL",   10.00),
    ]

    cursor.executemany(
        "INSERT INTO users (username, password, email, role, ssn, balance) VALUES (?,?,?,?,?,?)",
        users
    )

    conn.commit()
    conn.close()

    print(f"[+] Database '{DB_PATH}' created successfully.")
    print(f"[+] Seeded {len(users)} user records.")
    print(f"[+] Tables: users, audit_log")
    print()
    print("    Sample credentials:")
    print("      admin   / SuperSecret!99  (role=admin)")
    print("      alice   / alice123        (role=user)")
    print()
    print("[*] Run 'python server.py' to start the vulnerable server.")


if __name__ == "__main__":
    seed()
