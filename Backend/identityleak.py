# identityLeak.py
import atexit
import os
import csv
import json
import re
import sqlite3
import time
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
from apscheduler.schedulers.background import BackgroundScheduler

LEAKED_CSV = os.path.join(os.path.dirname(__file__), "leaked_data.csv")
DB_FILE = os.path.join(os.path.dirname(__file__), "leaked_data.db")

# ---------------- Helpers ----------------
def get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def execute_with_retry(cursor, query, params=(), retries=5, delay=0.1):
    for i in range(retries):
        try:
            cursor.execute(query, params)
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and i < retries - 1:
                time.sleep(delay)
            else:
                raise

def normalize_phone(p: str) -> str:
    p = str(p).strip()
    p = re.sub(r"\D+", "", p)
    if p.startswith("0"):
        p = p[1:]
    return p

def detect_type(q: str):
    q = q.strip()
    try:
        validate_email(q)
        return "email"
    except EmailNotValidError:
        pass
    digits = re.sub(r"\D+", "", q)
    if len(digits) >= 7:
        return "phone"
    return "username"

# ---------------- DB Init ----------------
def init_db():
    conn = get_conn()
    cursor = conn.cursor()
    try:
        execute_with_retry(cursor, """
        CREATE TABLE IF NOT EXISTS leaked_data (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            phone TEXT
        )
        """)
        execute_with_retry(cursor, """
        CREATE TABLE IF NOT EXISTS monitored_assets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            asset TEXT,
            asset_type TEXT,
            auto_scan INTEGER,
            enabled INTEGER DEFAULT 1,
            last_checked TEXT,
            last_status TEXT,
            last_matches INTEGER,
            updated_at TEXT
        )
        """)
        execute_with_retry(cursor, """
        CREATE TABLE IF NOT EXISTS asset_breaches (
            id INTEGER PRIMARY KEY,
            monitored_asset_id INTEGER,
            leaked_row_id INTEGER,
            source TEXT,
            leaked_at TEXT,
            raw_data TEXT
        )
        """)
        execute_with_retry(cursor, """
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY,
            monitored_asset_id INTEGER,
            status TEXT,
            matches INTEGER,
            checked_at TEXT
        )
        """)
        conn.commit()
    finally:
        cursor.close()
        conn.close()

# ---------------- Import CSV ----------------
def import_leaked_csv():
    init_db()
    if not os.path.exists(LEAKED_CSV):
        return
    conn = get_conn()
    cursor = conn.cursor()
    try:
        with open(LEAKED_CSV, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = row.get("email", "").strip().lower()
                username = row.get("username", "").strip().lower()
                phone = normalize_phone(row.get("phone", ""))
                execute_with_retry(cursor, """
                    INSERT OR IGNORE INTO leaked_data (id, username, email, phone)
                    VALUES (?, ?, ?, ?)
                """, (row.get("id"), username, email, phone))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

# ---------------- Scan Logic ----------------
def perform_scan_for_asset(asset_row, user_id):
    conn = get_conn()
    cursor = conn.cursor()
    asset = asset_row["asset"].strip()
    atype = asset_row["asset_type"]

    if not asset_row.get("id"):
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        execute_with_retry(cursor, """
            INSERT INTO monitored_assets (user_id, asset, asset_type, auto_scan, enabled, last_checked, last_status, last_matches, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, asset, atype, 0, 1, None, None, 0, now))
        asset_row["id"] = cursor.lastrowid
        conn.commit()
        
    try:
        if atype == "email":
            asset = asset.lower()
            execute_with_retry(cursor, "SELECT * FROM leaked_data WHERE LOWER(TRIM(email)) = ? LIMIT 100", (asset,))
        elif atype == "phone":
            digits = normalize_phone(asset)
            execute_with_retry(cursor, "SELECT * FROM leaked_data WHERE phone LIKE ? LIMIT 100", (f"%{digits}%",))
        else:
            asset = asset.lower()
            execute_with_retry(cursor, "SELECT * FROM leaked_data WHERE LOWER(TRIM(username)) = ? LIMIT 100", (asset,))
        rows = [dict(zip([column[0] for column in cursor.description], r)) for r in cursor.fetchall()]
        if rows:
            return "malicious", rows
        return "safe", []
    finally:
        cursor.close()
        conn.close()

def save_scan_result(monitored_asset_id, status, matches):
    conn = get_conn()
    cursor = conn.cursor()
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        execute_with_retry(cursor, """
            UPDATE monitored_assets
            SET last_checked=?, last_status=?, last_matches=?, updated_at=?
            WHERE id=?
        """, (now, status, len(matches), now, monitored_asset_id))

        if status == "malicious":
            for m in matches:
                execute_with_retry(cursor, """
                    INSERT INTO asset_breaches (monitored_asset_id, leaked_row_id, source, leaked_at, raw_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (monitored_asset_id, m.get("id"), m.get("source"), m.get("leaked_at"), json.dumps(m)))

        execute_with_retry(cursor, """
            INSERT INTO scan_logs (monitored_asset_id, status, matches, checked_at)
            VALUES (?, ?, ?, ?)
        """, (monitored_asset_id, status, len(matches), now))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

# ---------------- Full Scan ----------------
def full_scan(user_id):
    conn = get_conn()
    cursor = conn.cursor()
    try:
        execute_with_retry(cursor, "SELECT id, asset, asset_type FROM monitored_assets WHERE user_id = ? AND enabled = 1", (user_id,))
        rows = cursor.fetchall()
        for r in rows:
            asset_row = {"id": r[0], "asset": r[1], "asset_type": r[2]}
            status, matches = perform_scan_for_asset(asset_row)
            save_scan_result(asset_row["id"], status, matches)
    finally:
        cursor.close()
        conn.close()

# ---------------- Protection Rate & Total Breaches ----------------
def get_total_breaches(user_id):
    conn = get_conn()
    cursor = conn.cursor()
    try:
        execute_with_retry(cursor, "SELECT SUM(last_matches) FROM monitored_assets WHERE user_id = ?", (user_id,))
        total = cursor.fetchone()[0] or 0
        return total
    finally:
        cursor.close()
        conn.close()

def get_protection_rate(user_id):
    conn = get_conn()
    cursor = conn.cursor()
    try:
        execute_with_retry(cursor, "SELECT COUNT(*) FROM monitored_assets WHERE user_id = ?", (user_id,))
        total_assets = cursor.fetchone()[0] or 1
        execute_with_retry(cursor, "SELECT COUNT(*) FROM monitored_assets WHERE last_status='safe'", (user_id,))
        safe_assets = cursor.fetchone()[0] or 0
        rate = (safe_assets / total_assets) * 100
        return round(rate, 2)
    finally:
        cursor.close()
        conn.close()

# ---------------- Auto-scan Scheduler ----------------
scheduler = BackgroundScheduler()

def autoscan_job():
    conn = get_conn()
    cursor = conn.cursor()
    try:
        execute_with_retry(cursor, "SELECT id, asset, asset_type, user_id FROM monitored_assets WHERE enabled=1 AND auto_scan=1")
        rows = cursor.fetchall()
        for r in rows:
            asset_row = {"id": r[0], "asset": r[1], "asset_type": r[2]}
            user_id = r[3]
            status, matches = perform_scan_for_asset(asset_row, user_id)
            save_scan_result(asset_row["id"], status, matches)
    finally:
        cursor.close()
        conn.close()

scheduler.add_job(autoscan_job, 'interval', hours=24)
scheduler.start()
atexit.register(lambda: scheduler.shutdown(wait=False))

# ---------------- Toggle Auto-Scan ----------------
def toggle_auto_scan(asset_id, user_id, enable: bool):
    conn = get_conn()
    cursor = conn.cursor()
    try:
        execute_with_retry(cursor, "UPDATE monitored_assets SET auto_scan=? WHERE id=? AND user_id=?", (1 if enable else 0, asset_id, user_id))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
