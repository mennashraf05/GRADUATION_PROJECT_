import sqlite3
import os

DB_PATH = os.path.join("data", "scans.db")
os.makedirs("data", exist_ok=True)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    url TEXT,
    risk INTEGER,
    result TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()
conn.close()


def save_scan(user_id, url, risk, result):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (user_id, url, risk, result) VALUES (?, ?, ?, ?)",
        (user_id, url, risk, result)
    )
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def get_user_scans(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, url, risk, result, timestamp FROM scans WHERE user_id = ? ORDER BY timestamp DESC",
        (user_id,)
    )
    rows = c.fetchall()
    conn.close()

    return [
        {
            "scan_id": row[0],
            "url": row[1],
            "risk": row[2],
            "result": row[3],
            "timestamp": row[4]
        }
        for row in rows
    ]


def delete_scan(scan_id, user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
    conn.commit()
    conn.close()
