from __future__ import annotations

import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "identity_monitor.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS identity_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                username TEXT,
                domain TEXT,
                status TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'Low',
                recommendation TEXT,
                sources_checked INTEGER DEFAULT 0,
                source_status TEXT DEFAULT '{}',
                total_findings INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                user_id INTEGER,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS identity_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                category TEXT DEFAULT 'public_mention',
                severity TEXT NOT NULL,
                title TEXT,
                url TEXT,
                matched_field TEXT,
                matched_value TEXT,
                evidence TEXT,
                found_in_search INTEGER DEFAULT 0,
                found_in_page INTEGER DEFAULT 0,
                risk_keyword_detected INTEGER DEFAULT 0,
                detected_keywords TEXT DEFAULT '[]',
                confidence INTEGER DEFAULT 0,
                detected_at TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY(scan_id) REFERENCES identity_scans(id)
            );

            CREATE TABLE IF NOT EXISTS identity_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                user_id INTEGER,
                is_read INTEGER DEFAULT 0,
                email_status TEXT DEFAULT 'skipped',
                email_sent_at TEXT,
                email_error TEXT,
                FOREIGN KEY(scan_id) REFERENCES identity_scans(id)
            );

            CREATE TABLE IF NOT EXISTS identity_monitored_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_type TEXT NOT NULL,
                asset_value TEXT NOT NULL,
                label TEXT,
                status TEXT DEFAULT 'pending',
                last_scan_id INTEGER,
                last_risk_score INTEGER DEFAULT 0,
                last_risk_level TEXT DEFAULT 'Low',
                last_findings_count INTEGER DEFAULT 0,
                last_checked_at TEXT,
                auto_scan_enabled INTEGER DEFAULT 1,
                user_id INTEGER,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, asset_type, asset_value)
            );
            """
        )
        _ensure_column(conn, "identity_findings", "category", "TEXT DEFAULT 'public_mention'")
        _ensure_column(conn, "identity_findings", "detected_keywords", "TEXT DEFAULT '[]'")
        _ensure_column(conn, "identity_findings", "user_id", "INTEGER")
        _ensure_column(conn, "identity_scans", "recommendation", "TEXT")
        _ensure_column(conn, "identity_scans", "source_status", "TEXT DEFAULT '{}'")
        _ensure_column(conn, "identity_scans", "user_id", "INTEGER")
        _ensure_column(conn, "identity_alerts", "user_id", "INTEGER")
        _ensure_column(conn, "identity_alerts", "email_status", "TEXT DEFAULT 'skipped'")
        _ensure_column(conn, "identity_alerts", "email_sent_at", "TEXT")
        _ensure_column(conn, "identity_alerts", "email_error", "TEXT")
        _ensure_column(conn, "identity_monitored_assets", "label", "TEXT")
        _ensure_column(conn, "identity_monitored_assets", "auto_scan_enabled", "INTEGER DEFAULT 1")
        _ensure_column(conn, "identity_monitored_assets", "user_id", "INTEGER")
        _ensure_assets_user_scope_schema(conn)


def create_scan(email: str | None, username: str | None, domain: str | None, created_at: str, user_id: int) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO identity_scans (email, username, domain, status, created_at, user_id)
            VALUES (?, ?, ?, 'running', ?, ?)
            """,
            (email or None, username or None, domain or None, created_at, user_id),
        )
        return int(cursor.lastrowid)


def complete_scan(scan_id: int, result: dict, completed_at: str, user_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE identity_scans
            SET status=?, risk_score=?, risk_level=?, recommendation=?, sources_checked=?, source_status=?,
                total_findings=?, completed_at=?, error_message=NULL
            WHERE id=? AND user_id=?
            """,
            (
                result.get("status", "completed"),
                int(result.get("risk_score", 0)),
                result.get("risk_level", "Low"),
                result.get("recommendation"),
                int(result.get("sources_checked", 0)),
                json.dumps(result.get("source_status") or {}),
                int(result.get("total_findings", 0)),
                completed_at,
                scan_id,
                user_id,
            ),
        )


def fail_scan(scan_id: int, message: str, completed_at: str, user_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE identity_scans
            SET status='failed', completed_at=?, error_message=?
            WHERE id=? AND user_id=?
            """,
            (completed_at, message[:500], scan_id, user_id),
        )


def save_findings(scan_id: int, findings: list[dict], detected_at: str, user_id: int) -> None:
    if not findings:
        return

    rows = [
        (
            scan_id,
            finding.get("source"),
            finding.get("category", "public_mention"),
            finding.get("severity", "Low"),
            finding.get("title"),
            finding.get("url"),
            finding.get("matched_field"),
            finding.get("matched_value"),
            finding.get("evidence"),
            1 if finding.get("found_in_search") else 0,
            1 if finding.get("found_in_page") else 0,
            1 if finding.get("risk_keyword_detected") else 0,
            json.dumps(finding.get("detected_keywords") or []),
            int(finding.get("confidence", 0)),
            detected_at,
            user_id,
        )
        for finding in findings
    ]

    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO identity_findings (
                scan_id, source, category, severity, title, url, matched_field, matched_value,
                evidence, found_in_search, found_in_page, risk_keyword_detected,
                detected_keywords, confidence, detected_at, user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def create_alert(scan_id: int, risk_level: str, total_findings: int, created_at: str, user_id: int) -> int | None:
    if risk_level not in {"Medium", "High", "Critical"}:
        return None

    title = f"{risk_level} identity exposure detected"
    message = f"Scan #{scan_id} returned {total_findings} public exposure finding(s). Review evidence and source links."
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO identity_alerts (scan_id, module, title, message, severity, created_at, user_id, is_read)
            VALUES (?, 'Identity Leak Monitor', ?, ?, ?, ?, ?, 0)
            """,
            (scan_id, title, message, risk_level, created_at, user_id),
        )
        return int(cursor.lastrowid)


def backfill_missing_alerts(user_id: int, limit: int = 250) -> int:
    """Create missing Identity alert rows for completed risky scans only."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                identity_scans.id AS scan_id,
                identity_scans.risk_level,
                identity_scans.total_findings,
                COALESCE(identity_scans.completed_at, identity_scans.created_at) AS alert_created_at
            FROM identity_scans
            WHERE identity_scans.user_id=?
              AND identity_scans.status='completed'
              AND identity_scans.risk_level IN ('Medium', 'High', 'Critical')
              AND identity_scans.total_findings > 0
              AND NOT EXISTS (
                  SELECT 1
                  FROM identity_alerts
                  WHERE identity_alerts.user_id=identity_scans.user_id
                    AND identity_alerts.scan_id=identity_scans.id
              )
            ORDER BY datetime(COALESCE(identity_scans.completed_at, identity_scans.created_at)) DESC,
                     identity_scans.id DESC
            LIMIT ?
            """,
            (user_id, max(1, min(int(limit or 250), 500))),
        ).fetchall()

        inserted = 0
        for row in rows:
            risk_level = row["risk_level"] or "Medium"
            title = f"{risk_level} identity exposure detected"
            message = (
                f"Scan #{row['scan_id']} returned {int(row['total_findings'] or 0)} "
                "public exposure finding(s). Review evidence and source links."
            )
            conn.execute(
                """
                INSERT INTO identity_alerts (scan_id, module, title, message, severity, created_at, user_id, is_read)
                VALUES (?, 'Identity Leak Monitor', ?, ?, ?, ?, ?, 0)
                """,
                (
                    int(row["scan_id"]),
                    title,
                    message,
                    risk_level,
                    row["alert_created_at"],
                    user_id,
                ),
            )
            inserted += 1
        return inserted


def list_scans(user_id: int, limit: int = 25) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                identity_scans.*,
                COALESCE(SUM(CASE WHEN identity_findings.category='confirmed_breach' THEN 1 ELSE 0 END), 0)
                    AS confirmed_breach_count
            FROM identity_scans
            LEFT JOIN identity_findings ON identity_findings.scan_id = identity_scans.id
            WHERE identity_scans.user_id=?
            GROUP BY identity_scans.id
            ORDER BY datetime(identity_scans.created_at) DESC, identity_scans.id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [_scan_row_to_dict(row) for row in rows]


def get_scan(scan_id: int, user_id: int) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM identity_scans WHERE id=? AND user_id=?", (scan_id, user_id)).fetchone()
        return _scan_row_to_dict(row) if row else None


def list_findings(scan_id: int, user_id: int) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM identity_findings
            WHERE scan_id=? AND user_id=?
            ORDER BY id ASC
            """,
            (scan_id, user_id),
        ).fetchall()
        findings = [_row_to_dict(row) for row in rows]
        for finding in findings:
            finding["found_in_search"] = bool(finding["found_in_search"])
            finding["found_in_page"] = bool(finding["found_in_page"])
            finding["risk_keyword_detected"] = bool(finding["risk_keyword_detected"])
            try:
                finding["detected_keywords"] = json.loads(finding.get("detected_keywords") or "[]")
            except json.JSONDecodeError:
                finding["detected_keywords"] = []
        return findings


def list_alerts(user_id: int, limit: int = 25) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM identity_alerts
            WHERE user_id=?
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        alerts = [_row_to_dict(row) for row in rows]
        for alert in alerts:
            alert["is_read"] = bool(alert["is_read"])
        return alerts


def unread_alert_count(user_id: int) -> int:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM identity_alerts WHERE user_id=? AND is_read=0",
            (user_id,),
        ).fetchone()
        return int(row["count"] if row else 0)


def mark_alerts_read(user_id: int, alert_ids: list[int]) -> int:
    clean_ids = sorted({int(alert_id) for alert_id in alert_ids if int(alert_id) > 0})
    if not clean_ids:
        return 0

    placeholders = ",".join("?" for _ in clean_ids)
    with get_connection() as conn:
        cursor = conn.execute(
            f"""
            UPDATE identity_alerts
            SET is_read=1
            WHERE user_id=? AND is_read=0 AND id IN ({placeholders})
            """,
            (user_id, *clean_ids),
        )
        return int(cursor.rowcount or 0)


def mark_all_alerts_read(user_id: int) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE identity_alerts SET is_read=1 WHERE user_id=? AND is_read=0",
            (user_id,),
        )
        return int(cursor.rowcount or 0)


def update_alert_email_status(
    alert_id: int | None,
    user_id: int,
    status: str,
    sent_at: str | None = None,
    error: str | None = None,
) -> None:
    if not alert_id:
        return
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE identity_alerts
            SET email_status=?, email_sent_at=?, email_error=?
            WHERE id=? AND user_id=?
            """,
            (status, sent_at, (error or None), int(alert_id), user_id),
        )


def clear_history(user_id: int) -> int:
    with get_connection() as conn:
        scan_rows = conn.execute("SELECT id FROM identity_scans WHERE user_id=?", (user_id,)).fetchall()
        scan_ids = [int(row["id"]) for row in scan_rows]
        if not scan_ids:
            return 0

        placeholders = ",".join("?" for _ in scan_ids)
        conn.execute(
            f"DELETE FROM identity_findings WHERE user_id=? AND scan_id IN ({placeholders})",
            (user_id, *scan_ids),
        )
        conn.execute(
            f"DELETE FROM identity_alerts WHERE user_id=? AND scan_id IN ({placeholders})",
            (user_id, *scan_ids),
        )
        conn.execute(
            f"""
            UPDATE identity_monitored_assets
            SET status='pending', last_scan_id=NULL, last_risk_score=0,
                last_risk_level='Low', last_findings_count=0, last_checked_at=NULL
            WHERE user_id=? AND last_scan_id IN ({placeholders})
            """,
            (user_id, *scan_ids),
        )
        cursor = conn.execute("DELETE FROM identity_scans WHERE user_id=?", (user_id,))
        return int(cursor.rowcount or 0)


def list_assets(user_id: int) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                identity_monitored_assets.*,
                COALESCE(SUM(
                    CASE
                        WHEN identity_findings.category IN (
                            'confirmed_breach',
                            'confirmed_exposure',
                            'possible_exposure'
                        )
                        THEN 1 ELSE 0
                    END
                ), 0) AS exposure_findings_count
            FROM identity_monitored_assets
            LEFT JOIN identity_findings
                ON identity_findings.scan_id = identity_monitored_assets.last_scan_id
                AND identity_findings.user_id = identity_monitored_assets.user_id
            WHERE identity_monitored_assets.user_id=?
            GROUP BY identity_monitored_assets.id
            ORDER BY datetime(identity_monitored_assets.created_at) DESC, identity_monitored_assets.id DESC
            """
            ,
            (user_id,),
        ).fetchall()
        return [_asset_row_to_dict(row) for row in rows]


def create_asset(asset_type: str, asset_value: str, label: str | None, created_at: str, user_id: int) -> dict:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO identity_monitored_assets (
                asset_type, asset_value, label, status, auto_scan_enabled, created_at, user_id
            )
            VALUES (?, ?, ?, 'pending', 1, ?, ?)
            ON CONFLICT(user_id, asset_type, asset_value) DO UPDATE SET
                label=excluded.label
            RETURNING *
            """,
            (asset_type, asset_value, label or None, created_at, user_id),
        )
        return _asset_row_to_dict(cursor.fetchone())


def delete_asset(asset_id: int, user_id: int) -> bool:
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM identity_monitored_assets WHERE id=? AND user_id=?", (asset_id, user_id))
        return cursor.rowcount > 0


def update_asset_scan_result(asset_id: int, scan_id: int, result: dict, checked_at: str, user_id: int) -> None:
    risk_level = result.get("risk_level") or "Low"
    status = "risky" if str(risk_level).lower() in {"medium", "high", "critical"} else "clean"
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE identity_monitored_assets
            SET status=?, last_scan_id=?, last_risk_score=?, last_risk_level=?,
                last_findings_count=?, last_checked_at=?
            WHERE id=? AND user_id=?
            """,
            (
                status,
                scan_id,
                int(result.get("risk_score", 0)),
                risk_level,
                int(result.get("total_findings", 0)),
                checked_at,
                asset_id,
                user_id,
            ),
        )


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


def _scan_row_to_dict(row: sqlite3.Row) -> dict:
    scan = _row_to_dict(row)
    try:
        scan["source_status"] = json.loads(scan.get("source_status") or "{}")
    except json.JSONDecodeError:
        scan["source_status"] = {}
    return scan


def _asset_row_to_dict(row: sqlite3.Row) -> dict:
    asset = _row_to_dict(row)
    asset["auto_scan_enabled"] = bool(asset.get("auto_scan_enabled"))
    asset["exposure_findings_count"] = int(asset.get("exposure_findings_count") or 0)
    return asset


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _ensure_assets_user_scope_schema(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='identity_monitored_assets'"
    ).fetchone()
    create_sql = str(row["sql"] if row else "")
    if "UNIQUE(asset_type, asset_value)" not in create_sql:
        return

    conn.executescript(
        """
        ALTER TABLE identity_monitored_assets RENAME TO identity_monitored_assets_legacy;

        CREATE TABLE identity_monitored_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type TEXT NOT NULL,
            asset_value TEXT NOT NULL,
            label TEXT,
            status TEXT DEFAULT 'pending',
            last_scan_id INTEGER,
            last_risk_score INTEGER DEFAULT 0,
            last_risk_level TEXT DEFAULT 'Low',
            last_findings_count INTEGER DEFAULT 0,
            last_checked_at TEXT,
            auto_scan_enabled INTEGER DEFAULT 1,
            user_id INTEGER,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, asset_type, asset_value)
        );

        INSERT INTO identity_monitored_assets (
            id, asset_type, asset_value, label, status, last_scan_id, last_risk_score,
            last_risk_level, last_findings_count, last_checked_at, auto_scan_enabled,
            user_id, created_at
        )
        SELECT
            id, asset_type, asset_value, label, status, last_scan_id, last_risk_score,
            last_risk_level, last_findings_count, last_checked_at, auto_scan_enabled,
            user_id, created_at
        FROM identity_monitored_assets_legacy
        WHERE user_id IS NOT NULL;

        DROP TABLE identity_monitored_assets_legacy;
        """
    )
