from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime, UTC
from pathlib import Path


PHONE_VERIFICATION_TABLES = (
    "phone_otp_challenge",
    "sms_dispatch_log",
)

PHONE_VERIFICATION_USER_COLUMNS = (
    "phone_verified",
    "phone_verified_at",
    "sms_alerts_enabled",
    "login_phone_otp_enabled",
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_databases() -> list[Path]:
    root = _repo_root()
    return [
        root / "Backend" / "instance" / "sentinel_ai.db",
        root / "instance" / "sentinel_ai.db",
    ]


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _column_exists(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    if not _table_exists(conn, table_name):
        return False
    return any(row[1] == column_name for row in conn.execute(f'PRAGMA table_info("{table_name}")'))


def _backup_database(db_path: Path) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    backup_path = db_path.with_suffix(f"{db_path.suffix}.phone_cleanup_{timestamp}.bak")
    shutil.copy2(db_path, backup_path)
    return backup_path


def migrate_database(db_path: Path) -> dict[str, object]:
    db_path = db_path.resolve()
    if not db_path.exists():
        return {"database": str(db_path), "skipped": True, "reason": "missing"}

    backup_path = _backup_database(db_path)
    dropped_tables: list[str] = []
    dropped_columns: list[str] = []

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN")

        for table_name in PHONE_VERIFICATION_TABLES:
            if _table_exists(conn, table_name):
                conn.execute(f'DROP TABLE "{table_name}"')
                dropped_tables.append(table_name)

        for column_name in PHONE_VERIFICATION_USER_COLUMNS:
            if _column_exists(conn, "user", column_name):
                conn.execute(f'ALTER TABLE "user" DROP COLUMN "{column_name}"')
                dropped_columns.append(f"user.{column_name}")

        conn.commit()
    except Exception:
        conn.rollback()
        shutil.copy2(backup_path, db_path)
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.close()

    return {
        "database": str(db_path),
        "backup": str(backup_path),
        "dropped_tables": dropped_tables,
        "dropped_columns": dropped_columns,
    }


def main() -> None:
    for db_path in _default_databases():
        result = migrate_database(db_path)
        print(result)


if __name__ == "__main__":
    main()
