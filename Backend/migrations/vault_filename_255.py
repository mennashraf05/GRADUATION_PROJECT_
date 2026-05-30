from __future__ import annotations

import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_databases() -> list[Path]:
    root = _repo_root()
    return [
        root / "Backend" / "instance" / "vault.db",
        root / "instance" / "vault.db",
    ]


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _backup_database(db_path: Path) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    backup_path = db_path.with_suffix(f"{db_path.suffix}.vault_filename_255_{timestamp}.bak")
    shutil.copy2(db_path, backup_path)
    return backup_path


def migrate_database(db_path: Path) -> dict[str, object]:
    db_path = db_path.resolve()
    if not db_path.exists():
        return {"database": str(db_path), "skipped": True, "reason": "missing"}

    backup_path = _backup_database(db_path)
    conn = sqlite3.connect(db_path)
    try:
        if not _table_exists(conn, "vault_documents"):
            return {"database": str(db_path), "skipped": True, "reason": "missing_table"}

        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN")
        conn.execute(
            """
            CREATE TABLE vault_documents_new (
                id INTEGER NOT NULL,
                filename VARCHAR(255) NOT NULL,
                stored_filename VARCHAR(255) NOT NULL,
                upload_date DATETIME NOT NULL,
                user_id INTEGER NOT NULL,
                file_hash VARCHAR(64) NOT NULL,
                salt VARCHAR(32) NOT NULL,
                offline_enabled BOOLEAN NOT NULL,
                signature TEXT,
                hmac_key VARCHAR(44),
                PRIMARY KEY (id)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO vault_documents_new (
                id, filename, stored_filename, upload_date, user_id, file_hash,
                salt, offline_enabled, signature, hmac_key
            )
            SELECT
                id, filename, stored_filename, upload_date, user_id, file_hash,
                salt, offline_enabled, signature, hmac_key
            FROM vault_documents
            """
        )
        conn.execute("DROP TABLE vault_documents")
        conn.execute("ALTER TABLE vault_documents_new RENAME TO vault_documents")
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
        "updated": "vault_documents filename/stored_filename VARCHAR(255)",
    }


def main() -> None:
    for db_path in _default_databases():
        print(migrate_database(db_path))


if __name__ == "__main__":
    main()
