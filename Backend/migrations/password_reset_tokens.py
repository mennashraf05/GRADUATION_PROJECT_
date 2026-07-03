from __future__ import annotations

import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "instance" / "sentinel.db"


def migrate_database(db_path: Path = DEFAULT_DB_PATH) -> dict[str, object]:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash VARCHAR(64) NOT NULL UNIQUE,
                expires_at DATETIME NOT NULL,
                used_at DATETIME,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                FOREIGN KEY(user_id) REFERENCES user (id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_user_id "
            "ON password_reset_tokens (user_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_token_hash "
            "ON password_reset_tokens (token_hash)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_expires_at "
            "ON password_reset_tokens (expires_at)"
        )
        conn.commit()

    return {
        "database": str(db_path),
        "table": "password_reset_tokens",
        "indexes": [
            "ix_password_reset_tokens_user_id",
            "ix_password_reset_tokens_token_hash",
            "ix_password_reset_tokens_expires_at",
        ],
    }


if __name__ == "__main__":
    print(migrate_database())
