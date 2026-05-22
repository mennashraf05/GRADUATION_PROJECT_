#!/usr/bin/env python3
"""Development helper for PCAP Recent Security Alerts.

This script is intended for local development/testing only. It updates or
removes rows in the pcap_alert table for a single user, without touching any
other tables or deleting reports/evidence/users/auth data.

Usage examples:
    python Backend/dev_reset_pcap_alerts.py --user-id 9 --soft-dismiss
    python Backend/dev_reset_pcap_alerts.py --user-id 9 --show-counts
    python Backend/dev_reset_pcap_alerts.py --user-id 9 --hard-delete
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

DEFAULT_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///sentinel_ai.db")


def parse_sqlite_url(database_url: str) -> Path:
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise ValueError("Only sqlite database URLs are supported by this script.")

    if parsed.path in {":memory:", "/:memory:"}:
        raise ValueError(
            "In-memory SQLite databases cannot be modified by this script."
        )

    raw_path = unquote(parsed.path or "")
    if raw_path.startswith("//") and parsed.netloc:
        raw_path = f"//{parsed.netloc}{raw_path[2:]}"
    elif raw_path.startswith("/") and not re.match(r"^/[A-Za-z]:", raw_path):
        raw_path = raw_path[1:]

    if not raw_path:
        raise ValueError("SQLite URL does not contain a valid file path.")

    path = Path(raw_path)
    if not path.is_absolute():
        base_dir = Path(__file__).resolve().parent
        path = (base_dir / path).resolve()
    return path


def get_database_path() -> Path:
    try:
        return parse_sqlite_url(DEFAULT_DATABASE_URL)
    except ValueError as exc:
        raise SystemExit(
            f"Failed to resolve database path from DATABASE_URL='{DEFAULT_DATABASE_URL}': {exc}"
        )


def is_production_environment() -> bool:
    return (
        os.getenv("FLASK_ENV", "").strip().lower() == "production"
        or os.getenv("ENV", "").strip().lower() == "production"
    )


def format_timestamp(value: object) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, (str, bytes)):
        return str(value)
    return str(value)


def query_counts(conn: sqlite3.Connection, user_id: int) -> tuple[int, int]:
    cursor = conn.execute(
        "SELECT COUNT(*) FROM pcap_alert WHERE user_id = ?", (user_id,)
    )
    total = cursor.fetchone()[0]
    cursor = conn.execute(
        "SELECT COUNT(*) FROM pcap_alert WHERE user_id = ? AND dismissed_at IS NULL",
        (user_id,),
    )
    visible = cursor.fetchone()[0]
    return total, visible


def report_counts(user_id: int, total: int, visible: int) -> None:
    print(f"user_id={user_id} | pcap_alert rows={total} | visible alerts={visible}")


def soft_dismiss_alerts(conn: sqlite3.Connection, user_id: int) -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    result = conn.execute(
        "UPDATE pcap_alert SET dismissed_at = ? WHERE user_id = ? AND dismissed_at IS NULL",
        (now, user_id),
    )
    return result.rowcount


def hard_delete_alerts(conn: sqlite3.Connection, user_id: int) -> int:
    result = conn.execute(
        "DELETE FROM pcap_alert WHERE user_id = ?",
        (user_id,),
    )
    return result.rowcount


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Development-only reset helper for PCAP Recent Security Alerts."
    )
    parser.add_argument(
        "--user-id", type=int, required=True, help="Target user_id for pcap_alert reset"
    )
    parser.add_argument(
        "--soft-dismiss",
        action="store_true",
        help="Soft-dismiss visible alerts for the target user (default action).",
    )
    parser.add_argument(
        "--hard-delete",
        action="store_true",
        help="Hard-delete pcap_alert rows for the target user. Requires explicit flag.",
    )
    parser.add_argument(
        "--show-counts",
        action="store_true",
        help="Show counts before and after without making any modifications.",
    )
    args = parser.parse_args()

    if is_production_environment():
        print("ERROR: This script is intended for local development only. Aborting.")
        return 1

    if args.hard_delete and args.soft_dismiss:
        print("ERROR: --hard-delete and --soft-dismiss cannot be used together.")
        return 1

    action = "soft_dismiss"
    if args.hard_delete:
        action = "hard_delete"
    elif args.soft_dismiss:
        action = "soft_dismiss"

    if action == "hard_delete":
        print("WARNING: This deletes only pcap_alert rows, not reports or evidence.")

    db_path = get_database_path()
    print(f"Resolved database path: {db_path}")

    if not db_path.exists():
        print(f"ERROR: Database file does not exist: {db_path}")
        return 1

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        pre_total, pre_visible = query_counts(conn, args.user_id)
        print("Counts before action:")
        report_counts(args.user_id, pre_total, pre_visible)

        if args.show_counts:
            return 0

        if action == "soft_dismiss":
            changed = soft_dismiss_alerts(conn, args.user_id)
            conn.commit()
            print(
                f"Soft-dismissed {changed} visible alert(s) for user_id={args.user_id}."
            )
        else:
            changed = hard_delete_alerts(conn, args.user_id)
            conn.commit()
            print(
                f"Hard-deleted {changed} pcap_alert row(s) for user_id={args.user_id}."
            )

        post_total, post_visible = query_counts(conn, args.user_id)
        print("Counts after action:")
        report_counts(args.user_id, post_total, post_visible)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
