from __future__ import annotations

import json
import math
from datetime import UTC, date, datetime, time, timedelta
from typing import Any


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return float(default)
    if math.isnan(numeric) or math.isinf(numeric):
        return float(default)
    return numeric


def safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def serialize_datetime(value: datetime | None) -> str | None:
    normalized = ensure_utc(value)
    return normalized.isoformat() if normalized is not None else None


def parse_metadata(raw_value: str | None) -> dict[str, Any]:
    if not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def serialize_metadata(value: dict[str, Any] | None) -> str:
    if not value:
        return "{}"
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return "{}"


def current_daily_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    current = ensure_utc(now) or utc_now()
    start = datetime.combine(current.date(), time.min, tzinfo=UTC)
    end = start + timedelta(days=1)
    return start, end


def current_weekly_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    current = ensure_utc(now) or utc_now()
    week_start_date = current.date() - timedelta(days=current.weekday())
    start = datetime.combine(week_start_date, time.min, tzinfo=UTC)
    end = start + timedelta(days=7)
    return start, end


def activity_date(now: datetime | None = None) -> date:
    current = ensure_utc(now) or utc_now()
    return current.date()


def build_event_key(*parts: Any) -> str:
    normalized = [safe_str(part) for part in parts]
    return ":".join(part for part in normalized if part != "")


def report_summary(report: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {}
    summary = report.get("summary")
    return summary if isinstance(summary, dict) else {}


def report_alerts(report: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return []
    alerts = report.get("alerts")
    if not isinstance(alerts, list):
        return []
    return [item for item in alerts if isinstance(item, dict)]


def extract_report_metrics(report: dict[str, Any] | None) -> dict[str, Any]:
    summary = report_summary(report)
    alerts = report_alerts(report)

    critical_count = 0
    high_count = 0
    for alert in alerts:
        severity = safe_str(alert.get("severity")).lower()
        if severity == "critical":
            critical_count += 1
        elif severity == "high":
            high_count += 1

    severity_counts = summary.get("severity_counts")
    if isinstance(severity_counts, dict):
        critical_count = max(critical_count, safe_int(severity_counts.get("critical"), critical_count))
        high_count = max(high_count, safe_int(severity_counts.get("high"), high_count))

    return {
        "security_score": safe_float(summary.get("security_score"), default=-1.0),
        "critical_alert_count": critical_count,
        "high_alert_count": high_count,
        "alerts_count": safe_int(summary.get("alerts_count"), len(alerts)),
        "risk_level": safe_str(summary.get("risk_level"), "Normal") or "Normal",
    }


def compact_message(value: str, limit: int = 200) -> str:
    text = safe_str(value)
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)].rstrip() + "..."
