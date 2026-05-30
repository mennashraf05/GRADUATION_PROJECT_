import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


MONTHLY_REPORT_STATUS_PENDING = "pending"
MONTHLY_REPORT_STATUS_COMPLETED = "completed"


@dataclass(frozen=True)
class ReportingMonth:
    year: int
    month: int

    @property
    def month_key(self) -> str:
        return f"{self.year:04d}-{self.month:02d}"


def normalize_report_month(value) -> ReportingMonth | None:
    text = str(value or "").strip()
    try:
        year_text, month_text = text.split("-", 1)
        year = int(year_text)
        month = int(month_text)
    except (TypeError, ValueError):
        return None
    if not 1 <= month <= 12:
        return None
    return ReportingMonth(year=year, month=month)


def compute_current_reporting_month(now: datetime | None = None) -> ReportingMonth:
    current = now or datetime.now(UTC)
    return ReportingMonth(year=current.year, month=current.month)


def compute_reporting_month(now: datetime | None = None) -> ReportingMonth:
    current = now or datetime.now(UTC)
    if current.month == 1:
        return ReportingMonth(year=current.year - 1, month=12)
    return ReportingMonth(year=current.year, month=current.month - 1)


def _safe_len(value) -> int:
    try:
        return len(value or [])
    except TypeError:
        return 0


def _count_by_attr(items, attr_name: str) -> dict:
    counts = {}
    for item in items or []:
        value = getattr(item, attr_name, None) or "unknown"
        key = str(value).strip() or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


def _as_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _report_month_bounds(report_month: ReportingMonth) -> tuple[datetime, datetime]:
    start = datetime(report_month.year, report_month.month, 1, tzinfo=UTC)
    if report_month.month == 12:
        end = datetime(report_month.year + 1, 1, 1, tzinfo=UTC)
    else:
        end = datetime(report_month.year, report_month.month + 1, 1, tzinfo=UTC)
    return start, end


def _in_report_month(value, report_month: ReportingMonth) -> bool:
    timestamp = _as_datetime(value)
    if timestamp is None:
        return False
    start, end = _report_month_bounds(report_month)
    return start <= timestamp.astimezone(UTC) < end


def _filter_items_for_report_month(items, report_month: ReportingMonth, *attrs: str) -> list:
    filtered = []
    for item in items or []:
        for attr_name in attrs:
            if _in_report_month(getattr(item, attr_name, None), report_month):
                filtered.append(item)
                break
    return filtered


def _safe_text(value, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _vault_action_name(item) -> str:
    raw = _safe_text(
        getattr(item, "action_type", None)
        or getattr(item, "action", None)
        or getattr(item, "title", None),
        "unknown",
    ).lower()
    raw = raw.replace("-", "_").replace(" ", "_")
    mapping = {
        "vault_file_uploaded": "upload",
        "upload": "upload",
        "vault_file_encrypted": "encrypt",
        "encrypt": "encrypt",
        "encrypted": "encrypt",
        "vault_file_downloaded": "download",
        "download": "download",
        "vault_file_deleted": "delete",
        "delete": "delete",
        "vault_offline_enabled": "offline_enabled",
        "offline_enabled": "offline_enabled",
        "vault_offline_disabled": "offline_disabled",
        "offline_disabled": "offline_disabled",
        "vault_wrong_password": "wrong_password",
        "wrong_password": "wrong_password",
        "vault_access_denied": "access_denied",
        "access_denied": "access_denied",
        "vault_integrity_failed": "integrity_failed",
        "integrity_failed": "integrity_failed",
        "vault_integrity_verified": "integrity_verified",
        "integrity_verified": "integrity_verified",
        "vault_operation_failed": "operation_failed",
        "operation_failed": "operation_failed",
        "ai_vault_suspicious_behavior": "ai_suspicious_behavior",
        "ai_vault_wrong_password_pattern": "ai_wrong_password_pattern",
        "ai_vault_mass_download_pattern": "ai_mass_download_pattern",
        "ai_vault_mass_delete_pattern": "ai_mass_delete_pattern",
        "ai_vault_offline_risk_pattern": "ai_offline_risk_pattern",
        "ai_vault_behavior_safe": "ai_behavior_safe",
    }
    return mapping.get(raw, raw or "unknown")


def _count_vault_actions(items) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items or []:
        action_name = _vault_action_name(item)
        counts[action_name] = counts.get(action_name, 0) + 1
    return counts


def _is_vault_activity(item) -> bool:
    module = _safe_text(getattr(item, "module", None)).lower().replace("-", "_").replace(" ", "_")
    action = _safe_text(getattr(item, "action_type", None) or getattr(item, "action", None)).lower()
    return module in {"vault", "file_vault", "encrypted_file_vault"} or action.startswith("vault_") or action.startswith("ai_vault_")


def _first_present(*values, default=0):
    for value in values:
        if value is not None:
            return value
    return default


def build_monthly_security_report_data(
    *,
    user,
    report_month: ReportingMonth,
    pcap_alert_query=None,
    list_recent_jobs=None,
    load_report_payload_for_job=None,
    activity_log_query=None,
    password_check_query=None,
) -> dict:
    user_id = int(getattr(user, "id", 0) or 0)
    pcap_alerts = _filter_items_for_report_month(
        list(pcap_alert_query(user_id) if callable(pcap_alert_query) else []),
        report_month,
        "event_at",
        "created_at",
    )
    activity_logs = _filter_items_for_report_month(
        list(activity_log_query(user_id) if callable(activity_log_query) else []),
        report_month,
        "created_at",
    )
    password_checks = _filter_items_for_report_month(
        list(password_check_query(user_id) if callable(password_check_query) else []),
        report_month,
        "created_at",
        "checked_at",
    )
    vault_logs = [item for item in activity_logs if _is_vault_activity(item)]
    recent_jobs = list(list_recent_jobs() if callable(list_recent_jobs) else [])
    severity_counts = _count_by_attr(pcap_alerts, "severity")
    vault_action_counts = _count_vault_actions(vault_logs)
    vault_file_counts: dict[str, int] = {}
    vault_wrong_password_file_counts: dict[str, int] = {}
    for item in vault_logs:
        target_label = _safe_text(getattr(item, "target_label", None))
        if target_label:
            vault_file_counts[target_label] = vault_file_counts.get(target_label, 0) + 1
            if _vault_action_name(item) == "wrong_password":
                vault_wrong_password_file_counts[target_label] = vault_wrong_password_file_counts.get(target_label, 0) + 1
    weak_password_checks = [
        item
        for item in password_checks
        if str(getattr(item, "strength_label", "") or getattr(item, "risk_level", "")).lower()
        in {"weak", "high", "critical", "poor"}
    ]
    breached_password_checks = [
        item for item in password_checks if bool(getattr(item, "breached", False))
    ]
    pcap_recommendations = []
    if pcap_alerts:
        pcap_recommendations.append("Review high severity packet capture alerts and isolate suspicious hosts.")
    else:
        pcap_recommendations.append("No PCAP threats were recorded for this reporting month.")

    vault_recommendations = []
    if vault_logs:
        vault_recommendations.append("Review vault activity and confirm unusual file access patterns.")
    else:
        vault_recommendations.append("No vault activity was recorded for this reporting month.")

    password_recommendations = []
    if weak_password_checks or breached_password_checks:
        password_recommendations.append("Rotate weak or breached passwords and enable MFA where possible.")
    else:
        password_recommendations.append("No risky password checks were recorded for this reporting month.")

    return {
        "report_month": report_month.month_key,
        "generated_at": datetime.now(UTC).isoformat(),
        "user": {
            "id": user_id,
            "email": getattr(user, "email", None),
            "username": getattr(user, "username", None),
        },
        "summary": {
            "pcap_alerts": _safe_len(pcap_alerts),
            "activity_events": _safe_len(activity_logs),
            "password_checks": _safe_len(password_checks),
            "recent_jobs": _safe_len(recent_jobs),
        },
        "executive_summary": [
            f"{_safe_len(pcap_alerts)} PCAP alerts reviewed for this month.",
            f"{_safe_len(vault_logs)} file vault events recorded.",
            f"{_safe_len(password_checks)} password checks included in the security snapshot.",
        ],
        "sections": {
            "pcap": {
                "files_analyzed": _safe_len(recent_jobs),
                "threats_detected": _safe_len(pcap_alerts),
                "high_alerts": severity_counts.get("high", 0),
                "critical_alerts": severity_counts.get("critical", 0),
                "score_change": None,
                "top_threat_types": [
                    {"name": name, "count": count}
                    for name, count in sorted(severity_counts.items(), key=lambda item: item[1], reverse=True)[:6]
                ],
                "recommendations": pcap_recommendations,
            },
            "vault": {
                "uploads": vault_action_counts.get("upload", 0),
                "downloads": vault_action_counts.get("download", 0),
                "deletes": vault_action_counts.get("delete", 0),
                "offline_enabled": vault_action_counts.get("offline_enabled", 0),
                "offline_disabled": vault_action_counts.get("offline_disabled", 0),
                "wrong_password": vault_action_counts.get("wrong_password", 0),
                "total_events": _safe_len(vault_logs),
                "unique_files": len(vault_file_counts),
                "total_storage_bytes": 0,
                "largest_file": None,
                "largest_file_size_bytes": 0,
                "most_active_file": (
                    {
                        "filename": max(vault_file_counts.items(), key=lambda item: item[1])[0],
                        "activity_count": max(vault_file_counts.values()),
                    }
                    if vault_file_counts
                    else None
                ),
                "most_failed_file": (
                    {
                        "filename": max(vault_wrong_password_file_counts.items(), key=lambda item: item[1])[0],
                        "wrong_password_attempts": max(vault_wrong_password_file_counts.values()),
                    }
                    if vault_wrong_password_file_counts
                    else None
                ),
                "action_breakdown": [
                    {"name": name, "count": count}
                    for name, count in sorted(vault_action_counts.items(), key=lambda item: item[1], reverse=True)[:8]
                ],
                "recommendations": vault_recommendations,
            },
            "identity": {
                "total_identity_scans": 0,
                "total_findings": 0,
                "total_alerts": 0,
                "monitored_assets_count": 0,
                "risky_assets_count": 0,
                "confirmed_breach_count": 0,
                "confirmed_exposure_count": 0,
                "possible_exposure_count": 0,
                "public_mention_count": 0,
                "high_risk_scans": 0,
                "critical_risk_scans": 0,
                "leakcheck_confirmed_breaches": 0,
                "source_coverage": {},
                "risk_summary": {},
                "category_summary": {},
                "recent_alerts": [],
                "recent_high_risk_scans": [],
                "recommendations": ["Run identity scans to enrich future monthly reports."],
            },
        },
        "password_checker_summary": {
            "status": "Assessed" if password_checks else "Not Assessed",
            "current_score": None,
            "risk_level": "High" if weak_password_checks or breached_password_checks else "Low",
            "last_checked_at": str(getattr(password_checks[0], "created_at", "")) if password_checks else None,
            "total_checks": _safe_len(password_checks),
            "safe_checks": max(_safe_len(password_checks) - _safe_len(weak_password_checks) - _safe_len(breached_password_checks), 0),
            "weak_checks": _safe_len(weak_password_checks),
            "breached_checks": _safe_len(breached_password_checks),
            "reused_checks": None,
            "latest_checks": [
                {
                    "checked_at": str(getattr(item, "created_at", "") or getattr(item, "checked_at", "")),
                    "masked_password": "********",
                    "strength_label": getattr(item, "strength_label", None),
                    "risk_level": getattr(item, "risk_level", None),
                    "breached": bool(getattr(item, "breached", False)),
                    "recommendation": getattr(item, "recommendation", None),
                }
                for item in password_checks[:5]
            ],
            "recommendations": password_recommendations,
        },
        "pcap_alerts": [
            {
                "title": getattr(item, "title", ""),
                "severity": getattr(item, "severity", ""),
                "created_at": str(getattr(item, "created_at", "")),
            }
            for item in pcap_alerts[:20]
        ],
    }


def build_monthly_security_report_summary(payload: dict, report_record=None) -> dict:
    payload = payload if isinstance(payload, dict) else {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    sections = payload.get("sections") if isinstance(payload.get("sections"), dict) else {}
    pcap = sections.get("pcap") if isinstance(sections.get("pcap"), dict) else {}
    vault = sections.get("vault") if isinstance(sections.get("vault"), dict) else {}
    identity = sections.get("identity") if isinstance(sections.get("identity"), dict) else {}
    report_month = payload.get("report_month") or getattr(report_record, "report_month", None)
    pdf_path = getattr(report_record, "pdf_path", None)
    available_sections = [
        section_name
        for section_name, section_value in sections.items()
        if isinstance(section_value, dict) and section_value
    ]
    return {
        "id": getattr(report_record, "id", None),
        "report_month": report_month,
        "status": getattr(report_record, "status", MONTHLY_REPORT_STATUS_COMPLETED),
        "pdf_path": pdf_path,
        "pdf_available": bool(pdf_path),
        "generated_at": payload.get("generated_at") or str(getattr(report_record, "created_at", "")),
        "available_sections": available_sections,
        "available_section_count": len(available_sections),
        "latest_pcap_threat_count": int(_first_present(pcap.get("threats_detected"), summary.get("pcap_alerts")) or 0),
        "latest_pcap_score_change": pcap.get("score_change"),
        "latest_vault_event_count": int(_first_present(vault.get("total_events"), summary.get("activity_events")) or 0),
        "latest_vault_wrong_password_count": int(vault.get("wrong_password") or 0),
        "latest_identity_scan_count": int(identity.get("total_identity_scans") or 0),
        "latest_identity_alert_count": int(identity.get("total_alerts") or 0),
        "latest_identity_confirmed_breach_count": int(identity.get("confirmed_breach_count") or 0),
        "latest_identity_risky_asset_count": int(identity.get("risky_assets_count") or 0),
        "summary": summary,
    }


def render_monthly_security_report_pdf(payload: dict, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    pdf = canvas.Canvas(str(output_path), pagesize=letter)
    width, height = letter
    y = height - 72
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(72, y, "Sentinel AI Monthly Security Report")
    y -= 32
    pdf.setFont("Helvetica", 11)
    pdf.drawString(72, y, f"Month: {payload.get('report_month', '')}")
    y -= 20
    pdf.drawString(72, y, f"Generated: {payload.get('generated_at', '')}")
    y -= 32
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    for key, value in summary.items():
        pdf.drawString(72, y, f"{key.replace('_', ' ').title()}: {value}")
        y -= 18
    pdf.showPage()
    pdf.save()
    return output_path


def generate_and_store_monthly_security_report(
    *,
    user,
    report_month,
    base_dir,
    monthly_report_model,
    db_session,
    pcap_alert_query=None,
    list_recent_jobs=None,
    load_report_payload_for_job=None,
    render_pdf=None,
    create_notification=None,
    activity_log_query=None,
    password_check_query=None,
) :
    normalized = report_month if isinstance(report_month, ReportingMonth) else normalize_report_month(report_month)
    if normalized is None:
        raise ValueError("Invalid report month")

    payload = build_monthly_security_report_data(
        user=user,
        report_month=normalized,
        pcap_alert_query=pcap_alert_query,
        list_recent_jobs=list_recent_jobs,
        load_report_payload_for_job=load_report_payload_for_job,
        activity_log_query=activity_log_query,
        password_check_query=password_check_query,
    )

    output_path = Path(base_dir) / "reports" / "monthly" / f"sentinel-monthly-security-report-{normalized.month_key}.pdf"
    if callable(render_pdf):
        render_pdf(payload, output_path)

    record = (
        monthly_report_model.query.filter_by(
            user_id=int(getattr(user, "id")),
            report_month=normalized.month_key,
        ).first()
    )
    if record is None:
        record = monthly_report_model(
            user_id=int(getattr(user, "id")),
            report_month=normalized.month_key,
            report_year=normalized.year,
        )
        db_session.add(record)

    record.report_payload_json = json.dumps(payload, default=str)
    record.pdf_path = str(output_path)
    record.status = MONTHLY_REPORT_STATUS_COMPLETED
    db_session.commit()

    if callable(create_notification):
        create_notification(
            getattr(user, "id"),
            "report_ready",
            "Monthly security report ready",
            f"Your {normalized.month_key} security report is ready.",
            metadata={"module": "reports", "report_month": normalized.month_key},
        )

    return record


def run_monthly_security_reports(
    *,
    users,
    target_year=None,
    target_month=None,
    **kwargs,
) -> list:
    if target_year and target_month:
        report_month = ReportingMonth(year=int(target_year), month=int(target_month))
    else:
        report_month = compute_reporting_month()

    return [
        generate_and_store_monthly_security_report(user=user, report_month=report_month, **kwargs)
        for user in users
    ]
