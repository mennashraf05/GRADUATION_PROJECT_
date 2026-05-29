from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Index

from extensions import db

MODULE_AUTH = "auth"
MODULE_PCAP = "pcap"
MODULE_VAULT = "vault"
MODULE_AI = "ai"
MODULE_IDENTITY = "identity"
MODULE_PASSWORD = "password"
MODULE_SETTINGS = "settings"

STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_WARNING = "warning"
STATUS_INFO = "info"
STATUS_SKIPPED = "skipped"

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

AUTH_EVENT_TYPES = {
    "login_success",
    "login_failed",
    "logout",
    "password_changed",
    "profile_updated",
    "new_device_login",
    "suspicious_login_detected",
    "session_expired",
}

PCAP_EVENT_TYPES = {
    "pcap_uploaded",
    "pcap_analysis_started",
    "pcap_analysis_completed",
    "pcap_analysis_failed",
    "pcap_analysis_cancel_requested",
    "pcap_analysis_cancelled",
    "pcap_analysis_cancel_failed",
    "pcap_threat_detected",
    "pcap_safe_result_recorded",
    "pcap_report_viewed",
    "pcap_report_downloaded",
    "pcap_evidence_viewed",
    "pcap_evidence_downloaded",
    "pcap_reanalysis_started",
    "pcap_chatbot_question",
}

VAULT_EVENT_TYPES = {
    "vault_file_uploaded",
    "vault_file_encrypted",
    "vault_file_downloaded",
    "vault_file_deleted",
    "vault_access_denied",
    "vault_operation_failed",
    "vault_integrity_failed",
    "vault_integrity_verified",
    "vault_offline_enabled",
    "vault_offline_disabled",
    "vault_wrong_password",
}

AI_EVENT_TYPES = {
    "ai_vault_suspicious_behavior",
    "ai_vault_wrong_password_pattern",
    "ai_vault_mass_download_pattern",
    "ai_vault_mass_delete_pattern",
    "ai_vault_offline_risk_pattern",
    "ai_vault_behavior_safe",
}

IDENTITY_EVENT_TYPES = {
    "identity_scan_started",
    "identity_scan_completed",
    "identity_alert_generated",
    "identity_confirmed_breach_detected",
    "identity_asset_added",
    "identity_asset_deleted",
    "identity_full_asset_scan_started",
    "identity_full_asset_scan_completed",
    "identity_scan_viewed",
    "identity_report_downloaded",
    "identity_chatbot_question",
    "identity_source_skipped",
    "identity_provider_error",
    "identity_protection_rate_calculated",
}

PASSWORD_EVENT_TYPES = {
    "password_check_completed",
    "password_breach_detected",
    "weak_password_detected",
    "password_history_viewed",
    "password_history_cleared",
}

SETTINGS_EVENT_TYPES = {
    "profile_settings_updated",
    "security_settings_updated",
    "notification_setting_changed",
    "password_changed",
    "linked_account_added",
    "linked_account_updated",
    "linked_account_deleted",
    "linked_account_primary_changed",
}

VALID_ACTIVITY_EVENT_TYPES = (
    AUTH_EVENT_TYPES
    | PCAP_EVENT_TYPES
    | VAULT_EVENT_TYPES
    | AI_EVENT_TYPES
    | IDENTITY_EVENT_TYPES
    | PASSWORD_EVENT_TYPES
    | SETTINGS_EVENT_TYPES
)

VALID_ACTIVITY_MODULES = {
    MODULE_AUTH,
    MODULE_PCAP,
    MODULE_VAULT,
    MODULE_AI,
    MODULE_IDENTITY,
    MODULE_PASSWORD,
    MODULE_SETTINGS,
}

VALID_ACTIVITY_STATUSES = {
    STATUS_SUCCESS,
    STATUS_FAILED,
    STATUS_WARNING,
    STATUS_INFO,
    STATUS_SKIPPED,
}

VALID_ACTIVITY_SEVERITIES = {
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
}

PASSIVE_AUDIT_ACTION_TYPES = {
    "threat_viewed",
    "audit_trail_viewed",
    "report_viewed",
    "identity_scan_viewed",
    "evidence_viewed",
    "password_history_viewed",
    "pcap_report_viewed",
    "pcap_evidence_viewed",
}

NEVER_DEDUPE_AUDIT_ACTION_TYPES = {
    "admin_login",
    "admin_logout",
    "login_failed",
    "login_success",
    "suspicious_login_detected",
    "new_device_login",
    "user_invited",
    "user_created",
    "user_role_changed",
    "user_disabled",
    "user_deleted",
    "password_breach_detected",
    "password_check_completed",
    "vault_access_denied",
    "vault_file_uploaded",
    "vault_file_deleted",
    "identity_confirmed_breach_detected",
    "identity_scan_started",
    "identity_scan_completed",
    "pcap_uploaded",
    "pcap_analysis_started",
    "pcap_analysis_completed",
    "pcap_analysis_cancelled",
    "pcap_report_downloaded",
    "pcap_evidence_downloaded",
    "security_alert_dismissed",
    "security_alerts_cleared",
}

USER_ACTIVITY_LABELS = {
    "login_success": "Login successful",
    "login_failed": "Login attempt failed",
    "logout": "Signed out",
    "password_changed": "Password changed",
    "profile_updated": "Profile updated",
    "new_device_login": "New device sign-in detected",
    "suspicious_login_detected": "Suspicious login detected",
    "session_expired": "Session expired",

    "pcap_uploaded": "PCAP uploaded",
    "pcap_analysis_started": "PCAP analysis started",
    "pcap_analysis_completed": "PCAP analysis completed",
    "pcap_analysis_failed": "PCAP analysis failed",
    "pcap_analysis_cancel_requested": "PCAP analysis cancellation requested",
    "pcap_analysis_cancelled": "PCAP analysis cancelled",
    "pcap_analysis_cancel_failed": "PCAP analysis cancellation failed",
    "pcap_threat_detected": "Threat indicators detected",
    "pcap_safe_result_recorded": "Safe PCAP result recorded",
    "pcap_report_viewed": "PCAP report viewed",
    "pcap_report_downloaded": "PCAP report downloaded",
    "pcap_evidence_viewed": "Evidence viewed",
    "pcap_evidence_downloaded": "Evidence package downloaded",
    "pcap_reanalysis_started": "PCAP reanalysis started",
    "pcap_chatbot_question": "PCAP chatbot question asked",

    "vault_file_uploaded": "Vault file uploaded",
    "vault_file_encrypted": "Vault file encrypted",
    "vault_file_downloaded": "Vault file downloaded",
    "vault_file_deleted": "Vault file deleted",
    "vault_access_denied": "Vault access denied",
    "vault_operation_failed": "Vault operation failed",
    "vault_integrity_failed": "Vault integrity check failed",
    "vault_integrity_verified": "Vault file integrity verified",
    "vault_offline_enabled": "Vault offline access enabled",
    "vault_offline_disabled": "Vault offline access disabled",
    "vault_wrong_password": "Wrong vault password attempt",

    "ai_vault_suspicious_behavior": "AI detected suspicious vault behavior",
    "ai_vault_wrong_password_pattern": "AI detected repeated wrong vault passwords",
    "ai_vault_mass_download_pattern": "AI detected unusual vault download activity",
    "ai_vault_mass_delete_pattern": "AI detected unusual vault deletion activity",
    "ai_vault_offline_risk_pattern": "AI detected risky offline vault usage",
    "ai_vault_behavior_safe": "AI reviewed vault behavior as safe",

    "identity_scan_started": "Identity scan started",
    "identity_scan_completed": "Identity scan completed",
    "identity_alert_generated": "Identity alert generated",
    "identity_confirmed_breach_detected": "Confirmed identity breach detected",
    "identity_asset_added": "Monitored identity asset added",
    "identity_asset_deleted": "Monitored identity asset deleted",
    "identity_full_asset_scan_started": "Identity full asset scan started",
    "identity_full_asset_scan_completed": "Identity full asset scan completed",
    "identity_scan_viewed": "Identity scan viewed",
    "identity_report_downloaded": "Identity report downloaded",
    "identity_chatbot_question": "Identity chatbot question asked",
    "identity_source_skipped": "Identity source skipped",
    "identity_provider_error": "Identity provider unavailable",
    "identity_protection_rate_calculated": "Identity protection rate calculated",

    "password_check_completed": "Password check completed",
    "password_breach_detected": "Breached password detected",
    "weak_password_detected": "Weak password detected",
    "password_history_viewed": "Password history viewed",
    "password_history_cleared": "Password history cleared",
    "profile_settings_updated": "Profile settings updated",
    "security_settings_updated": "Security settings updated",
    "notification_setting_changed": "Notification setting changed",
    "linked_account_added": "Linked account added",
    "linked_account_updated": "Linked account updated",
    "linked_account_deleted": "Linked account deleted",
    "linked_account_primary_changed": "Primary linked account changed",
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def generate_event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


def safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        text_value = str(value).strip()
    except Exception:
        return default
    return text_value or default


def clamp_risk_score(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        numeric = int(round(float(value)))
    except (TypeError, ValueError):
        return None
    return max(0, min(100, numeric))


def normalize_module(value: Any) -> str:
    normalized = safe_str(value).lower()
    return normalized if normalized in VALID_ACTIVITY_MODULES else MODULE_AUTH


def normalize_action_type(value: Any) -> str:
    normalized = safe_str(value).lower()
    return normalized if normalized in VALID_ACTIVITY_EVENT_TYPES else normalized


def normalize_status(value: Any) -> str:
    normalized = safe_str(value).lower()
    return normalized if normalized in VALID_ACTIVITY_STATUSES else STATUS_INFO


def normalize_severity(value: Any) -> str:
    normalized = safe_str(value).lower()
    return normalized if normalized in VALID_ACTIVITY_SEVERITIES else SEVERITY_LOW


def should_skip_recent_passive_audit(
    actor_id: Any,
    actor_type: Any,
    module: Any,
    action_type: Any,
    within_seconds: int = 60,
    *,
    recent_record_exists: bool = False,
) -> bool:
    normalized_action = safe_str(action_type).lower()
    if normalized_action in NEVER_DEDUPE_AUDIT_ACTION_TYPES:
        return False
    if normalized_action not in PASSIVE_AUDIT_ACTION_TYPES:
        return False
    return bool(recent_record_exists)


def normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = safe_str(value).lower()
    return normalized in {"1", "true", "yes", "on"}


def serialize_metadata(metadata: Any) -> str:
    if not isinstance(metadata, dict):
        return "{}"
    try:
        return json.dumps(metadata, ensure_ascii=False)
    except Exception:
        return "{}"


def deserialize_metadata(raw_value: Any) -> dict[str, Any]:
    if not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def safe_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}

    sanitized: dict[str, Any] = {}

    for key, value in metadata.items():
        clean_key = safe_str(key)
        if not clean_key:
            continue

        if value is None:
            sanitized[clean_key] = None
        elif isinstance(value, (str, int, float, bool)):
            sanitized[clean_key] = value
        elif isinstance(value, list):
            sanitized[clean_key] = [
                item
                for item in value
                if item is None or isinstance(item, (str, int, float, bool))
            ][:50]
        elif isinstance(value, dict):
            nested = {
                safe_str(nested_key): nested_value
                for nested_key, nested_value in value.items()
                if safe_str(nested_key)
                and (
                    nested_value is None
                    or isinstance(nested_value, (str, int, float, bool))
                )
            }
            sanitized[clean_key] = nested
        else:
            sanitized[clean_key] = safe_str(value)

    return sanitized


@dataclass(slots=True)
class UserEventPayload:
    user_id: int
    module: str
    action_type: str
    title: str = ""
    description: str = ""
    status: str = STATUS_INFO
    severity: str = SEVERITY_LOW
    risk_score: int | None = None
    target_type: str | None = None
    target_id: str | None = None
    target_label: str | None = None
    ip_address: str | None = None
    session_id: str | None = None
    is_sensitive: bool = False
    is_suspicious: bool = False
    created_at: datetime | None = None
    metadata_json: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=generate_event_id)

    def normalized(self) -> "UserEventPayload":
        return UserEventPayload(
            event_id=safe_str(self.event_id) or generate_event_id(),
            user_id=int(self.user_id),
            module=normalize_module(self.module),
            action_type=normalize_action_type(self.action_type),
            title=safe_str(self.title)[:200]
            or USER_ACTIVITY_LABELS.get(
                normalize_action_type(self.action_type),
                "User activity event",
            ),
            description=safe_str(self.description),
            status=normalize_status(self.status),
            severity=normalize_severity(self.severity),
            risk_score=clamp_risk_score(self.risk_score),
            target_type=safe_str(self.target_type)[:80] or None,
            target_id=safe_str(self.target_id)[:140] or None,
            target_label=safe_str(self.target_label)[:200] or None,
            ip_address=safe_str(self.ip_address)[:64] or None,
            session_id=safe_str(self.session_id)[:140] or None,
            is_sensitive=normalize_bool(self.is_sensitive),
            is_suspicious=normalize_bool(self.is_suspicious),
            created_at=self.created_at or utc_now(),
            metadata_json=safe_metadata(self.metadata_json),
        )


class UserActivityLog(db.Model):
    __tablename__ = "user_activity_logs"
    __table_args__ = (
        Index("ix_user_activity_logs_user_id", "user_id"),
        Index("ix_user_activity_logs_module", "module"),
        Index("ix_user_activity_logs_action_type", "action_type"),
        Index("ix_user_activity_logs_status", "status"),
        Index("ix_user_activity_logs_severity", "severity"),
        Index("ix_user_activity_logs_created_at", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(40), nullable=False, unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    module = db.Column(db.String(40), nullable=False)
    action_type = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default=STATUS_INFO)
    severity = db.Column(db.String(20), nullable=False, default=SEVERITY_LOW)
    risk_score = db.Column(db.Integer, nullable=True)
    target_type = db.Column(db.String(80), nullable=True)
    target_id = db.Column(db.String(140), nullable=True)
    target_label = db.Column(db.String(200), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    session_id = db.Column(db.String(140), nullable=True)
    is_sensitive = db.Column(db.Boolean, nullable=False, default=False)
    is_suspicious = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    metadata_json = db.Column(db.Text, nullable=True)


def build_user_activity_record(payload: UserEventPayload) -> UserActivityLog:
    event = payload.normalized()

    return UserActivityLog(
        event_id=event.event_id,
        user_id=event.user_id,
        module=event.module,
        action_type=event.action_type,
        title=event.title,
        description=event.description or None,
        status=event.status,
        severity=event.severity,
        risk_score=event.risk_score,
        target_type=event.target_type,
        target_id=event.target_id,
        target_label=event.target_label,
        ip_address=event.ip_address,
        session_id=event.session_id,
        is_sensitive=event.is_sensitive,
        is_suspicious=event.is_suspicious,
        created_at=event.created_at or utc_now(),
        metadata_json=serialize_metadata(event.metadata_json),
    )


def log_user_activity(payload: UserEventPayload) -> UserActivityLog:
    record = build_user_activity_record(payload)
    db.session.add(record)
    db.session.commit()
    return record
