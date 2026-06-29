import logging
import sys
from datetime import UTC, datetime

from flask import jsonify, request

from . import password_checker_bp
from .hibp_client import check_pwned_password


FIXED_PASSWORD_MASK = "********"


def _app_module():
    module = sys.modules.get("app") or sys.modules.get("__main__")
    if module is None:
        raise RuntimeError("Application module is not loaded.")
    return module


def _current_user_or_401():
    user = _app_module().get_current_user()
    if not user:
        return None, (jsonify({"status": "error", "message": "Unauthorized"}), 401)
    return user, None


def _password_strength(password: str) -> tuple[str, int]:
    checks = [
        bool(password[:1].isupper()),
        len(password) >= 8,
        any(ch.islower() for ch in password),
        any(ch.isdigit() for ch in password),
        any(ch in "!@#$%^&*()_-+=[]{};':\"\\|,.<>/?`~" for ch in password),
    ]
    score = sum(1 for ok in checks if ok)

    if score >= 4 and len(password) >= 12:
        return "Strong", score
    if score >= 3:
        return "Medium", score
    if score >= 2:
        return "Weak", score
    return "Very weak", score


def _serialize_password_check(record) -> dict[str, object]:
    created_at = getattr(record, "created_at", None)
    if created_at is not None:
        try:
            checked_at = created_at.strftime("%Y-%m-%d %H:%M")
        except Exception:
            checked_at = str(created_at)
    else:
        checked_at = ""

    breach_count = int(getattr(record, "breach_count", 0) or 0)
    verdict = str(getattr(record, "verdict", "") or "").strip().lower()

    return {
        "id": int(getattr(record, "id", 0) or 0),
        "masked_password": FIXED_PASSWORD_MASK,
        "password": FIXED_PASSWORD_MASK,
        "strength_label": getattr(record, "strength_label", None),
        "score": getattr(record, "score", None),
        "breach_count": breach_count,
        "breaches": breach_count,
        "verdict": verdict,
        "status": "breached" if verdict == "breached" or breach_count > 0 else "safe",
        "checked_at": checked_at,
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else checked_at,
    }


def _password_activity_risk_level(*, breached: bool, strength_label: str, score: int) -> str:
    if breached:
        return "critical"
    normalized_strength = str(strength_label or "").strip().lower()
    if normalized_strength == "very weak" or score <= 1:
        return "high"
    if normalized_strength == "weak" or score <= 2:
        return "medium"
    return "low"


def _log_password_activity(user, action_type: str, *, title: str, description: str, metadata: dict | None = None, severity: str = "low", risk_score: int | None = None, target_id: str | None = None) -> None:
    try:
        app_module = _app_module()
        log_user_event = getattr(app_module, "log_user_event", None)
        if not callable(log_user_event):
            return
        log_user_event(
            user_id=int(user.id),
            module="password",
            action_type=action_type,
            title=title,
            description=description,
            status=getattr(app_module, "STATUS_SUCCESS", "success"),
            severity=severity,
            risk_score=risk_score,
            target_type="password_check" if target_id else "password_history",
            target_id=target_id,
            target_label="Password Checker",
            is_sensitive=True,
            is_suspicious=severity in {"high", "critical"},
            metadata_json=metadata or {},
            commit=True,
        )
    except Exception:
        try:
            _app_module().db.session.rollback()
        except Exception:
            pass
        logging.exception("Failed to record Password Checker activity safely")


def _log_password_check_activity(user, record, *, breached: bool, strength_label: str, score: int, breach_count: int) -> None:
    password_check_id = int(getattr(record, "id", 0) or 0)
    risk_level = _password_activity_risk_level(
        breached=breached,
        strength_label=strength_label,
        score=score,
    )
    metadata = {
        "risk_level": risk_level,
        "strength_label": strength_label,
        "breached": bool(breached),
        "breach_count": int(breach_count or 0),
        "score": int(score or 0),
        "password_check_id": password_check_id,
    }

    if breached:
        _log_password_activity(
            user,
            "password_breach_detected",
            title="Breached password detected",
            description="A password check found breach exposure. The raw password was not logged.",
            severity="critical",
            risk_score=100,
            target_id=str(password_check_id) if password_check_id else None,
            metadata=metadata,
        )
        return

    if risk_level in {"high", "medium"}:
        _log_password_activity(
            user,
            "weak_password_detected",
            title="Weak password detected",
            description="A password check detected weak password hygiene. The raw password was not logged.",
            severity="high" if risk_level == "high" else "medium",
            risk_score=80 if risk_level == "high" else 50,
            target_id=str(password_check_id) if password_check_id else None,
            metadata=metadata,
        )
        return

    _log_password_activity(
        user,
        "password_check_completed",
        title="Password check completed",
        description="Password check completed safely. The raw password was not logged.",
        severity="low",
        risk_score=10,
        target_id=str(password_check_id) if password_check_id else None,
        metadata=metadata,
    )


@password_checker_bp.route("/check", methods=["POST"])
def check_password():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password") or "")

    if not password:
        return jsonify({"status": "error", "message": "Password is required."}), 400

    user, unauthorized = _current_user_or_401()
    if unauthorized:
        return unauthorized

    count = check_pwned_password(password)
    if count == -1:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Password check service is temporarily unavailable.",
                }
            ),
            503,
        )

    strength_label, score = _password_strength(password)
    verdict = "breached" if count > 0 else "safe"

    try:
        app_module = _app_module()
        PasswordCheck = app_module.PasswordCheck
        db = app_module.db
        created_notifications = []

        record = PasswordCheck(
            user_id=int(user.id),
            masked_password=FIXED_PASSWORD_MASK,
            strength_label=strength_label,
            score=score,
            breach_count=int(count),
            verdict=verdict,
            created_at=datetime.now(UTC),
        )
        db.session.add(record)
        db.session.commit()

        notify_password_check = getattr(app_module, "process_password_check_notifications", None)
        if callable(notify_password_check):
            try:
                created_notifications = notify_password_check(user, record) or []
            except Exception:
                logging.exception("Failed to create password security notification")

        create_password_alert = getattr(app_module, "create_password_checker_security_alert", None)
        password_security_alert = None
        if callable(create_password_alert):
            try:
                password_security_alert = create_password_alert(user, record)
            except Exception:
                logging.exception("Failed to create password checker security alert")

        _log_password_check_activity(
            user,
            record,
            breached=count > 0,
            strength_label=strength_label,
            score=score,
            breach_count=int(count),
        )

        history_item = _serialize_password_check(record)
    except Exception:
        db = _app_module().db

        db.session.rollback()
        logging.exception("Failed to save password check metadata")
        return jsonify({"status": "error", "message": "Could not save password check history."}), 500

    is_risky_password = bool(count > 0 or score <= 1)
    email_alert_sent = any(
        bool(getattr(notification, "_email_side_effect_sent", False))
        for notification in created_notifications
    )
    admin_email_alert_sent = bool(getattr(password_security_alert, "_admin_email_alert_sent", False))
    admin_email_alert_reason = str(
        getattr(password_security_alert, "_admin_email_alert_reason", "")
        or ("safe_or_not_high_risk" if not is_risky_password else "admin_alert_not_attempted")
    )
    email_alert_reason = "safe_password_no_email"
    if is_risky_password:
        if email_alert_sent:
            email_alert_reason = "sent"
        elif created_notifications:
            email_alert_reason = str(
                getattr(
                    created_notifications[0],
                    "_email_side_effect_reason",
                    "email_not_sent",
                )
            )
        else:
            email_alert_reason = "notification_not_created"

    return (
        jsonify(
            {
                "status": "ok",
                "pwned": count > 0,
                "count": count,
                "strength_label": strength_label,
                "score": score,
                "history_item": history_item,
                "email_alert_sent": email_alert_sent,
                "email_alert_reason": email_alert_reason,
                "admin_email_alert_sent": admin_email_alert_sent,
                "admin_email_alert_reason": admin_email_alert_reason,
            }
        ),
        200,
    )


@password_checker_bp.route("/history", methods=["GET"])
def get_user_password_history():
    user, unauthorized = _current_user_or_401()
    if unauthorized:
        return unauthorized

    try:
        PasswordCheck = _app_module().PasswordCheck

        records = (
            PasswordCheck.query.filter_by(user_id=int(user.id))
            .order_by(PasswordCheck.created_at.desc(), PasswordCheck.id.desc())
            .limit(50)
            .all()
        )
        _log_password_activity(
            user,
            "password_history_viewed",
            title="Password history viewed",
            description="Password Checker history was viewed.",
            severity="low",
            metadata={"returned_count": len(records)},
        )
    except Exception:
        logging.exception("Failed to load password check history")
        return jsonify({"status": "error", "message": "Could not load password check history."}), 500

    return jsonify({"status": "ok", "history": [_serialize_password_check(r) for r in records]}), 200


@password_checker_bp.route("/history", methods=["DELETE"])
@password_checker_bp.route("/history/clear", methods=["POST", "DELETE"])
def clear_user_password_history():
    user, unauthorized = _current_user_or_401()
    if unauthorized:
        return unauthorized

    try:
        app_module = _app_module()
        PasswordCheck = app_module.PasswordCheck
        db = app_module.db

        deleted = PasswordCheck.query.filter_by(user_id=int(user.id)).delete()
        db.session.commit()
        _log_password_activity(
            user,
            "password_history_cleared",
            title="Password history cleared",
            description="Password Checker history was cleared.",
            severity="medium" if int(deleted or 0) else "low",
            metadata={"deleted_count": int(deleted or 0)},
        )
    except Exception:
        db = _app_module().db

        db.session.rollback()
        logging.exception("Failed to clear password check history")
        return jsonify({"status": "error", "message": "Could not clear password check history."}), 500

    return jsonify({"status": "ok", "deleted": int(deleted or 0)}), 200
