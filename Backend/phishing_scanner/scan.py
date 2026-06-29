#scan.py
from flask import Blueprint, request, jsonify, current_app
from phishing_scanner.ml import predict_url
from phishing_scanner.risk import calculate_risk, category_from_score, get_user_guidance
from phishing_scanner.database import save_scan, get_user_scans, delete_scan
from phishing_scanner.virustotal import extract_domain_from_url, get_domain_reputation
from urllib.parse import urlparse
from extensions import db
from activity_logs import UserActivityLog
from datetime import UTC, datetime

scan_bp = Blueprint("scan_bp", __name__, url_prefix="/api/v1")

INVALID_URL_RESPONSE = {
    "success": False,
    "message": "Please enter a valid URL, for example https://github.com",
}

def _phishing_notification_severity(final_category):
    if final_category == "dangerous":
        return "critical"
    if final_category == "suspicious":
        return "warning"
    return "info"


def _phishing_notification_message(final_category):
    if final_category == "dangerous":
        return "Dangerous phishing risk detected. Do not open this URL."
    if final_category == "suspicious":
        return "The scanned URL looks suspicious. Review before opening."
    return "The scanned URL appears safe."


def _phishing_notification_title(final_category):
    if final_category == "dangerous":
        return "Dangerous Phishing Risk Detected"
    if final_category == "suspicious":
        return "Suspicious URL Detected"
    return "URL Scan Completed"


def _phishing_ml_probability_text(ml_result):
    try:
        return f"{float((ml_result or {}).get('probability') or 0) * 100:.2f}%"
    except (TypeError, ValueError):
        return "Unavailable"


def _phishing_email_required(final_category, final_risk_score):
    try:
        score = int(final_risk_score)
    except (TypeError, ValueError):
        score = 0
    return final_category in {"suspicious", "dangerous"} or score >= 50


def _phishing_email_skip_reason(email_required, notification_created, notification):
    if not email_required:
        return "safe_scan_no_email"
    if not notification_created:
        return "notification_not_created"
    return getattr(notification, "_email_side_effect_reason", "email_not_sent")


def _build_phishing_notification_body(url, domain, final_data, ml_result, virustotal_data):
    return _phishing_notification_message(final_data["final_category"])


def _build_phishing_notification_metadata(url, domain, final_data, ml_result, virustotal_data, scan_id):
    return {
        "source_module": "Phishing Scanner",
        "module": "Phishing Scanner",
        "module_key": "phishing",
        "scan_id": scan_id,
        "action_url": "/phishing-scanner",
        "url": url,
        "domain": domain,
        "final_category": final_data["final_category"],
        "final_risk_score": final_data["final_risk_score"],
        "ml_probability": (ml_result or {}).get("probability"),
        "virustotal_reputation": (virustotal_data or {}).get("reputation"),
        "virustotal_malicious": int((virustotal_data or {}).get("malicious") or 0),
        "virustotal_suspicious": int((virustotal_data or {}).get("suspicious") or 0),
    }


def combine_ml_and_virustotal(risk_data, virustotal_data):
    ml_score = int(risk_data["risk_score"])
    final_score = ml_score
    malicious_detected = False
    suspicious_detected = False

    if virustotal_data.get("available"):
        malicious = int(virustotal_data.get("malicious") or 0)
        suspicious = int(virustotal_data.get("suspicious") or 0)
        malicious_detected = malicious > 0
        suspicious_detected = suspicious > 0

        if malicious_detected:
            vt_boost = min(15, 5 + malicious * 2 + suspicious)
            final_score = min(100, max(ml_score + vt_boost, 85))
        elif suspicious_detected:
            vt_boost = min(10, suspicious * 3)
            final_score = min(100, max(ml_score + vt_boost, 50))

    final_score = min(max(final_score, ml_score), 100)
    final_category = category_from_score(final_score)

    if malicious_detected:
        final_category = "dangerous"
    elif suspicious_detected and final_category == "safe":
        final_category = "suspicious"

    return {
        "final_category": final_category,
        "final_risk_score": final_score,
        "final_guidance": get_user_guidance(final_category),
    }


def _record_phishing_gamification(user, scan_id, url, domain, final_data):
    try:
        gamification_service = current_app.extensions.get("gamification_service")
        if gamification_service is None:
            current_app.logger.warning(
                "[PhishingScanner] gamification skipped because gamification_service is not registered | user_id=%s scan_id=%s",
                getattr(user, "id", None),
                scan_id,
            )
            return None

        result = gamification_service.record_phishing_scan_completion(
            int(user.id),
            int(scan_id),
            url=url,
            domain=domain,
            final_category=final_data["final_category"],
            final_risk_score=final_data["final_risk_score"],
        )
        current_app.logger.info(
            "[PhishingScanner] gamification recorded | user_id=%s scan_id=%s result=%s",
            getattr(user, "id", None),
            scan_id,
            result,
        )
        return result
    except Exception:
        current_app.logger.exception(
            "[PhishingScanner] gamification failed safely | user_id=%s scan_id=%s",
            getattr(user, "id", None),
            scan_id,
        )
        return None


def _phishing_activity_context(final_category):
    category = str(final_category or "").strip().lower()
    if category == "dangerous":
        return {
            "action_type": "phishing_dangerous_url_detected",
            "title": "Dangerous phishing URL detected",
            "description": "A phishing scan detected a dangerous URL. The user should not open it.",
            "status": "warning",
            "severity": "high",
            "is_suspicious": True,
            "event_suffix": "dangerous",
        }
    if category == "suspicious":
        return {
            "action_type": "phishing_suspicious_url_detected",
            "title": "Suspicious phishing URL detected",
            "description": "A phishing scan found a suspicious URL that should be reviewed before opening.",
            "status": "warning",
            "severity": "medium",
            "is_suspicious": True,
            "event_suffix": "suspicious",
        }
    return {
        "action_type": "phishing_scan_completed",
        "title": "Phishing URL scan completed",
        "description": "A phishing URL scan completed and the scanned URL appears safe.",
        "status": "success",
        "severity": "low",
        "is_suspicious": False,
        "event_suffix": "completed",
    }


def _record_phishing_activity(user, scan_id, url, domain, final_data, ml_result, virustotal_data):
    user_id = getattr(user, "id", None)
    if not user_id or not scan_id:
        return False, "missing_user_or_scan_id"

    log_user_event = current_app.extensions.get("log_user_event")
    if not callable(log_user_event):
        return False, "activity_helper_unavailable"

    context = _phishing_activity_context(final_data.get("final_category"))
    final_risk_score = final_data.get("final_risk_score")
    event_id = f"phishing-audit:{int(user_id)}:{int(scan_id)}:{context['event_suffix']}"
    try:
        existing = UserActivityLog.query.filter(
            UserActivityLog.user_id == int(user_id),
            UserActivityLog.module == "phishing",
            UserActivityLog.target_type == "phishing_scan",
            UserActivityLog.target_id == str(scan_id),
            UserActivityLog.action_type.in_(
                [
                    context["action_type"],
                    "phishing_suspicious_url_reviewed",
                ]
            ),
        ).first()
        if existing is not None:
            return False, "duplicate_event"

        log_user_event(
            user_id=int(user_id),
            module="phishing",
            action_type=context["action_type"],
            title=context["title"],
            description=context["description"],
            status=context["status"],
            severity=context["severity"],
            risk_score=final_risk_score,
            target_type="phishing_scan",
            target_id=str(scan_id),
            target_label="Phishing",
            is_sensitive=False,
            is_suspicious=context["is_suspicious"],
            metadata_json={
                "module": "Phishing Scanner",
                "scan_id": scan_id,
                "url": url,
                "domain": domain,
                "final_category": final_data.get("final_category"),
                "final_risk_score": final_risk_score,
                "ml_probability": (ml_result or {}).get("probability"),
                "virustotal_malicious": int((virustotal_data or {}).get("malicious") or 0),
                "virustotal_suspicious": int((virustotal_data or {}).get("suspicious") or 0),
                "timestamp": datetime.now(UTC).isoformat(),
            },
            event_id=event_id,
            commit=True,
        )
        return True, "logged"
    except Exception as exc:
        db.session.rollback()
        message = str(exc).lower()
        if "unique" in message or "integrity" in message:
            return False, "duplicate_event"
        current_app.logger.exception(
            "[PhishingScanner] activity logging failed safely | user_id=%s scan_id=%s",
            user_id,
            scan_id,
        )
        return False, "activity_logging_exception"


@scan_bp.route("/scan-url", methods=["POST"])
def scan_url():
    current_app.logger.warning("[phishing-integration] route_hit=true")
    get_current_user = current_app.extensions["get_current_user"]
    user = get_current_user()

    if not user:
        current_app.logger.warning(
            "[phishing-integration] user_id_exists=false user_email_exists=false notification_created=false notification_reason=not_authenticated recent_alert_created=false email_trigger_passed=false email_helper_called=false email_alert_sent=false email_alert_reason=not_authenticated"
        )
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify(INVALID_URL_RESPONSE), 400

    url = data.get("url", "").strip()
    if not url:
        return jsonify(INVALID_URL_RESPONSE), 400
    
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return jsonify(INVALID_URL_RESPONSE), 400

    if parsed.scheme not in ("http", "https"):
        return jsonify(INVALID_URL_RESPONSE), 400


    # 🔹 ML Prediction
    ml_result = predict_url(url)

    # 🔹 Risk Score
    risk_data = calculate_risk(ml_result)

    # 🔹 Guidance
    guidance = get_user_guidance(risk_data["category"])
    domain = extract_domain_from_url(url)
    try:
        virustotal_data = get_domain_reputation(url)
    except Exception:
        virustotal_data = {
            "available": False,
            "domain": domain,
            "source": "virustotal",
            "reputation": "unavailable",
            "message": "VirusTotal reputation is currently unavailable",
        }
    final_data = combine_ml_and_virustotal(risk_data, virustotal_data)

    scan_id = save_scan(
        user_id=user.id,
        url=url,
        risk=final_data["final_risk_score"],
        result=final_data["final_category"]
    )
    notification_created = False
    notification_reason = "not_attempted"
    recent_alert_created = False
    recent_alert_source_type = ""
    admin_email_alert_sent = False
    admin_email_alert_reason = "safe_or_not_high_risk"
    email_alert_sent = False
    activity_logged = False
    activity_log_reason = "not_attempted"
    email_required = _phishing_email_required(final_data["final_category"], final_data["final_risk_score"])
    email_alert_reason = "safe_scan_no_email" if not email_required else "email_not_attempted"
    email_helper_called = False
    gamification_result = _record_phishing_gamification(user, scan_id, url, domain, final_data)
    notification_metadata = _build_phishing_notification_metadata(
        url,
        domain,
        final_data,
        ml_result,
        virustotal_data,
        scan_id,
    )

    activity_logged, activity_log_reason = _record_phishing_activity(
        user,
        scan_id,
        url,
        domain,
        final_data,
        ml_result,
        virustotal_data,
    )

    current_app.logger.warning(
        "[PhishingScanner] email trigger evaluated | user_id=%s category=%s score=%s trigger=%s user_email_exists=%s",
        getattr(user, "id", None),
        final_data["final_category"],
        final_data["final_risk_score"],
        bool(email_required),
        bool(str(getattr(user, "email", "") or "").strip()),
    )

    try:
        create_notification = current_app.extensions.get("create_phishing_scan_notification")
        if callable(create_notification):
            notification = create_notification(
                user.id,
                title=_phishing_notification_title(final_data["final_category"]),
                body=_build_phishing_notification_body(url, domain, final_data, ml_result, virustotal_data),
                severity=_phishing_notification_severity(final_data["final_category"]),
                job_id=f"phishing-scan-{scan_id}",
                metadata=notification_metadata,
                send_email_side_effect=email_required,
            )
            notification_created = bool(notification)
            notification_reason = "created" if notification_created else "helper_returned_none"
            email_alert_sent = bool(getattr(notification, "_email_side_effect_sent", False))
            email_alert_reason = (
                "sent"
                if email_alert_sent
                else _phishing_email_skip_reason(email_required, notification_created, notification)
            )
            current_app.logger.warning(
                "[PhishingScanner] notification helper called | user_id=%s scan_id=%s notification_created=%s email_required=%s email_sent=%s reason=%s",
                getattr(user, "id", None),
                scan_id,
                notification_created,
                bool(email_required),
                email_alert_sent,
                email_alert_reason,
            )
        else:
            notification_reason = "notification_helper_unavailable"
            email_alert_reason = "notification_helper_unavailable" if email_required else email_alert_reason
            current_app.logger.warning("[PhishingScanner] notification helper unavailable")
    except Exception:
        notification_reason = "notification_exception"
        email_alert_reason = "notification_exception" if email_required else email_alert_reason
        current_app.logger.exception("[PhishingScanner] notification creation failed safely")

    if email_required and notification_created and not email_alert_sent:
        try:
            send_phishing_email = current_app.extensions.get("send_phishing_scan_email_alert")
            if callable(send_phishing_email):
                email_helper_called = True
                fallback_sent, fallback_reason = send_phishing_email(
                    user,
                    url=url,
                    domain=domain,
                    final_category=final_data["final_category"],
                    final_risk_score=final_data["final_risk_score"],
                    ml_probability=(ml_result or {}).get("probability"),
                    virustotal_reputation=(virustotal_data or {}).get("reputation"),
                    virustotal_malicious=(virustotal_data or {}).get("malicious"),
                    virustotal_suspicious=(virustotal_data or {}).get("suspicious"),
                )
                email_alert_sent = bool(fallback_sent)
                email_alert_reason = (
                    "sent_via_phishing_fallback"
                    if email_alert_sent
                    else str(fallback_reason or "phishing_fallback_returned_false")
                )
            else:
                email_alert_reason = "email_helper_unavailable"
        except Exception:
            email_helper_called = True
            email_alert_reason = "email_exception"
            current_app.logger.exception(
                "[phishing-email] fallback failed safely | user_id=%s scan_id=%s",
                getattr(user, "id", None),
                scan_id,
            )

    if not email_required:
        current_app.logger.info(
            "[phishing-email] trigger_passed=false final_category=%s final_risk_score=%s user_id_exists=%s recipient_exists=%s helper_called=false sent=false reason=safe_scan_no_email",
            final_data["final_category"],
            final_data["final_risk_score"],
            bool(getattr(user, "id", None)),
            bool(str(getattr(user, "email", "") or "").strip()),
        )

    try:
        create_security_alert = current_app.extensions.get("create_phishing_scanner_security_alert")
        if callable(create_security_alert):
            recent_alert = create_security_alert(
                user,
                scan_id=scan_id,
                url=url,
                domain=domain,
                final_category=final_data["final_category"],
                final_risk_score=final_data["final_risk_score"],
                ml_probability=(ml_result or {}).get("probability"),
                virustotal_malicious=(virustotal_data or {}).get("malicious"),
                virustotal_suspicious=(virustotal_data or {}).get("suspicious"),
                metadata=notification_metadata,
            )
            recent_alert_created = bool(recent_alert)
            recent_alert_source_type = str(getattr(recent_alert, "source_type", "") or "")
            admin_email_alert_sent = bool(getattr(recent_alert, "_admin_email_alert_sent", False))
            admin_email_alert_reason = str(
                getattr(recent_alert, "_admin_email_alert_reason", "")
                or admin_email_alert_reason
            )
        else:
            current_app.logger.warning("[PhishingScanner] security alert helper unavailable")
    except Exception:
        current_app.logger.exception("[PhishingScanner] security alert creation failed safely")

    integration_log = (
        "[phishing-integration] "
        f"user_id_exists={bool(getattr(user, 'id', None))} "
        f"user_email_exists={bool(str(getattr(user, 'email', '') or '').strip())} "
        f"scan_id={scan_id} "
        f"final_category={final_data['final_category']} "
        f"final_risk_score={final_data['final_risk_score']} "
        f"notification_created={bool(notification_created)} "
        f"notification_reason={notification_reason} "
        f"recent_alert_created={bool(recent_alert_created)} "
        f"recent_alert_source_type={recent_alert_source_type or 'none'} "
        f"admin_email_alert_sent={bool(admin_email_alert_sent)} "
        f"admin_email_alert_reason={admin_email_alert_reason} "
        f"email_trigger_passed={bool(email_required)} "
        f"email_helper_called={bool(email_helper_called or email_required)} "
        f"email_alert_sent={bool(email_alert_sent)} "
        f"email_alert_reason={email_alert_reason}"
    )
    current_app.logger.warning(integration_log)
    print(integration_log, flush=True)

    return jsonify({
        "url": url,
        "domain": domain,
        "ml_result": ml_result,
        "risk_score": risk_data["risk_score"],
        "category": risk_data["category"],
        "guidance": guidance,
        "virustotal": virustotal_data,
        "final_category": final_data["final_category"],
        "final_risk_score": final_data["final_risk_score"],
        "final_guidance": final_data["final_guidance"],
        "notification_created": notification_created,
        "recent_alert_created": recent_alert_created,
        "admin_email_alert_sent": admin_email_alert_sent,
        "admin_email_alert_reason": admin_email_alert_reason,
        "email_alert_sent": email_alert_sent,
        "email_alert_reason": email_alert_reason,
        "activity_logged": activity_logged,
        "activity_log_reason": activity_log_reason,
        "gamification": gamification_result,
    }), 200


#@scan_bp.route("/scans", methods=["GET"])
#def get_scans():
#    return jsonify(get_user_scans(user_id=None)), 200

@scan_bp.route("/scans", methods=["GET"])
def get_scans():
    get_current_user = current_app.extensions["get_current_user"]
    user = get_current_user()

    if not user:
        return jsonify({"success": False, "message": "Not authenticated"}), 401


    scans = get_user_scans(user_id=user.id)
    # تحويل result → category لكل سجل
    for scan in scans:
        scan["category"] = scan.pop("result")
        scan["risk_score"] = scan.pop("risk")  # لو قاعدة البيانات تسميه risk
    return jsonify(scans), 200

@scan_bp.route("/scan/<int:scan_id>", methods=["DELETE"])
def delete_scan_route(scan_id):
    get_current_user = current_app.extensions["get_current_user"]
    user = get_current_user()

    if not user:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    delete_scan(scan_id, user.id)
    return jsonify({"message": f"Scan {scan_id} deleted"}), 200

