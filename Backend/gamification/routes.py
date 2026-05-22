from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from gamification.definitions import UI_EVENT_TYPES
from gamification.helpers import safe_int, safe_str


gamification_bp = Blueprint("gamification", __name__)

ALERT_REVIEW_MUTATION_EVENTS = {
    "alert_reviewed",
    "alert_marked_true_positive",
    "alert_marked_false_positive",
    "investigation_note_added",
}


def _service():
    service = current_app.extensions.get("gamification_service")
    if service is None:
        raise RuntimeError("Gamification service is not registered")
    return service


def _require_user():
    resolver = current_app.extensions.get("require_full_auth_user")
    if resolver is None:
        raise RuntimeError("Auth resolver is not registered")
    return resolver()


def _can_mutate_alert_review(user) -> bool:
    role_candidates = {
        safe_str(getattr(user, "admin_role", "")),
        safe_str(getattr(user, "role", "")),
    }
    normalized_roles = {role.strip().lower() for role in role_candidates if role}
    return bool(normalized_roles.intersection({"admin", "analyst"}))


@gamification_bp.route("/api/gamification/profile", methods=["GET"])
def gamification_profile():
    user, auth_error = _require_user()
    if auth_error:
        return auth_error
    return jsonify(_service().get_profile_payload(int(user.id)))


@gamification_bp.route("/api/gamification/badges", methods=["GET"])
def gamification_badges():
    user, auth_error = _require_user()
    if auth_error:
        return auth_error
    return jsonify(_service().get_badges_payload(int(user.id)))


@gamification_bp.route("/api/gamification/challenges", methods=["GET"])
def gamification_challenges():
    user, auth_error = _require_user()
    if auth_error:
        return auth_error
    return jsonify(_service().get_challenges_payload(int(user.id)))


@gamification_bp.route("/api/gamification/history", methods=["GET"])
def gamification_history():
    user, auth_error = _require_user()
    if auth_error:
        return auth_error
    limit = safe_int(request.args.get("limit"), 15)
    return jsonify(_service().get_history_payload(int(user.id), limit=limit))


@gamification_bp.route("/api/gamification/overview", methods=["GET"])
def gamification_overview():
    user, auth_error = _require_user()
    if auth_error:
        return auth_error
    return jsonify(_service().get_overview_payload(int(user.id)))


@gamification_bp.route("/api/gamification/alert-context", methods=["GET"])
def gamification_alert_context():
    user, auth_error = _require_user()
    if auth_error:
        return auth_error

    job_id = safe_str(request.args.get("job_id"))
    alert_id = safe_str(request.args.get("alert_id"))
    if not job_id or not alert_id:
        return jsonify({"error": "job_id and alert_id are required"}), 400

    return jsonify(_service().get_alert_context(int(user.id), job_id, alert_id))


@gamification_bp.route("/api/gamification/events", methods=["POST"])
def gamification_events():
    user, auth_error = _require_user()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    event_type = safe_str(data.get("event_type")).lower()
    if not event_type:
        return jsonify({"error": "event_type is required"}), 400
    if event_type not in UI_EVENT_TYPES:
        return jsonify({"error": "Unsupported UI gamification event"}), 400
    if event_type in ALERT_REVIEW_MUTATION_EVENTS and not _can_mutate_alert_review(user):
        return jsonify({"error": "Admin or analyst authorization required"}), 403

    payload = {
        "job_id": safe_str(data.get("job_id")) or None,
        "alert_id": safe_str(data.get("alert_id")) or None,
        "evidence_key": safe_str(data.get("evidence_key")) or None,
        "evidence_context": safe_str(data.get("evidence_context")) or None,
        "access_method": safe_str(data.get("access_method")) or None,
        "note_body": safe_str(data.get("note_body")) or None,
    }

    if event_type in {
        "report_accessed",
        "report_opened",
        "alert_viewed",
        "evidence_accessed",
        "evidence_opened",
        "alert_reviewed",
        "alert_marked_true_positive",
        "alert_marked_false_positive",
        "investigation_note_added",
    } and not payload["job_id"]:
        return jsonify({"error": "job_id is required"}), 400

    if event_type in {
        "alert_viewed",
        "alert_reviewed",
        "alert_marked_true_positive",
        "alert_marked_false_positive",
        "investigation_note_added",
    } and not payload["alert_id"]:
        return jsonify({"error": "alert_id is required"}), 400

    if event_type == "investigation_note_added" and not payload["note_body"]:
        return jsonify({"error": "note_body is required"}), 400

    try:
        result = _service().record_ui_event(int(user.id), event_type, payload)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)
