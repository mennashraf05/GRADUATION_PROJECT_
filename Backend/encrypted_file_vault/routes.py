import os
import re
import hashlib
from datetime import datetime
from pathlib import Path
from io import BytesIO

from flask import Blueprint, request, jsonify, abort, send_file, current_app
from cryptography.fernet import InvalidToken
from werkzeug.exceptions import HTTPException

from .crypto import generate_salt, get_cipher_from_password
from .models import VaultDocument
from extensions import db
from security_utils import ensure_path_within_directory, safe_error_response
from upload_security import validate_vault_upload

from activity_logs import (
    MODULE_VAULT,
    STATUS_SUCCESS,
    STATUS_FAILED,
    STATUS_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    UserEventPayload,
    log_user_activity,
)


bp = Blueprint("vault", __name__)


@bp.errorhandler(Exception)
def handle_vault_error(e):
    if isinstance(e, HTTPException):
        return jsonify({
            "error": e.description or "Unable to complete the File Vault request."
        }), e.code or 500

    return safe_error_response(
        public_message="Unable to complete the File Vault request right now.",
        error_code="vault_error",
        status_code=500,
        log_exception=e,
        log_context={"module": "file_vault"},
    )


UPLOAD_FOLDER_NAME = "upload"
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt",
    "xls", "xlsx", "ppt", "pptx",
    "jpg", "jpeg", "png", "gif", "webp",
    "csv",
    "py", "js", "ts", "jsx", "tsx",
    "java", "c", "cpp", "h", "hpp",
    "cs", "go", "rs",
    "html", "css", "scss",
    "json", "xml", "yml", "yaml",
    "md", "ini", "cfg", "toml",
}

_INVALID_NAME_CHARS = re.compile(r"[^A-Za-z0-9.\- _()]+")


def log_vault_event(
    user_id,
    action_type,
    title,
    description="",
    status=STATUS_INFO,
    severity=SEVERITY_LOW,
    doc=None,
    metadata=None,
):
    forwarded_for = str(request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
    ip_address = forwarded_for or str(request.remote_addr or "").strip()
    safe_metadata = {}
    for key, value in (metadata or {}).items():
        clean_key = str(key or "")
        if any(fragment in clean_key.lower() for fragment in ("hash", "salt", "key", "stored_filename", "path")):
            continue
        safe_metadata[clean_key] = value
    try:
        log_user_activity(UserEventPayload(
            user_id=user_id,
            module=MODULE_VAULT,
            action_type=action_type,
            title=title,
            description=description,
            status=status,
            severity=severity,
            target_type="vault_document" if doc else None,
            target_id=str(doc.id) if doc else None,
            target_label=doc.filename if doc else None,
            ip_address=ip_address[:64] or None,
            metadata_json=safe_metadata,
        ))
    except Exception:
        current_app.logger.exception("Failed to write vault activity log")


def record_vault_gamification_event(event_type: str, user, doc: VaultDocument):
    """
    Best-effort bridge from Encrypted File Vault actions to Gamification.
    If gamification fails, the Vault action itself should not fail.
    """
    try:
        gamification_service = current_app.extensions.get("gamification_service")

        if gamification_service is None:
            current_app.logger.warning(
                "Vault gamification skipped because gamification_service is not registered | event_type=%s",
                event_type,
            )
            return None

        method_map = {
            "vault_file_uploaded": "record_vault_file_uploaded",
            "vault_file_downloaded": "record_vault_file_downloaded",
            "vault_integrity_verified": "record_vault_integrity_verified",
            "vault_offline_enabled": "record_vault_offline_enabled",
            "vault_offline_disabled": "record_vault_offline_disabled",
        }

        method_name = method_map.get(event_type)
        method = getattr(gamification_service, method_name, None) if method_name else None

        if callable(method):
            result = method(
                int(user.id),
                str(doc.id),
                doc.file_hash,
                doc.filename,
            )
        else:
            result = gamification_service.process_event(
                int(user.id),
                event_type,
                {
                    "document_id": str(doc.id),
                    "file_hash": doc.file_hash,
                    "filename": doc.filename,
                },
            )

        current_app.logger.info(
            "Vault gamification event recorded | event_type=%s | user_id=%s | doc_id=%s | result=%s",
            event_type,
            user.id,
            doc.id,
            result,
        )

        return result

    except Exception:
        current_app.logger.exception(
            "Failed to record vault gamification event | event_type=%s",
            event_type,
        )
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def validate_password_strength(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter"
    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter"
    if not re.search(r"[0-9]", password):
        return "Password must contain a number"
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain a special character"
    return None


def sanitize_filename(name: str) -> str:
    name = (name or "").strip()
    name = name.replace("\\", "/").split("/")[-1]
    name = _INVALID_NAME_CHARS.sub("_", name)

    if len(name) > 180:
        root, dot, ext = name.rpartition(".")
        if dot:
            root = root[:150]
            ext = ext[:20]
            name = f"{root}.{ext}"
        else:
            name = name[:180]

    return name or "file"


def allowed_file(filename: str) -> bool:
    allowed_extensions = get_allowed_extensions()
    if "." not in filename:
        return "" in allowed_extensions
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions


def get_allowed_extensions() -> set[str]:
    getter = current_app.extensions.get("get_admin_allowed_file_extensions")
    if callable(getter):
        try:
            configured = {
                str(item or "").strip().lower().lstrip(".")
                for item in getter()
                if str(item or "").strip()
            }
            if configured:
                return configured
        except Exception:
            current_app.logger.exception("Failed to load admin File Vault extension policy")
    return set(ALLOWED_EXTENSIONS)


def calculate_file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_current_user_via_app():
    fn = current_app.extensions.get("get_current_user")
    return fn() if fn else None


def get_upload_dir() -> Path:
    backend_dir = Path(current_app.root_path).resolve()
    project_dir = backend_dir.parent
    upload_dir = (project_dir / UPLOAD_FOLDER_NAME).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


@bp.route("/api/documents", methods=["GET"])
def list_documents():
    user = get_current_user_via_app()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    upload_dir = get_upload_dir()

    docs = (
        VaultDocument.query
        .filter_by(user_id=user.id)
        .order_by(VaultDocument.id.desc())
        .all()
    )

    out = []

    for d in docs:
        path = upload_dir / d.stored_filename
        size = path.stat().st_size if path.exists() else 0

        out.append({
            "id": d.id,
            "filename": d.filename,
            "upload_date": d.upload_date.isoformat(),
            "size_bytes": size,
            "status": "Encrypted",
            "offline_enabled": bool(d.offline_enabled),
        })

    return jsonify(out), 200


@bp.route("/api/documents", methods=["POST"])
def upload_document():
    user = get_current_user_via_app()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    password = request.form.get("password", "").strip()

    password_error = validate_password_strength(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if not file or not file.filename or file.filename.strip() == "":
        return jsonify({"error": "Empty filename"}), 400

    raw_filename = file.filename.strip()

    allowed_extensions = get_allowed_extensions()
    validation = validate_vault_upload(file, raw_filename, allowed_extensions)
    if not validation.get("ok"):
        current_app.logger.warning(
            "Rejected File Vault upload | reason=%s",
            validation.get("safe_reason") or "invalid_file",
        )
        return safe_error_response(
            public_message=validation.get("public_message") or "This file type is not allowed.",
            error_code=validation.get("error_code") or "invalid_file_type",
            status_code=400,
            log_context={
                "module": "file_vault",
                "reason": validation.get("safe_reason") or "invalid_file",
            },
        )

    original_name = sanitize_filename(raw_filename)

    if not allowed_file(original_name):
        current_app.logger.warning("Rejected File Vault upload | reason=invalid_extension")
        return safe_error_response(
            public_message="This file type is not allowed.",
            error_code="invalid_file_type",
            status_code=400,
            log_context={"module": "file_vault", "reason": "invalid_extension"},
        )

    raw = file.read()

    if not raw:
        return jsonify({"error": "Empty file"}), 400

    if len(raw) > MAX_FILE_SIZE_BYTES:
        return jsonify({
            "error": "File is too large",
            "max_size_mb": MAX_FILE_SIZE_BYTES // (1024 * 1024),
        }), 400

    file_hash = calculate_file_hash(raw)

    salt = generate_salt()
    cipher = get_cipher_from_password(password, salt)
    encrypted = cipher.encrypt(raw)

    upload_dir = get_upload_dir()

    safe_ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    stored_filename = f"{user.id}_{safe_ts}_{file_hash}.bin"
    stored_path = upload_dir / stored_filename

    if stored_path.exists():
        stored_filename = f"{user.id}_{safe_ts}_{file_hash}_{os.getpid()}.bin"
        stored_path = upload_dir / stored_filename

    with open(stored_path, "wb") as f:
        f.write(encrypted)

    doc = VaultDocument(
        filename=original_name,
        stored_filename=stored_filename,
        user_id=user.id,
        file_hash=file_hash,
        salt=salt.hex(),
        offline_enabled=False,
        signature=None,
        hmac_key=None,
    )

    db.session.add(doc)
    db.session.commit()

    size = stored_path.stat().st_size

    log_vault_event(
        user_id=user.id,
        action_type="vault_file_uploaded",
        title="Vault file uploaded",
        description=f"Uploaded encrypted file: {doc.filename}",
        status=STATUS_SUCCESS,
        severity=SEVERITY_MEDIUM,
        doc=doc,
        metadata={
            "filename": doc.filename,
            "size_bytes": size,
            "offline_enabled": bool(doc.offline_enabled),
        },
    )
    log_vault_event(
        user_id=user.id,
        action_type="vault_file_encrypted",
        title="Vault file encrypted",
        description=f"File encryption completed for: {doc.filename}",
        status=STATUS_SUCCESS,
        severity=SEVERITY_MEDIUM,
        doc=doc,
        metadata={
            "filename": doc.filename,
            "size_bytes": size,
            "offline_enabled": bool(doc.offline_enabled),
        },
    )

    gamification_result = record_vault_gamification_event(
        "vault_file_uploaded",
        user,
        doc,
    )

    return jsonify({
        "message": "File uploaded successfully",
        "document": {
            "id": doc.id,
            "filename": doc.filename,
            "upload_date": doc.upload_date.isoformat(),
            "size_bytes": size,
            "status": "Encrypted",
            "offline_enabled": bool(doc.offline_enabled),
        },
        "gamification": gamification_result,
    }), 201


@bp.route("/api/upload", methods=["POST"])
def upload_alias():
    return upload_document()


@bp.route("/api/documents/<int:doc_id>/offline", methods=["PATCH"])
def toggle_offline_access(doc_id):
    user = get_current_user_via_app()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    doc = VaultDocument.query.get_or_404(doc_id)

    if doc.user_id != user.id:
        log_vault_event(
            user_id=user.id,
            action_type="vault_access_denied",
            title="Vault access denied",
            description="A vault document access request was denied.",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={"operation": "toggle_offline", "document_id": doc_id},
        )
        abort(403)

    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("offline_enabled", False))
    previous_enabled = bool(doc.offline_enabled)

    doc.offline_enabled = enabled
    db.session.commit()

    action_type = "vault_offline_enabled" if enabled else "vault_offline_disabled"

    log_vault_event(
        user_id=user.id,
        action_type=action_type,
        title="Vault offline access enabled" if enabled else "Vault offline access disabled",
        description=(
            f"Enabled offline access for: {doc.filename}"
            if enabled
            else f"Disabled offline access for: {doc.filename}"
        ),
        status=STATUS_SUCCESS,
        severity=SEVERITY_LOW,
        doc=doc,
        metadata={
            "filename": doc.filename,
            "offline_enabled": bool(doc.offline_enabled),
            "previous_offline_enabled": previous_enabled,
        },
    )

    gamification_result = record_vault_gamification_event(
        action_type,
        user,
        doc,
    )

    return jsonify({
        "message": "Offline access updated",
        "id": doc.id,
        "offline_enabled": bool(doc.offline_enabled),
        "previous_offline_enabled": previous_enabled,
        "gamification": gamification_result,
    }), 200


@bp.route("/api/documents/<int:doc_id>/verify", methods=["POST"])
def verify_document_integrity(doc_id):
    user = get_current_user_via_app()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()

    password_error = validate_password_strength(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    doc = VaultDocument.query.get_or_404(doc_id)

    if doc.user_id != user.id:
        log_vault_event(
            user_id=user.id,
            action_type="vault_access_denied",
            title="Vault access denied",
            description="A vault integrity verification request was denied.",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={"operation": "verify_integrity", "document_id": doc_id},
        )
        abort(403)

    upload_dir = get_upload_dir()

    try:
        stored_path = ensure_path_within_directory(
            upload_dir / doc.stored_filename,
            upload_dir,
        )
    except ValueError as exc:
        return safe_error_response(
            public_message="Unable to access the requested file.",
            error_code="invalid_file_path",
            status_code=403,
            log_exception=exc,
            log_context={
                "module": "file_vault",
                "reason": "path_outside_allowed_directory",
            },
        )

    if not stored_path.exists():
        return jsonify({"error": "File not found"}), 404

    with open(stored_path, "rb") as f:
        encrypted_data = f.read()

    try:
        salt = bytes.fromhex(doc.salt)
        cipher = get_cipher_from_password(password, salt)
        decrypted = cipher.decrypt(encrypted_data)
    except InvalidToken:
        log_vault_event(
            user_id=user.id,
            action_type="vault_wrong_password",
            title="Wrong vault password attempt",
            description=f"Wrong password while verifying integrity: {doc.filename}",
            status=STATUS_FAILED,
            severity=SEVERITY_MEDIUM,
            doc=doc,
            metadata={
                "operation": "verify_integrity",
                "filename": doc.filename,
            },
        )
        return jsonify({"error": "Wrong encryption password"}), 403

    current_hash = calculate_file_hash(decrypted)

    if current_hash != doc.file_hash:
        log_vault_event(
            user_id=user.id,
            action_type="vault_integrity_failed",
            title="Vault integrity check failed",
            description=f"Integrity check failed for: {doc.filename}",
            status=STATUS_FAILED,
            severity=SEVERITY_MEDIUM,
            doc=doc,
            metadata={
            "filename": doc.filename,
            },
        )
        return jsonify({"error": "Integrity check failed"}), 409

    log_vault_event(
        user_id=user.id,
        action_type="vault_integrity_verified",
        title="Vault file integrity verified",
        description=f"Verified encrypted file integrity: {doc.filename}",
        status=STATUS_SUCCESS,
        severity=SEVERITY_LOW,
        doc=doc,
        metadata={
            "filename": doc.filename,
            "size_bytes": len(decrypted),
            "offline_enabled": bool(doc.offline_enabled),
        },
    )

    gamification_result = record_vault_gamification_event(
        "vault_integrity_verified",
        user,
        doc,
    )

    return jsonify({
        "message": "Integrity verified successfully",
        "document_id": doc.id,
        "filename": doc.filename,
        "integrity_ok": True,
        "gamification": gamification_result,
    }), 200


@bp.route("/api/documents/<int:doc_id>/download", methods=["POST"])
def download_document(doc_id):
    user = get_current_user_via_app()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()

    password_error = validate_password_strength(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    doc = VaultDocument.query.get_or_404(doc_id)

    if doc.user_id != user.id:
        log_vault_event(
            user_id=user.id,
            action_type="vault_access_denied",
            title="Vault access denied",
            description="A vault download request was denied.",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={"operation": "download", "document_id": doc_id},
        )
        abort(403)

    upload_dir = get_upload_dir()

    try:
        stored_path = ensure_path_within_directory(
            upload_dir / doc.stored_filename,
            upload_dir,
        )
    except ValueError as exc:
        return safe_error_response(
            public_message="Unable to access the requested file.",
            error_code="invalid_file_path",
            status_code=403,
            log_exception=exc,
            log_context={
                "module": "file_vault",
                "reason": "path_outside_allowed_directory",
            },
        )

    if not stored_path.exists():
        return jsonify({"error": "File not found"}), 404

    with open(stored_path, "rb") as f:
        encrypted_data = f.read()

    try:
        salt = bytes.fromhex(doc.salt)
        cipher = get_cipher_from_password(password, salt)
        decrypted = cipher.decrypt(encrypted_data)
    except InvalidToken:
        log_vault_event(
            user_id=user.id,
            action_type="vault_wrong_password",
            title="Wrong vault password attempt",
            description=f"Wrong password while downloading: {doc.filename}",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={
                "operation": "download",
                "filename": doc.filename,
            },
        )
        return jsonify({"error": "Wrong encryption password"}), 403

    if calculate_file_hash(decrypted) != doc.file_hash:
        log_vault_event(
            user_id=user.id,
            action_type="vault_integrity_failed",
            title="Vault integrity check failed",
            description=f"Integrity check failed while downloading: {doc.filename}",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={"operation": "download", "filename": doc.filename},
        )
        return jsonify({"error": "Integrity check failed"}), 409

    log_vault_event(
        user_id=user.id,
        action_type="vault_file_downloaded",
        title="Vault file downloaded",
        description=f"Downloaded encrypted file: {doc.filename}",
        status=STATUS_SUCCESS,
        severity=SEVERITY_LOW,
        doc=doc,
        metadata={
            "filename": doc.filename,
            "size_bytes": len(decrypted),
            "offline_enabled": bool(doc.offline_enabled),
        },
    )

    record_vault_gamification_event(
        "vault_file_downloaded",
        user,
        doc,
    )

    # Download already verifies integrity successfully before sending the file.
    # This also completes the "Verify 1 vault file" challenge.
    record_vault_gamification_event(
        "vault_integrity_verified",
        user,
        doc,
    )

    bio = BytesIO(decrypted)
    bio.seek(0)

    return send_file(
        bio,
        as_attachment=True,
        download_name=doc.filename,
        mimetype="application/octet-stream",
        max_age=0,
    )


@bp.route("/download/<int:doc_id>", methods=["GET"])
def old_download_blocked(doc_id):
    return jsonify({
        "error": "This endpoint is disabled. Use POST /api/documents/<id>/download with password."
    }), 405


@bp.route("/api/documents/<int:doc_id>", methods=["DELETE"])
def delete_document(doc_id):
    user = get_current_user_via_app()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()

    password_error = validate_password_strength(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    doc = VaultDocument.query.get_or_404(doc_id)

    if doc.user_id != user.id:
        log_vault_event(
            user_id=user.id,
            action_type="vault_access_denied",
            title="Vault access denied",
            description="A vault delete request was denied.",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={"operation": "delete", "document_id": doc_id},
        )
        abort(403)

    upload_dir = get_upload_dir()

    try:
        stored_path = ensure_path_within_directory(
            upload_dir / doc.stored_filename,
            upload_dir,
        )
    except ValueError as exc:
        return safe_error_response(
            public_message="Unable to access the requested file.",
            error_code="invalid_file_path",
            status_code=403,
            log_exception=exc,
            log_context={
                "module": "file_vault",
                "reason": "path_outside_allowed_directory",
            },
        )

    if not stored_path.exists():
        return jsonify({"error": "File not found"}), 404

    with open(stored_path, "rb") as f:
        encrypted_data = f.read()

    try:
        salt = bytes.fromhex(doc.salt)
        cipher = get_cipher_from_password(password, salt)
        decrypted = cipher.decrypt(encrypted_data)
    except InvalidToken:
        log_vault_event(
            user_id=user.id,
            action_type="vault_wrong_password",
            title="Wrong vault password attempt",
            description=f"Wrong password while deleting: {doc.filename}",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={
                "operation": "delete",
                "filename": doc.filename,
            },
        )
        return jsonify({"error": "Wrong encryption password"}), 403

    if calculate_file_hash(decrypted) != doc.file_hash:
        log_vault_event(
            user_id=user.id,
            action_type="vault_integrity_failed",
            title="Vault integrity check failed",
            description=f"Integrity check failed while deleting: {doc.filename}",
            status=STATUS_FAILED,
            severity=SEVERITY_HIGH,
            doc=doc,
            metadata={"operation": "delete", "filename": doc.filename},
        )
        return jsonify({"error": "Integrity check failed"}), 409

    deleted_filename = doc.filename
    deleted_doc_id = doc.id
    deleted_size = len(decrypted)
    was_offline = bool(doc.offline_enabled)

    try:
        stored_path.unlink()
    except Exception as e:
        log_vault_event(
            user_id=user.id,
            action_type="vault_operation_failed",
            title="Vault operation failed",
            description=f"Vault file deletion failed for: {doc.filename}",
            status=STATUS_FAILED,
            severity=SEVERITY_MEDIUM,
            doc=doc,
            metadata={"operation": "delete", "filename": doc.filename},
        )
        return safe_error_response(
            public_message="Unable to delete the file right now.",
            error_code="vault_delete_failed",
            status_code=500,
            log_exception=e,
            log_context={"module": "file_vault", "document_id": doc_id},
        )

    db.session.delete(doc)
    db.session.commit()

    log_vault_event(
        user_id=user.id,
        action_type="vault_file_deleted",
        title="Vault file deleted",
        description=f"Deleted encrypted file: {deleted_filename}",
        status=STATUS_SUCCESS,
        severity=SEVERITY_HIGH,
        metadata={
            "document_id": deleted_doc_id,
            "filename": deleted_filename,
            "size_bytes": deleted_size,
            "offline_enabled": was_offline,
        },
    )

    return jsonify({
        "message": "File deleted successfully",
        "id": doc_id,
    }), 200
