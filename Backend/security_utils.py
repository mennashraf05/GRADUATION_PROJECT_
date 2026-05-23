import logging
from pathlib import Path
from typing import Any

from flask import current_app, jsonify

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def sanitize_csv_cell(value: Any) -> str:
    if value is None:
        return ""
    try:
        text = str(value)
    except Exception:
        text = ""
    if text.startswith(CSV_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def sanitize_csv_row(values) -> list[str]:
    return [sanitize_csv_cell(value) for value in values]


def ensure_path_within_directory(candidate_path, allowed_base_dir) -> Path:
    base = Path(allowed_base_dir).expanduser().resolve()
    candidate = Path(candidate_path).expanduser().resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError("Path is outside the allowed directory") from exc
    return candidate


def safe_error_response(
    public_message: str = "Something went wrong. Please try again later.",
    error_code: str = "internal_error",
    status_code: int = 500,
    log_exception: BaseException | None = None,
    log_context: dict[str, Any] | None = None,
    extra_fields: dict[str, Any] | None = None,
):
    context = log_context or {}
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    if log_exception is not None:
        logger.error(
            "Safe error response returned | error_code=%s | status_code=%s | context=%s",
            error_code,
            status_code,
            context,
            exc_info=(type(log_exception), log_exception, log_exception.__traceback__),
        )

    payload = {
        "success": False,
        "error": error_code,
        "message": public_message,
    }
    if extra_fields:
        payload.update(extra_fields)
    return jsonify(payload), status_code
