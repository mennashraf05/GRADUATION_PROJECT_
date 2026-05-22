import json
import logging
import os
import time
from typing import Any
from urllib.parse import quote

import requests

from .prompts import SENTINEL_CHATBOT_SYSTEM_PROMPT


GEMINI_API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(str(os.getenv(name, default)).strip())
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _gemini_model() -> str:
    return str(os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip() or "gemini-2.5-flash"


def _gemini_timeout_seconds() -> int:
    return _positive_int_env("GEMINI_TIMEOUT_SECONDS", 45)


def _context_section_count(safe_context: dict[str, Any]) -> int:
    if not isinstance(safe_context, dict):
        return 0
    return len([key for key, value in safe_context.items() if value not in (None, "", [], {})])


def _error_result(reason: str, *, model: str | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "answer": "",
        "reply": "",
        "provider": "gemini",
        "model": model or _gemini_model(),
        "fallback_reason": reason,
        "error_reason": reason,
    }


def get_gemini_provider_config() -> dict[str, Any]:
    api_key = str(os.getenv("GEMINI_API_KEY") or "").strip()
    api_key_configured = bool(api_key and api_key != "YOUR_BACKEND_ONLY_KEY_HERE")
    enabled = _env_truthy("GEMINI_ENABLED", False)
    return {
        "provider": "gemini",
        "enabled": bool(enabled and api_key_configured),
        "configured_enabled": bool(enabled),
        "api_key_configured": api_key_configured,
        "model": _gemini_model(),
        "timeout_seconds": _gemini_timeout_seconds(),
    }


def check_gemini_status() -> dict[str, Any]:
    return get_gemini_provider_config()


def _build_gemini_prompt(user_message: str, module: str, safe_context: dict[str, Any]) -> str:
    context_json = json.dumps(safe_context, ensure_ascii=False, indent=2, default=str)
    detected_intent = str(safe_context.get("detected_intent") or "general").strip()
    response_guidance = str(safe_context.get("response_guidance") or "").strip()
    return (
        "User question:\n"
        f"{user_message}\n\n"
        "Selected Sentinel AI module:\n"
        f"{module}\n\n"
        "Detected intent:\n"
        f"{detected_intent}\n\n"
        "Response guidance for this intent:\n"
        f"{response_guidance or 'Answer the specific question using the selected module context.'}\n\n"
        "Safe Sentinel AI context JSON:\n"
        f"{context_json}\n\n"
        "Instructions:\n"
        "- Answer only from the safe context above.\n"
        "- Do not invent scans, reports, scores, findings, exports, URLs, users, IPs, filenames, tables, detections, alerts, or report data.\n"
        "- Preserve identifiers exactly as provided. Copy IDs exactly from context and never rewrite, shorten, correct, or regenerate IDs.\n"
        "- If selected module is security_score, discuss only Password Checker, File Vault, Phishing Scanner, and Identity Leak. Do not include PCAP as a score component, evidence item, or recommendation.\n"
        "- If selected module is pcap, use pcap_context first and never expose raw packet payloads or raw PCAP contents.\n"
        "- For PCAP IP review questions, use pcap_context.ip_review_summary.top_ips. If top_ips is empty or unavailable, say IP-level detail is not available and do not invent IPs.\n"
        "- If selected module is identity, use only identity_context and identity_safe_summary. Never expose raw findings, credentials, scraped page text, or full sensitive identifiers.\n"
        "- For Identity Leak, current scans use public OSINT-like sources unless dark web integration is explicitly present in context. Do not claim dark web coverage otherwise.\n"
        "- For Identity Leak password questions, say a finding does not automatically prove password exposure unless credential exposure or confirmed breach is explicitly present in the safe context.\n"
        "- If dynamic module data is missing, say no dynamic data is available yet, then explain what the module does from static module knowledge.\n"
    )


def _extract_gemini_text(data: Any) -> tuple[str, str | None]:
    if not isinstance(data, dict):
        return "", "invalid_gemini_response"

    prompt_feedback = data.get("promptFeedback")
    if isinstance(prompt_feedback, dict):
        block_reason = str(prompt_feedback.get("blockReason") or "").strip()
        if block_reason:
            return "", "gemini_safety_blocked"

    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return "", "invalid_gemini_response"

    first = candidates[0] if isinstance(candidates[0], dict) else {}
    finish_reason = str(first.get("finishReason") or "").strip().upper()
    if finish_reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"}:
        return "", "gemini_safety_blocked"

    content = first.get("content") if isinstance(first, dict) else None
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        return "", "invalid_gemini_response"

    text_parts = [
        str(part.get("text") or "").strip()
        for part in parts
        if isinstance(part, dict) and str(part.get("text") or "").strip()
    ]
    answer = "\n".join(text_parts).strip()
    return answer, None if answer else "invalid_gemini_response"


def call_gemini_llm(user_message: str, module: str, safe_context: dict[str, Any]) -> dict[str, Any]:
    model = _gemini_model()
    timeout_seconds = _gemini_timeout_seconds()
    started_at = time.perf_counter()

    if not _env_truthy("GEMINI_ENABLED", False):
        return _error_result("gemini_disabled", model=model)

    api_key = str(os.getenv("GEMINI_API_KEY") or "").strip()
    if not api_key or api_key == "YOUR_BACKEND_ONLY_KEY_HERE":
        return _error_result("missing_api_key", model=model)

    endpoint = f"{GEMINI_API_BASE_URL}/models/{quote(model, safe='')}:generateContent"
    payload = {
        "systemInstruction": {
            "parts": [{"text": SENTINEL_CHATBOT_SYSTEM_PROMPT}],
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": _build_gemini_prompt(user_message, module, safe_context)}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
        },
    }

    fallback_reason: str | None = None
    try:
        response = requests.post(
            endpoint,
            params={"key": api_key},
            json=payload,
            timeout=timeout_seconds,
        )
    except requests.Timeout:
        fallback_reason = "gemini_timeout"
        return _error_result(fallback_reason, model=model)
    except requests.RequestException:
        fallback_reason = "gemini_error"
        return _error_result(fallback_reason, model=model)
    finally:
        if fallback_reason:
            elapsed_ms = int((time.perf_counter() - started_at) * 1000)
            logging.info(
                "Gemini chatbot call finished | provider=gemini | model=%s | elapsed_ms=%s | fallback_reason=%s | context_sections=%s",
                model,
                elapsed_ms,
                fallback_reason,
                _context_section_count(safe_context),
            )

    if response.status_code == 429:
        fallback_reason = "gemini_rate_limit"
        result = _error_result(fallback_reason, model=model)
    elif response.status_code >= 400:
        fallback_reason = "gemini_error"
        result = _error_result(fallback_reason, model=model)
    else:
        try:
            data = response.json()
        except ValueError:
            fallback_reason = "invalid_gemini_response"
            result = _error_result(fallback_reason, model=model)
        else:
            answer, parse_reason = _extract_gemini_text(data)
            if parse_reason:
                fallback_reason = parse_reason
                result = _error_result(parse_reason, model=model)
            else:
                result = {
                    "ok": True,
                    "answer": answer,
                    "reply": answer,
                    "provider": "gemini",
                    "model": model,
                    "fallback_reason": None,
                    "error_reason": None,
                }

    elapsed_ms = int((time.perf_counter() - started_at) * 1000)
    logging.info(
        "Gemini chatbot call finished | provider=gemini | model=%s | elapsed_ms=%s | fallback_reason=%s | context_sections=%s",
        model,
        elapsed_ms,
        fallback_reason,
        _context_section_count(safe_context),
    )
    return result
