import json
import os
from typing import Any
from urllib.parse import urljoin

import requests

from .prompts import SENTINEL_CHATBOT_SYSTEM_PROMPT

OLLAMA_SYSTEM_INSTRUCTION = SENTINEL_CHATBOT_SYSTEM_PROMPT


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(str(os.getenv(name, default)).strip())
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _ollama_base_url() -> str:
    return str(os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434").strip().rstrip("/")


def _ollama_model() -> str:
    return str(os.getenv("OLLAMA_MODEL") or "qwen2.5:7b").strip() or "qwen2.5:7b"


def _timeout_seconds() -> int:
    return _positive_int_env("OLLAMA_TIMEOUT_SECONDS", _positive_int_env("LLM_TIMEOUT_SECONDS", 90))


def _error_result(reason: str, *, model: str | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "answer": "",
        "reply": "",
        "provider": "ollama",
        "model": model or _ollama_model(),
        "fallback_reason": reason,
        "error_reason": reason,
    }


def _classify_ollama_error(status_code: int, body: str = "") -> str:
    lowered = str(body or "").lower()
    if status_code == 404 or ("model" in lowered and ("not found" in lowered or "pull" in lowered)):
        return "ollama_model_missing"
    return "ollama_error"


def get_ollama_provider_config() -> dict[str, Any]:
    return {
        "provider": "ollama",
        "base_url": _ollama_base_url(),
        "model": _ollama_model(),
        "timeout_seconds": _timeout_seconds(),
    }


def check_ollama_status() -> dict[str, Any]:
    config = get_ollama_provider_config()
    base_url = config["base_url"]
    model = config["model"]
    timeout = min(int(config["timeout_seconds"]), 10)
    reachable = False
    model_available = False
    try:
        response = requests.get(urljoin(f"{base_url}/", "api/tags"), timeout=timeout)
        reachable = response.status_code < 500
        if response.ok:
            data = response.json()
            models = data.get("models") if isinstance(data, dict) else []
            if isinstance(models, list):
                model_available = any(
                    str(item.get("name") or "").strip() == model
                    for item in models
                    if isinstance(item, dict)
                )
    except (requests.Timeout, requests.ConnectionError, requests.RequestException, ValueError):
        reachable = False
        model_available = False
    return {
        **config,
        "base_url_reachable": bool(reachable),
        "model_available": bool(model_available),
    }


def call_ollama_llm(user_message: str, module: str, safe_context: dict[str, Any]) -> dict[str, Any]:
    base_url = _ollama_base_url()
    model = _ollama_model()
    timeout_seconds = _timeout_seconds()
    endpoint = urljoin(f"{base_url}/", "api/chat")

    context_json = json.dumps(safe_context, ensure_ascii=False, indent=2, default=str)
    detected_intent = str(safe_context.get("detected_intent") or "general").strip()
    response_guidance = str(safe_context.get("response_guidance") or "").strip()
    prompt = (
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
        "- Answer the specific question and detected intent, not every possible module summary.\n"
        "- Do not repeat the same answer for different intents.\n"
        "- If the user asks for recommendations, focus on actions. If the user asks for calculation, focus on calculation. If the user asks for available reports, focus on report categories.\n"
        "- Use dynamic module data for current user-specific results.\n"
        "- Use static module knowledge for general explanations, definitions, pipeline, architecture, logs, and reports questions.\n"
        "- For PCAP scoring questions, use only pcap_scoring_logic and dynamic PCAP score fields from the safe context.\n"
        "- For PCAP quick actions, use pcap_context first. It is the unified safe PCAP report summary.\n"
        "- For PCAP IP review questions, use pcap_context.ip_review_summary.top_ips. If top_ips is empty or unavailable, say IP-level detail is not available and do not invent IPs.\n"
        "- For PCAP clean/threat/risk questions, use pcap_context.summary, top_threats, top_alerts, severity_counts, and ip_review_summary only.\n"
        "- Never invent scoring formulas, thresholds, or weights. If scoring detail is missing, say it is not explicitly available in the current implementation.\n"
        "- If dynamic module data is missing, say no dynamic data is available yet, then explain what the module does from static module knowledge.\n"
        "- Do not invent scans, reports, scores, findings, exports, URLs, users, IPs, filenames, tables, detections, alerts, or report data.\n"
        "- Preserve identifiers exactly as provided. Copy IDs exactly from context and never rewrite, shorten, correct, or regenerate IDs.\n"
        "- If selected module is security_score, discuss only Password Checker, File Vault, Phishing Scanner, and Identity Leak. Do not include PCAP as a score component, evidence item, or recommendation.\n"
        "- If selected module is reports, explain the Reports & Export Center and mention PCAP only as a separate network-traffic report category. Do not merge PCAP with Security Score.\n"
        "- If selected module is identity, use only identity_safe_summary and dynamic_identity safe fields. Never expose raw findings, credentials, scraped page text, or full sensitive identifiers.\n"
        "- For Identity Leak, current scans use public OSINT-like sources unless dark web integration is explicitly present in context. Do not claim dark web coverage otherwise.\n"
        "- For Identity Leak password questions, say a finding does not automatically prove password exposure unless credential exposure or confirmed breach is explicitly present in the safe context.\n"
        "- For Identity Leak quick actions, use identity_context.has_data, identity_context.summary, source_statuses, severity_counts, category_counts, top_findings_summary, risky_assets_summary, recommendations, and security_score_weight.\n"
        "- If identity_context.has_data is false, say Identity Leak has not been assessed yet because no Identity Leak scan has been completed.\n"
        "- For Protection Rate, use identity_context.summary.protection_rate if present. If unavailable, explain that the exact current percentage is unavailable.\n"
        "- For risky assets, use identity_context.risky_assets_summary. If empty, do not invent assets.\n"
        "- Identity Leak contributes 25% to Security Score when assessed. Missing Identity scans are Not assessed yet, never a fake score.\n"
        "- If IP details are unavailable, say that the latest context does not include per-IP alert details.\n"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": OLLAMA_SYSTEM_INSTRUCTION},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.2},
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=timeout_seconds)
    except requests.Timeout:
        return _error_result("ollama_timeout", model=model)
    except requests.ConnectionError:
        return _error_result("ollama_not_running", model=model)
    except requests.RequestException:
        return _error_result("ollama_error", model=model)

    if response.status_code >= 400:
        return _error_result(_classify_ollama_error(response.status_code, response.text[:500]), model=model)

    try:
        data = response.json()
    except ValueError:
        return _error_result("invalid_ollama_response", model=model)

    message = data.get("message") if isinstance(data, dict) else None
    reply = str((message or {}).get("content") or "").strip() if isinstance(message, dict) else ""
    if not reply:
        return _error_result("invalid_ollama_response", model=model)

    return {
        "ok": True,
        "answer": reply,
        "reply": reply,
        "provider": "ollama",
        "model": model,
        "fallback_reason": None,
        "error_reason": None,
    }
