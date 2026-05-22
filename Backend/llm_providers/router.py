import os
from typing import Any, Callable

from .gemini_provider import call_gemini_llm, get_gemini_provider_config
from .ollama_provider import call_ollama_llm, get_ollama_provider_config


ProviderPreference = str
FallbackCallable = Callable[[], str]


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _csv_env(name: str, default: list[str]) -> list[str]:
    raw = str(os.getenv(name) or "").strip()
    values = [item.strip().lower() for item in raw.split(",") if item.strip()]
    return values or list(default)


def allowed_providers() -> list[str]:
    providers = _csv_env("LLM_ALLOWED_PROVIDERS", ["auto", "ollama", "gemini", "fallback"])
    valid = {"auto", "ollama", "gemini", "fallback"}
    ordered: list[str] = []
    for provider in providers:
        if provider in valid and provider not in ordered:
            ordered.append(provider)
    return ordered or ["auto", "ollama", "gemini", "fallback"]


def default_provider() -> str:
    configured = str(os.getenv("LLM_DEFAULT_PROVIDER") or os.getenv("LLM_PROVIDER") or "auto").strip().lower()
    if configured in allowed_providers():
        return configured
    return "auto"


def normalize_provider_preference(value: object | None) -> str:
    requested = str(value or "").strip().lower() or default_provider()
    if requested not in {"auto", "ollama", "gemini", "fallback"}:
        return default_provider()
    if requested not in allowed_providers():
        return default_provider()
    return requested


def get_provider_attempt_order(preference: object | None) -> list[str]:
    selected = normalize_provider_preference(preference)
    if selected == "auto":
        auto_priority = [
            item for item in _csv_env("LLM_AUTO_PRIORITY", ["ollama", "gemini", "fallback"])
            if item in {"ollama", "gemini", "fallback"}
        ]
        attempts = auto_priority or ["ollama", "gemini", "fallback"]
    elif selected == "ollama":
        attempts = ["ollama", "fallback"]
    elif selected == "gemini":
        attempts = ["gemini", "ollama", "fallback"]
    else:
        attempts = ["fallback"]

    deduped: list[str] = []
    for provider in attempts:
        if provider == "fallback" or provider in allowed_providers():
            if provider not in deduped:
                deduped.append(provider)
    if "fallback" not in deduped:
        deduped.append("fallback")
    return deduped


def provider_model(provider: str) -> str | None:
    if provider == "ollama":
        return str(get_ollama_provider_config().get("model") or "").strip() or None
    if provider == "gemini":
        return str(get_gemini_provider_config().get("model") or "").strip() or None
    return None


def _attempt_record(provider: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": provider,
        "ok": bool(result.get("ok")),
        "reason": None if result.get("ok") else str(result.get("fallback_reason") or result.get("error_reason") or "provider_error"),
    }


def _fallback_result(fallback_answer: str, reason: str | None = None) -> dict[str, Any]:
    return {
        "ok": True,
        "answer": fallback_answer,
        "reply": fallback_answer,
        "provider": "fallback",
        "model": None,
        "fallback_reason": reason,
        "error_reason": reason,
    }


def route_chatbot_llm(
    user_message: str,
    module: str,
    safe_context: dict[str, Any],
    provider_preference: object | None,
    fallback_callable: FallbackCallable,
) -> dict[str, Any]:
    selected = normalize_provider_preference(provider_preference)
    attempts = get_provider_attempt_order(selected)
    provider_attempts: list[dict[str, Any]] = []
    last_reason: str | None = None

    if not _env_truthy("ENABLE_LLM_CHATBOT", False):
        attempts = ["fallback"]
        last_reason = "llm_disabled"

    for provider in attempts:
        if provider == "fallback":
            if not _env_truthy("ENABLE_RULE_BASED_FALLBACK", True):
                disabled = {
                    "ok": False,
                    "answer": "",
                    "reply": "",
                    "provider": "fallback",
                    "model": None,
                    "fallback_reason": "fallback_disabled",
                    "error_reason": "fallback_disabled",
                }
                provider_attempts.append(_attempt_record("fallback", disabled))
                continue
            answer = fallback_callable()
            result = _fallback_result(answer, last_reason)
            provider_attempts.append({"provider": "fallback", "ok": True, "reason": last_reason})
            return {**result, "selected_provider": selected, "provider_attempts": provider_attempts}

        if provider == "ollama":
            if not _env_truthy("OLLAMA_ENABLED", True):
                result = {
                    "ok": False,
                    "provider": "ollama",
                    "model": provider_model("ollama"),
                    "fallback_reason": "ollama_disabled",
                    "error_reason": "ollama_disabled",
                }
            else:
                try:
                    result = call_ollama_llm(user_message, module, safe_context)
                except Exception:
                    result = {
                        "ok": False,
                        "provider": "ollama",
                        "model": provider_model("ollama"),
                        "fallback_reason": "ollama_error",
                        "error_reason": "ollama_error",
                    }
        elif provider == "gemini":
            try:
                result = call_gemini_llm(user_message, module, safe_context)
            except Exception:
                result = {
                    "ok": False,
                    "provider": "gemini",
                    "model": provider_model("gemini"),
                    "fallback_reason": "gemini_error",
                    "error_reason": "gemini_error",
                }
        else:
            continue

        provider_attempts.append(_attempt_record(provider, result))
        if bool(result.get("ok")):
            return {**result, "selected_provider": selected, "provider_attempts": provider_attempts}
        last_reason = str(result.get("fallback_reason") or result.get("error_reason") or f"{provider}_error")

    answer = fallback_callable() if _env_truthy("ENABLE_RULE_BASED_FALLBACK", True) else "The chatbot providers are unavailable and fallback mode is disabled."
    result = _fallback_result(answer, last_reason or "provider_not_available")
    if not provider_attempts or provider_attempts[-1].get("provider") != "fallback":
        provider_attempts.append({"provider": "fallback", "ok": True, "reason": result.get("fallback_reason")})
    return {**result, "selected_provider": selected, "provider_attempts": provider_attempts}
