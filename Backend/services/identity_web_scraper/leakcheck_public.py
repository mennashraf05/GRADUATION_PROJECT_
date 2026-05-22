from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any
from urllib.parse import urlparse

import requests


LEAKCHECK_PUBLIC_API_URL = "https://leakcheck.net/api/public"
REQUEST_TIMEOUT = 8
SKIPPED_REASON = "Query format is not supported by LeakCheck"

_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])?$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")


def run_leakcheck_public_scan(email: str, username: str, domain: str) -> tuple[list[dict], dict, int]:
    targets = []
    skipped_invalid = False

    for matched_field, raw_target in (("email", email), ("username", username), ("domain", domain)):
        target = _sanitize_leakcheck_target(raw_target)
        if not target:
            skipped_invalid = skipped_invalid or bool(str(raw_target or "").strip())
            continue
        targets.append((matched_field, target))

    if not targets:
        return [], {"status": "skipped", "reason": SKIPPED_REASON}, 0

    findings = []
    checked = 0
    successful_checks = 0
    failures = []

    for matched_field, target in targets:
        target_findings, status, reason = _check_target(matched_field, target)
        if status != "skipped":
            checked += 1
        if status == "checked":
            successful_checks += 1
        findings.extend(target_findings)
        if status == "skipped":
            skipped_invalid = True
        elif status == "failed":
            failures.append(reason or "LeakCheck Public API request failed.")

    if failures and not findings and successful_checks == 0:
        return findings, {"status": "failed", "reason": failures[0]}, checked
    if failures:
        return findings, {"status": "checked", "reason": f"Partial check completed. {failures[0]}"}, checked
    if skipped_invalid and not findings and successful_checks == 0:
        return findings, {"status": "skipped", "reason": SKIPPED_REASON}, checked
    if skipped_invalid:
        return findings, {"status": "checked", "reason": "Partial check completed. Unsupported LeakCheck query was skipped."}, checked
    return findings, {"status": "checked"}, checked


def _check_target(matched_field: str, target: str) -> tuple[list[dict], str, str]:
    try:
        response = requests.get(LEAKCHECK_PUBLIC_API_URL, params={"check": target}, timeout=REQUEST_TIMEOUT)
    except requests.Timeout:
        return [], "failed", "request timeout"
    except requests.RequestException:
        return [], "failed", "LeakCheck Public API request failed."
    except Exception:
        return [], "failed", "LeakCheck Public API request failed safely."

    if response.status_code == 429:
        return [], "failed", "rate_limited"

    try:
        payload = response.json()
    except ValueError:
        return [], "failed", "LeakCheck Public API returned an invalid response."

    if not isinstance(payload, dict):
        return [], "failed", "LeakCheck Public API returned an invalid response."

    if response.status_code >= 400:
        message = _safe_message(payload)
        if "invalid" in message.lower() and "character" in message.lower():
            return [], "skipped", SKIPPED_REASON
        return [], "failed", message or "failed_provider"

    if payload.get("success") is False:
        message = _safe_message(payload)
        if "invalid" in message.lower() and "character" in message.lower():
            return [], "skipped", SKIPPED_REASON
        if message and _looks_like_failure(message):
            return [], "failed", message
        return [], "checked", ""

    found = _safe_int(payload.get("found"))
    if found <= 0:
        return [], "checked", ""

    sources = _extract_sources(payload)
    return [_confirmed_breach_finding(matched_field, target, sources)], "checked", ""


def _confirmed_breach_finding(matched_field: str, target: str, sources: list[dict[str, str]]) -> dict:
    evidence = "Target found in known breach metadata from LeakCheck Public API."
    source_summary = _format_source_summary(sources)
    if source_summary:
        evidence = f"{evidence} Sources: {source_summary}."

    return {
        "source": "leakcheck_public_api",
        "category": "confirmed_breach",
        "severity": "High",
        "title": "Known breach metadata match",
        "url": "",
        "matched_field": matched_field,
        "matched_value": target,
        "evidence": evidence,
        "found_in_search": True,
        "found_in_page": False,
        "risk_keyword_detected": True,
        "detected_keywords": ["breach"],
        "confidence": 95,
        "detected_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }


def _extract_sources(payload: dict[str, Any]) -> list[dict[str, str]]:
    raw_sources = payload.get("sources")
    if raw_sources is None:
        raw_sources = payload.get("source")

    if isinstance(raw_sources, dict):
        raw_sources = [raw_sources]
    if not isinstance(raw_sources, list):
        return []

    sources = []
    for item in raw_sources:
        if isinstance(item, str):
            name = _clean_text(item)
            date = ""
        elif isinstance(item, dict):
            name = _clean_text(item.get("name") or item.get("source") or item.get("title") or item.get("database"))
            date = _clean_text(item.get("date") or item.get("breach_date") or item.get("year"))
        else:
            continue

        if name:
            source = {"name": name}
            if date:
                source["date"] = date
            sources.append(source)

    return sources[:12]


def _format_source_summary(sources: list[dict[str, str]]) -> str:
    parts = []
    for source in sources:
        name = source.get("name", "")
        date = source.get("date", "")
        if name and date:
            parts.append(f"{name} ({date})")
        elif name:
            parts.append(name)
    return ", ".join(parts)


def _safe_message(payload: dict[str, Any]) -> str:
    value = payload.get("message") or payload.get("error") or payload.get("reason")
    if isinstance(value, list):
        value = " ".join(str(part) for part in value)
    return _clean_text(value)[:180]


def _looks_like_failure(message: str) -> bool:
    lowered = message.lower()
    return any(word in lowered for word in ["error", "invalid", "failed", "limit", "blocked", "unavailable"])


def _sanitize_leakcheck_target(value: str | None) -> str:
    target = _clean_text(value).lower()
    if not target:
        return ""
    if len(target) < 3 or len(target) > 253:
        return ""
    if any(ord(ch) > 127 for ch in target):
        return ""
    if any(ch.isspace() for ch in target):
        return ""
    if "," in target or ";" in target:
        return ""
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or "/" in target or "?" in target or "#" in target:
        return ""
    if _EMAIL_RE.fullmatch(target):
        return target
    if _HASH_RE.fullmatch(target):
        return target
    if _DOMAIN_RE.fullmatch(target):
        return target
    if _USERNAME_RE.fullmatch(target):
        return target
    return ""


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").split())
