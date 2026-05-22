from __future__ import annotations

import html
import re
from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup

from .scoring import classify_finding, detected_keywords


STACKEXCHANGE_SEARCH_URL = "https://api.stackexchange.com/2.3/search/advanced"
USER_AGENT = "SentinelAIIdentityLeakMonitor/1.0 (+stackexchange-public-search)"
REQUEST_TIMEOUT = 8
RESULTS_PER_QUERY = 5


@dataclass(frozen=True)
class StackExchangeTerm:
    field: str
    value: str
    query: str


def run_stackexchange_search(email: str, username: str, domain: str) -> tuple[list[dict], str, int]:
    terms = list(_build_stackexchange_terms(email, username, domain))
    if not terms:
        return [], "skipped", 0

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    findings = []
    sources_checked = 0
    successful_queries = 0
    had_failure = False

    for term in terms:
        sources_checked += 1
        items, ok = _stackexchange_api_search(session, term.query)
        successful_queries += 1 if ok else 0
        had_failure = had_failure or not ok

        for item in items:
            parsed = _parse_stackexchange_item(item)
            haystack = " ".join([parsed["title"], parsed["evidence"], parsed["url"]])
            keyword_text = " ".join([parsed["title"], parsed["evidence"]])
            if not _contains_value(haystack, term.value):
                continue

            keyword_values = detected_keywords(keyword_text)
            category, severity, confidence = classify_finding("stackexchange_public_search", True, False, keyword_values)
            findings.append(
                {
                    "source": "stackexchange_public_search",
                    "category": category,
                    "severity": severity,
                    "title": parsed["title"],
                    "url": parsed["url"],
                    "matched_field": term.field,
                    "matched_value": term.value,
                    "evidence": _snippet_around_match(haystack, term.value) or _compact_text(parsed["evidence"], 260),
                    "found_in_search": True,
                    "found_in_page": False,
                    "risk_keyword_detected": bool(keyword_values),
                    "detected_keywords": keyword_values,
                    "confidence": confidence,
                }
            )

    if successful_queries == 0 and had_failure:
        return findings, "failed", sources_checked
    return findings, "checked", sources_checked


def _build_stackexchange_terms(email: str, username: str, domain: str) -> list[StackExchangeTerm]:
    terms = []
    if email:
        terms.append(StackExchangeTerm("email", email, email))
    if username:
        terms.append(StackExchangeTerm("username", username, username))
    if domain:
        terms.append(StackExchangeTerm("domain", domain, domain))
        terms.append(StackExchangeTerm("domain", domain, f"@{domain}"))
    return terms


def _stackexchange_api_search(session: requests.Session, query: str) -> tuple[list[dict], bool]:
    try:
        response = session.get(
            STACKEXCHANGE_SEARCH_URL,
            params={
                "order": "desc",
                "sort": "relevance",
                "q": query,
                "site": "stackoverflow",
                "pagesize": RESULTS_PER_QUERY,
                "filter": "withbody",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in {400, 401, 403, 429, 502}:
            return [], False
        response.raise_for_status()
        return response.json().get("items", []), True
    except (requests.RequestException, ValueError):
        return [], False


def _parse_stackexchange_item(item: dict) -> dict:
    title = html.unescape(item.get("title") or "Stack Overflow result")
    body = _visible_text(item.get("body") or "")
    return {
        "title": _compact_text(title, 180),
        "url": item.get("link") or "",
        "evidence": _compact_text(body or title, 300),
    }


def _visible_text(markup: str) -> str:
    soup = BeautifulSoup(markup, "html.parser")
    for tag in soup(["script", "style", "noscript", "form"]):
        tag.decompose()
    return soup.get_text(" ", strip=True)


def _contains_value(text: str, value: str) -> bool:
    return bool(text and value and value.lower() in text.lower())


def _snippet_around_match(text: str, value: str, radius: int = 130) -> str:
    lowered = (text or "").lower()
    index = lowered.find(value.lower()) if value else -1
    if index == -1:
        return ""
    start = max(index - radius, 0)
    end = min(index + len(value) + radius, len(text))
    return _compact_text(text[start:end], 320)


def _compact_text(text: str, limit: int) -> str:
    compacted = re.sub(r"\s+", " ", text or "").strip()
    if len(compacted) <= limit:
        return compacted
    return f"{compacted[: limit - 3].rstrip()}..."
