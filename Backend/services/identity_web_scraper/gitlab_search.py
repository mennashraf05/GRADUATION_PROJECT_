from __future__ import annotations

import os
import re
from dataclasses import dataclass

import requests
from dotenv import load_dotenv

from .scoring import classify_finding, detected_keywords

BACKEND_ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
GITLAB_API_URL = "https://gitlab.com/api/v4/search"
USER_AGENT = "SentinelAIIdentityLeakMonitor/1.0 (+gitlab-public-search)"
REQUEST_TIMEOUT = 8
RESULTS_PER_QUERY = 3
SEARCH_SCOPES = ["projects", "issues", "merge_requests", "snippets"]
EXPOSURE_KEYWORDS = [
    "leak",
    "leaked",
    "breach",
    "exposed",
    "database",
    "paste",
    "credentials",
    "token",
    "secret",
]


@dataclass(frozen=True)
class GitLabTerm:
    field: str
    value: str
    query: str


def run_gitlab_search(
    email: str, username: str, domain: str
) -> tuple[list[dict], str, int]:
    token = os.getenv("GITLAB_TOKEN", "").strip()
    if not token:
        load_dotenv(BACKEND_ENV_PATH, override=True)
        token = os.getenv("GITLAB_TOKEN", "").strip()
    if not token:
        return [], {"status": "skipped", "reason": "missing GITLAB_TOKEN"}, 0

    terms = list(_build_gitlab_terms(email, username, domain))
    if not terms:
        return [], {"status": "skipped", "reason": "no GitLab search terms"}, 0

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "PRIVATE-TOKEN": token})

    findings = []
    sources_checked = 0
    successful_queries = 0
    had_failure = False

    for term in terms:
        for scope in SEARCH_SCOPES:
            sources_checked += 1
            items, ok = _gitlab_api_search(session, scope, term.query)
            successful_queries += 1 if ok else 0
            had_failure = had_failure or not ok

            for item in items:
                parsed = _parse_gitlab_item(scope, item)
                haystack = " ".join(
                    [parsed["title"], parsed["evidence"], parsed["url"]]
                )
                keyword_text = " ".join([parsed["title"], parsed["evidence"]])
                if not _contains_value(haystack, term.value):
                    continue

                keyword_values = detected_keywords(keyword_text)
                findings.append(
                    _finding(
                        title=parsed["title"],
                        url=parsed["url"],
                        matched_field=term.field,
                        matched_value=term.value,
                        evidence=_snippet_around_match(haystack, term.value)
                        or _compact_text(parsed["evidence"], 260),
                        detected_keyword_values=keyword_values,
                    )
                )

    if successful_queries == 0 and had_failure:
        return findings, "failed", sources_checked
    return findings, "checked", sources_checked


def _build_gitlab_terms(email: str, username: str, domain: str) -> list[GitLabTerm]:
    terms = []
    if email:
        terms.extend(_terms_for_value("email", email))
    if username:
        terms.extend(_terms_for_value("username", username))
    if domain:
        terms.extend(_terms_for_value("domain", domain))
        terms.extend(_terms_for_value("domain", f"@{domain}", matched_value=domain))
    return terms


def _terms_for_value(
    field: str, query_value: str, matched_value: str | None = None
) -> list[GitLabTerm]:
    value = matched_value or query_value
    terms = [GitLabTerm(field, value, query_value)]
    terms.extend(
        GitLabTerm(field, value, f"{query_value} {keyword}")
        for keyword in EXPOSURE_KEYWORDS
    )
    return terms


def _gitlab_api_search(
    session: requests.Session, scope: str, query: str
) -> tuple[list[dict], bool]:
    try:
        response = session.get(
            GITLAB_API_URL,
            params={"scope": scope, "search": query, "per_page": RESULTS_PER_QUERY},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in {401, 403, 404, 422, 429}:
            return [], False
        response.raise_for_status()
        return response.json() if isinstance(response.json(), list) else [], True
    except (requests.RequestException, ValueError):
        return [], False


def _parse_gitlab_item(scope: str, item: dict) -> dict:
    if scope == "projects":
        title = (
            item.get("path_with_namespace")
            or item.get("name_with_namespace")
            or item.get("name")
            or "GitLab project result"
        )
        evidence = item.get("description") or title
        url = item.get("web_url") or ""
    elif scope in {"issues", "merge_requests"}:
        title = item.get("title") or f"GitLab {scope.replace('_', ' ')} result"
        evidence = item.get("description") or title
        url = item.get("web_url") or ""
    else:
        title = item.get("title") or item.get("file_name") or "GitLab snippet result"
        evidence = item.get("description") or item.get("file_name") or title
        url = item.get("web_url") or ""

    return {
        "title": _compact_text(title, 180),
        "url": url,
        "evidence": _compact_text(evidence, 300),
    }


def _finding(
    title: str,
    url: str,
    matched_field: str,
    matched_value: str,
    evidence: str,
    detected_keyword_values: list[str],
) -> dict:
    category, severity, confidence = classify_finding(
        "gitlab_public_search", True, False, detected_keyword_values
    )
    return {
        "source": "gitlab_public_search",
        "category": category,
        "severity": severity,
        "title": title,
        "url": url,
        "matched_field": matched_field,
        "matched_value": matched_value,
        "evidence": _compact_text(evidence, 320),
        "found_in_search": True,
        "found_in_page": False,
        "risk_keyword_detected": bool(detected_keyword_values),
        "detected_keywords": detected_keyword_values,
        "confidence": confidence,
    }


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
