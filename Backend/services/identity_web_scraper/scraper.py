from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import requests
from bs4 import BeautifulSoup

from .gitlab_search import run_gitlab_search
from .leakcheck_public import run_leakcheck_public_scan
from .scoring import (
    calculate_risk_score,
    classify_finding,
    detected_keywords,
    finalize_findings,
    recommendation_for_findings,
    risk_level,
)
from .stackexchange_search import run_stackexchange_search


DUCKDUCKGO_SEARCH_URL = "https://html.duckduckgo.com/html/?q="
GITHUB_API_URL = "https://api.github.com/search"
USER_AGENT = "SentinelAIIdentityLeakMonitor/1.0 (+public-web-scan)"
MAX_RESULTS_PER_QUERY = 4
MAX_PAGES_TO_OPEN = 12
MAX_TEXT_CHARS = 140_000
REQUEST_TIMEOUT = 8


@dataclass(frozen=True)
class SearchTerm:
    field: str
    value: str
    query: str


def run_identity_web_scan(email: str | None = None, username: str | None = None, domain: str | None = None) -> dict:
    normalized = {
        "email": _clean(email).lower(),
        "username": _clean(username),
        "domain": _normalize_domain(domain),
    }
    if not any(normalized.values()):
        raise ValueError("At least one of email, username, or domain is required")

    duckduckgo_findings, duckduckgo_status, duckduckgo_checked = run_duckduckgo_scan(**normalized)
    github_findings, github_status, github_checked = run_github_search(**normalized)
    gitlab_findings, gitlab_status, gitlab_checked = run_gitlab_search(**normalized)
    stackexchange_findings, stackexchange_status, stackexchange_checked = run_stackexchange_search(**normalized)
    leakcheck_findings, leakcheck_status, leakcheck_checked = run_leakcheck_public_scan(**normalized)
    findings = _dedupe_findings(
        [
            *duckduckgo_findings,
            *github_findings,
            *gitlab_findings,
            *stackexchange_findings,
            *leakcheck_findings,
        ]
    )
    findings = finalize_findings(findings)

    score = calculate_risk_score(findings)
    level = risk_level(score)
    return {
        "status": "completed",
        "email": normalized["email"] or None,
        "username": normalized["username"] or None,
        "domain": normalized["domain"] or None,
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation_for_findings(findings, level),
        "sources_checked": duckduckgo_checked + github_checked + gitlab_checked + stackexchange_checked + leakcheck_checked,
        "source_status": {
            "duckduckgo": duckduckgo_status,
            "github": github_status,
            "gitlab": gitlab_status,
            "stackexchange": stackexchange_status,
            "leakcheck": leakcheck_status,
        },
        "total_findings": len(findings),
        "findings": findings,
    }


def run_duckduckgo_scan(email: str, username: str, domain: str) -> tuple[list[dict], str, int]:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})

    findings = []
    pages_opened = 0
    sources_checked = 0
    had_failure = False
    successful_queries = 0

    for term in _build_duckduckgo_terms(email, username, domain):
        results, ok = _search_duckduckgo(session, term.query)
        sources_checked += 1
        had_failure = had_failure or not ok
        successful_queries += 1 if ok else 0

        for result in results:
            found_in_search = _contains_value(result["title"], term.value) or _contains_value(result["snippet"], term.value)
            search_text = " ".join([result["title"], result["snippet"]])
            search_keywords = detected_keywords(search_text)
            page_text = ""
            found_in_page = False

            if pages_opened < MAX_PAGES_TO_OPEN and _is_http_url(result["url"]):
                page_text = _fetch_visible_page_text(session, result["url"])
                pages_opened += 1 if page_text else 0
                found_in_page = _contains_value(page_text, term.value)

            if not found_in_search and not found_in_page:
                continue

            keyword_values = sorted(set([*search_keywords, *detected_keywords(page_text)]))
            evidence_source = page_text if found_in_page else " ".join([result["title"], result["snippet"]])
            evidence = _snippet_around_match(evidence_source, term.value) or _compact_text(result["snippet"] or result["title"], 260)

            findings.append(
                _finding(
                    source="duckduckgo_public_web",
                    title=result["title"],
                    url=result["url"],
                    matched_field=term.field,
                    matched_value=term.value,
                    evidence=evidence,
                    found_in_search=found_in_search,
                    found_in_page=found_in_page,
                    detected_keyword_values=keyword_values,
                )
            )

    if sources_checked == 0:
        return findings, "skipped", sources_checked
    if successful_queries == 0 and had_failure:
        return findings, "failed", sources_checked
    return findings, "checked", sources_checked


def run_github_search(email: str, username: str, domain: str) -> tuple[list[dict], str, int]:
    terms = list(_build_github_terms(email, username, domain))
    if not terms:
        return [], "skipped", 0

    token = os.getenv("GITHUB_TOKEN", "").strip()
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    if token:
        session.headers["Authorization"] = f"Bearer {token}"

    findings = []
    sources_checked = 0
    had_failure = False
    successful_queries = 0

    if username:
        sources_checked += 1
        profile, ok = _github_user_lookup(session, username)
        had_failure = had_failure or not ok
        successful_queries += 1 if ok else 0
        if profile:
            parsed = _parse_github_user(profile)
            haystack = " ".join([parsed["title"], parsed["evidence"], parsed["url"]])
            if _contains_value(haystack, username):
                keyword_values = detected_keywords(" ".join([parsed["title"], parsed["evidence"]]))
                findings.append(
                    _finding(
                        source="github_public_search",
                        title=parsed["title"],
                        url=parsed["url"],
                        matched_field="username",
                        matched_value=username,
                        evidence=_snippet_around_match(haystack, username) or _compact_text(parsed["evidence"], 260),
                        found_in_search=True,
                        found_in_page=False,
                        detected_keyword_values=keyword_values,
                    )
                )

    for term in terms:
        search_types = ["issues", "repositories"]
        if token:
            search_types.append("code")

        for search_type in search_types:
            sources_checked += 1
            items, ok = _github_api_search(session, search_type, term.query)
            had_failure = had_failure or not ok
            successful_queries += 1 if ok else 0
            for item in items:
                parsed = _parse_github_item(search_type, item)
                haystack = " ".join([parsed["title"], parsed["evidence"], parsed["url"]])
                keyword_text = " ".join([parsed["title"], parsed["evidence"]])
                found_in_search = _contains_value(haystack, term.value)
                if not found_in_search:
                    continue

                keyword_values = detected_keywords(keyword_text)
                findings.append(
                    _finding(
                        source="github_public_search",
                        title=parsed["title"],
                        url=parsed["url"],
                        matched_field=term.field,
                        matched_value=term.value,
                        evidence=_snippet_around_match(haystack, term.value) or _compact_text(parsed["evidence"], 260),
                        found_in_search=True,
                        found_in_page=False,
                        detected_keyword_values=keyword_values,
                    )
                )

    if sources_checked == 0:
        return findings, "skipped", sources_checked
    if successful_queries == 0 and had_failure:
        return findings, "failed", sources_checked
    return findings, "checked", sources_checked


def _build_duckduckgo_terms(email: str, username: str, domain: str) -> Iterable[SearchTerm]:
    if email:
        for query in [f'"{email}"', f'"{email}" leak', f'"{email}" paste', f'"{email}" exposed', f'"{email}" breach']:
            yield SearchTerm("email", email, query)
    if username:
        for query in [f'"{username}" leak', f'"{username}" paste', f'"{username}" breach', f'"{username}" exposed']:
            yield SearchTerm("username", username, query)
    if domain:
        for query in [f'"{domain}" leak', f'"{domain}" database', f'"{domain}" exposed', f'"@{domain}"']:
            yield SearchTerm("domain", domain, query)


def _build_github_terms(email: str, username: str, domain: str) -> Iterable[SearchTerm]:
    if email:
        yield SearchTerm("email", email, f'"{email}"')
    if username:
        yield SearchTerm("username", username, f'"{username}"')
    if domain:
        yield SearchTerm("domain", domain, f'"{domain}"')
        yield SearchTerm("domain", domain, f'"@{domain}"')


def _search_duckduckgo(session: requests.Session, query: str) -> tuple[list[dict], bool]:
    try:
        response = session.get(f"{DUCKDUCKGO_SEARCH_URL}{quote_plus(query)}", timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException:
        return [], False

    soup = BeautifulSoup(response.text, "html.parser")
    results = []
    for result in soup.select(".result")[:MAX_RESULTS_PER_QUERY]:
        link = result.select_one(".result__a")
        if not link:
            continue
        url = _extract_duckduckgo_url(link.get("href", ""))
        if not _is_http_url(url):
            continue
        snippet_node = result.select_one(".result__snippet")
        results.append(
            {
                "title": _compact_text(link.get_text(" ", strip=True), 180),
                "url": url,
                "snippet": _compact_text(snippet_node.get_text(" ", strip=True) if snippet_node else "", 300),
                "query": query,
            }
        )
    return results, True


def _github_api_search(session: requests.Session, search_type: str, query: str) -> tuple[list[dict], bool]:
    url = f"{GITHUB_API_URL}/{search_type}"
    params = {"q": query, "per_page": 5}
    try:
        response = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code in {401, 403, 422}:
            return [], False
        response.raise_for_status()
        return response.json().get("items", []), True
    except (requests.RequestException, ValueError):
        return [], False


def _github_user_lookup(session: requests.Session, username: str) -> tuple[dict | None, bool]:
    try:
        response = session.get(f"https://api.github.com/users/{username}", timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            return None, True
        if response.status_code in {401, 403, 422}:
            return None, False
        response.raise_for_status()
        return response.json(), True
    except (requests.RequestException, ValueError):
        return None, False


def _parse_github_user(item: dict) -> dict:
    login = item.get("login") or "GitHub user"
    display_name = item.get("name") or ""
    bio = item.get("bio") or ""
    public_repos = item.get("public_repos")
    evidence_parts = [login, display_name, bio]
    if public_repos is not None:
        evidence_parts.append(f"Public repositories: {public_repos}")
    return {
        "title": _compact_text(f"GitHub public profile: {login}", 180),
        "url": item.get("html_url") or "",
        "evidence": _compact_text(" | ".join(part for part in evidence_parts if part), 300),
    }


def _parse_github_item(search_type: str, item: dict) -> dict:
    if search_type == "issues":
        return {
            "title": _compact_text(item.get("title") or "GitHub issue/discussion result", 180),
            "url": item.get("html_url") or "",
            "evidence": _compact_text(item.get("body") or item.get("title") or "", 300),
        }
    if search_type == "repositories":
        return {
            "title": _compact_text(item.get("full_name") or item.get("name") or "GitHub repository result", 180),
            "url": item.get("html_url") or "",
            "evidence": _compact_text(item.get("description") or item.get("full_name") or "", 300),
        }
    repository = item.get("repository") or {}
    path = item.get("path") or ""
    return {
        "title": _compact_text(f"{repository.get('full_name', 'GitHub code result')} / {path}", 180),
        "url": item.get("html_url") or "",
        "evidence": _compact_text(f"Public GitHub code search metadata match in {path}. File contents were not downloaded.", 300),
    }


def _fetch_visible_page_text(session: requests.Session, url: str) -> str:
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, stream=True)
        content_type = response.headers.get("Content-Type", "").lower()
        if response.status_code >= 400 or "text/html" not in content_type:
            response.close()
            return ""
        html = response.raw.read(MAX_TEXT_CHARS, decode_content=True)
    except requests.RequestException:
        return ""

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "form"]):
        tag.decompose()
    return _compact_text(soup.get_text(" ", strip=True), MAX_TEXT_CHARS)


def _finding(
    source: str,
    title: str,
    url: str,
    matched_field: str,
    matched_value: str,
    evidence: str,
    found_in_search: bool,
    found_in_page: bool,
    detected_keyword_values: list[str],
) -> dict:
    category, severity, confidence = classify_finding(source, found_in_search, found_in_page, detected_keyword_values)
    return {
        "source": source,
        "category": category,
        "severity": severity,
        "title": title,
        "url": url,
        "matched_field": matched_field,
        "matched_value": matched_value,
        "evidence": _compact_text(evidence, 320),
        "found_in_search": found_in_search,
        "found_in_page": found_in_page,
        "risk_keyword_detected": bool(detected_keyword_values),
        "detected_keywords": detected_keyword_values,
        "confidence": confidence,
    }


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    for finding in findings:
        key = (finding.get("url"), finding.get("matched_field"), str(finding.get("matched_value", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _extract_duckduckgo_url(href: str) -> str:
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        return unquote(parse_qs(parsed.query).get("uddg", [""])[0])
    return href


def _contains_value(text: str, value: str) -> bool:
    return bool(text and value and value.lower() in text.lower())


def _has_risk_keyword(text: str) -> bool:
    return bool(detected_keywords(text))


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


def _clean(value: str | None) -> str:
    return (value or "").strip()


def _normalize_domain(value: str | None) -> str:
    cleaned = _clean(value).lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    return cleaned.split("/")[0].strip().lstrip("@")


def _is_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
