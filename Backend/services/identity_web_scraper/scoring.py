import re


RISK_KEYWORDS = {
    "leak",
    "leaked",
    "dump",
    "database",
    "breach",
    "breached",
    "exposed",
    "paste",
    "credentials",
    "combo",
    "token",
    "secret",
}

CODE_EXPOSURE_SOURCES = {"github_public_search", "gitlab_public_search"}
PUBLIC_MENTION_SOURCES = {"github_public_search", "gitlab_public_search", "stackexchange_public_search"}


def detected_keywords(text: str) -> list[str]:
    lowered = (text or "").lower()
    found = [keyword for keyword in sorted(RISK_KEYWORDS) if re.search(rf"\b{re.escape(keyword)}\b", lowered)]
    return found


def classify_finding(
    source: str,
    found_in_search: bool,
    found_in_page: bool,
    detected_keyword_values: list[str],
) -> tuple[str, str, int]:
    has_keywords = bool(detected_keyword_values)

    if found_in_page and has_keywords:
        return "confirmed_exposure", "High", _confidence(90, source)

    if has_keywords:
        severity = "High" if source in CODE_EXPOSURE_SOURCES else "Medium"
        return "possible_exposure", severity, _confidence(75 if severity == "High" else 65, source)

    if found_in_page and source == "duckduckgo_public_web":
        return "possible_exposure", "Medium", 60

    if found_in_search or found_in_page:
        return "public_mention", "Low", 55

    return "public_mention", "Low", 35


def calculate_risk_score(findings: list[dict]) -> int:
    if not findings:
        return 0

    public_mentions = [finding for finding in findings if finding.get("category") == "public_mention"]
    breach_findings = [finding for finding in findings if finding.get("category") == "confirmed_breach"]
    exposure_findings = [
        finding
        for finding in findings
        if finding.get("category") in {"possible_exposure", "confirmed_exposure"}
    ]

    score = min(len(public_mentions) * 5, 20)

    if breach_findings:
        score += 60
        breach_sources = {finding.get("source") for finding in breach_findings if finding.get("source")}
        score += max(len(breach_sources) - 1, 0) * 10

    for finding in exposure_findings:
        if finding.get("category") == "confirmed_exposure":
            score += 50
        elif finding.get("category") == "possible_exposure":
            score += 25

        if finding.get("source") in CODE_EXPOSURE_SOURCES:
            score += 10

    exposure_urls = {finding.get("url") for finding in exposure_findings if finding.get("url")}
    exposure_sources = {finding.get("source") for finding in exposure_findings if finding.get("source")}
    if len(exposure_urls) >= 2:
        score += 15
    if len(exposure_sources) >= 2:
        score += 20

    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def recommendation_for_findings(findings: list[dict], level: str) -> str:
    if any(finding.get("category") == "confirmed_breach" for finding in findings):
        return "Your identity data was found in known breach metadata. Review affected accounts and secure related services."
    if findings and all(finding.get("category") == "public_mention" for finding in findings):
        return "Public references were found, but no confirmed exposure context was detected."
    if any(finding.get("category") == "confirmed_exposure" for finding in findings):
        if level == "Critical":
            return "Multiple strong exposure indicators were detected. Immediate review is recommended."
        return "Confirmed identity exposure was detected. Review the exposed pages and take action."
    if any(finding.get("category") == "possible_exposure" for finding in findings):
        return "Potential exposure context was found. Review the evidence and keep monitoring."
    return "No confirmed public exposure was found. Continue periodic monitoring."


def recommendation_for_level(level: str) -> str:
    recommendations = {
        "Low": "No confirmed public exposure was found. Continue periodic monitoring.",
        "Medium": "Public mentions were found. Review the evidence and keep monitoring.",
        "High": "Potential exposure context was found. Review the evidence and take action if needed.",
        "Critical": "Multiple strong exposure indicators were detected. Immediate review is recommended.",
    }
    return recommendations.get(level, recommendations["Low"])


def finalize_findings(findings: list[dict]) -> list[dict]:
    finalized = []
    for finding in findings:
        updated = dict(finding)
        if updated.get("category") == "confirmed_breach":
            updated["severity"] = "High"
            updated["confidence"] = 95
            updated["risk_keyword_detected"] = True
            updated["detected_keywords"] = list(updated.get("detected_keywords") or ["breach"])
            finalized.append(updated)
            continue

        keyword_values = list(updated.get("detected_keywords") or [])
        category, severity, confidence = classify_finding(
            str(updated.get("source") or ""),
            bool(updated.get("found_in_search")),
            bool(updated.get("found_in_page")),
            keyword_values,
        )
        updated["category"] = category
        updated["severity"] = severity
        updated["confidence"] = min(int(updated.get("confidence") or confidence), confidence)
        updated["risk_keyword_detected"] = bool(keyword_values)
        updated["detected_keywords"] = keyword_values
        finalized.append(updated)
    return finalized


def _confidence(base: int, source: str) -> int:
    if source in CODE_EXPOSURE_SOURCES:
        base += 5
    return min(base, 100)
