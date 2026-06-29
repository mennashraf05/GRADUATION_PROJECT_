import os
import time
from urllib.parse import urlparse

import requests


VIRUSTOTAL_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/{domain}"
VIRUSTOTAL_TIMEOUT_SECONDS = 5
VIRUSTOTAL_CACHE_TTL_SECONDS = 6 * 60 * 60

_CACHE = {}


def extract_domain_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return hostname.lower().strip()


def _unavailable(domain, reputation, message):
    response = {
        "available": False,
        "source": "virustotal",
        "reputation": reputation,
        "message": message,
    }
    if domain:
        response["domain"] = domain
    return response


def get_virustotal_domain_report(domain):
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return _unavailable(
            domain,
            "unavailable",
            "VirusTotal API key is not configured",
        )

    try:
        response = requests.get(
            VIRUSTOTAL_DOMAIN_API.format(domain=domain),
            headers={"x-apikey": api_key},
            timeout=VIRUSTOTAL_TIMEOUT_SECONDS,
        )
    except (requests.Timeout, requests.RequestException):
        return _unavailable(
            domain,
            "unavailable",
            "VirusTotal reputation is currently unavailable",
        )

    if response.status_code == 429:
        return _unavailable(
            domain,
            "rate_limited",
            "VirusTotal rate limit reached",
        )

    if not response.ok:
        return _unavailable(
            domain,
            "unavailable",
            "VirusTotal reputation is currently unavailable",
        )

    try:
        return response.json()
    except ValueError:
        return _unavailable(
            domain,
            "unavailable",
            "VirusTotal reputation is currently unavailable",
        )


def parse_virustotal_reputation(response_json):
    if not isinstance(response_json, dict):
        return _unavailable("", "unavailable", "VirusTotal reputation is currently unavailable")

    if response_json.get("available") is False:
        return response_json

    data = response_json.get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    domain = str(data.get("id") or "").lower()

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)

    if malicious > 0:
        reputation = "malicious"
        message = "VirusTotal reports malicious detections for this domain"
    elif suspicious > 0:
        reputation = "suspicious"
        message = "VirusTotal reports suspicious detections for this domain"
    elif harmless > 0 or undetected > 0:
        reputation = "clean"
        message = "VirusTotal reports no malicious detections for this domain"
    else:
        reputation = "unknown"
        message = "VirusTotal has no clear reputation data for this domain"

    return {
        "available": True,
        "domain": domain,
        "source": "virustotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "reputation": reputation,
        "message": message,
    }


def get_domain_reputation(url):
    domain = extract_domain_from_url(url)
    if not domain:
        return _unavailable(
            "",
            "unavailable",
            "VirusTotal reputation is currently unavailable",
        )

    now = time.time()
    cached = _CACHE.get(domain)
    if cached and now - cached["timestamp"] < VIRUSTOTAL_CACHE_TTL_SECONDS:
        return cached["result"]

    report = get_virustotal_domain_report(domain)
    result = parse_virustotal_reputation(report)
    if "domain" not in result:
        result["domain"] = domain

    _CACHE[domain] = {"timestamp": now, "result": result}
    return result
