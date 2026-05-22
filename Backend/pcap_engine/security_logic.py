from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Dict, Mapping, Optional
from urllib.parse import unquote_plus


LABEL_SEVERITY: Dict[str, str] = {
    "benign": "Low",
    "mqtt_publish": "Low",
    "thing_speak": "Low",
    "wipro_bulb": "Low",
    "portscan": "Medium",
    "nmap_fin_scan": "Medium",
    "nmap_os_detection": "Medium",
    "nmap_tcp_scan": "Medium",
    "nmap_udp_scan": "Medium",
    "nmap_xmas_tree_scan": "Medium",
    "ddos": "Critical",
    "ddos_slowloris": "High",
    "dos": "High",
    "dos_goldeneye": "High",
    "dos_hulk": "High",
    "dos_slowhttptest": "High",
    "dos_slowloris": "High",
    "dos_syn_hping": "Critical",
    "ftp_patator": "High",
    "ssh_patator": "High",
    "webattack_bruteforce": "High",
    "webattack_xss": "High",
    "webattack_sql_injection": "High",
    "metasploit_brute_force_ssh": "High",
    "bot": "Critical",
    "heartbleed": "Critical",
    "arp_poisioning": "High",
    "arp_poisoning": "High",
}

SEVERITY_BASE_SCORES: Dict[str, float] = {
    "LOW": 0.20,
    "MEDIUM": 0.45,
    "HIGH": 0.75,
    "CRITICAL": 0.95,
}

SEVERITY_RISK: Dict[str, str] = {
    "Low": "LOW",
    "Medium": "MEDIUM",
    "High": "HIGH",
    "Critical": "CRITICAL",
}

CONFIDENCE_SUSPICIOUS = 0.70
CONFIDENCE_CONFIRM = 0.88
RARE_CONFIRM = 0.95

CONFIDENCE_MODE_PRESETS: Dict[str, tuple[float, float]] = {
    "balanced": (CONFIDENCE_SUSPICIOUS, CONFIDENCE_CONFIRM),
    "strict": (0.78, 0.92),
    "relaxed": (0.62, 0.84),
}


def _normalize_confidence_mode(value: Optional[str]) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "strict":
        return "strict"
    if normalized in {"relaxed", "lenient", "loose"}:
        return "relaxed"
    return "balanced"

HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443}
TLS_PORTS = {443, 465, 563, 636, 853, 8443, 993, 995}
FAILED_STATES = {"REJ", "S0", "RSTO", "RSTR", "SH", "SHR"}

RARE_LABELS = {
    "heartbleed",
    "webattack_sql_injection",
    "nmap_fin_scan",
    "metasploit_brute_force_ssh",
    "wipro_bulb",
    "ddos_slowloris",
}

HTTP_DOS_LABELS = {
    "dos_hulk",
    "dos_slowloris",
    "dos_slowhttptest",
    "dos_goldeneye",
}

DOS_FAMILY_LABELS = HTTP_DOS_LABELS | {
    "dos",
    "ddos",
    "ddos_slowloris",
    "dos_syn_hping",
}

NON_ALERT_SUSPICIOUS_LABELS = {
    "thing_speak",
    "mqtt_publish",
    "wipro_bulb",
}

SCAN_LABELS = {
    "portscan",
    "nmap_fin_scan",
    "nmap_os_detection",
    "nmap_tcp_scan",
    "nmap_udp_scan",
    "nmap_xmas_tree_scan",
}

BRUTE_FORCE_LABELS = {
    "ssh_patator",
    "metasploit_brute_force_ssh",
    "ftp_patator",
}

WEBATTACK_LABELS = {
    "webattack_bruteforce",
    "webattack_sql_injection",
    "webattack_xss",
}

REASON_PREFIXES = {
    "portscan": "Port scan suspected",
    "nmap_fin_scan": "Nmap FIN scan suspected",
    "nmap_os_detection": "Nmap OS detection suspected",
    "nmap_tcp_scan": "Nmap TCP scan suspected",
    "nmap_udp_scan": "Nmap UDP scan suspected",
    "nmap_xmas_tree_scan": "Nmap XMAS scan suspected",
    "ssh_patator": "SSH brute-force suspected",
    "metasploit_brute_force_ssh": "Metasploit SSH brute-force suspected",
    "ftp_patator": "FTP brute-force suspected",
    "ddos": "DDoS suspected",
    "ddos_slowloris": "DDoS Slowloris suspected",
    "dos": "DoS suspected",
    "dos_goldeneye": "GoldenEye HTTP DoS suspected",
    "dos_hulk": "Hulk HTTP DoS suspected",
    "dos_slowhttptest": "SlowHTTPTest suspected",
    "dos_slowloris": "Slowloris HTTP DoS suspected",
    "dos_syn_hping": "SYN flood suspected",
    "webattack_bruteforce": "Web login brute-force suspected",
    "webattack_sql_injection": "SQL injection activity suspected",
    "webattack_xss": "Cross-site scripting activity suspected",
    "heartbleed": "Heartbleed-like TLS exploitation suspected",
    "bot": "Bot activity suspected",
    "mqtt_publish": "MQTT publish pattern observed",
    "thing_speak": "ThingSpeak activity observed",
    "wipro_bulb": "Wipro bulb activity observed",
    "arp_poisioning": "ARP poisoning suspected",
    "arp_poisoning": "ARP poisoning suspected",
}

LOCAL_NOISE_PORTS = {53, 67, 68, 123, 137, 138, 139, 445, 1900, 5353, 5355}
INTERNAL_AUTH_PORTS = {88, 135, 139, 389, 445, 464, 3268, 3269}
INTERNAL_AUTH_SERVICES = {
    "kerberos",
    "krb_tcp",
    "krb_udp",
    "krb5",
    "ldap",
    "ldap_ssl",
    "ntlm",
    "dce_rpc",
    "rpc",
    "msrpc",
    "epmap",
    "smb",
    "smb_tcp",
}

VERDICT_RANK: Dict[str, int] = {
    "Normal": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def normalize_label(lbl) -> str:
    if lbl is None:
        return ""
    return str(lbl).strip().lower()


def _safe_conf(ml_conf: float) -> float:
    try:
        return max(0.0, min(1.0, float(ml_conf or 0.0)))
    except (TypeError, ValueError):
        return 0.0


def _safe_port(dst_port) -> int:
    try:
        return int(float(dst_port or 0))
    except (TypeError, ValueError):
        return 0


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _clean_text(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return ""
    return text


def _row_text(row: Optional[Mapping[str, object]], key: str) -> str:
    if row is None:
        return ""
    return _clean_text(row.get(key))


def _row_float(row: Optional[Mapping[str, object]], key: str, default: float = 0.0) -> float:
    if row is None:
        return default
    return _safe_float(row.get(key), default)


def _row_int(row: Optional[Mapping[str, object]], key: str, default: int = 0) -> int:
    if row is None:
        return default
    return _safe_int(row.get(key), default)


def _http_context_score(row: Optional[Mapping[str, object]], dst_port: int) -> int:
    score = 0
    service = _row_text(row, "service").lower()
    if dst_port in HTTP_PORTS:
        score += 1
    if service in {"http", "https", "ssl"}:
        score += 1
    if _row_int(row, "http_request_count") > 0 or _row_text(row, "http_top_host") or _row_text(row, "http_top_uri"):
        score += 1
    return score


def _target_conn_count(row: Optional[Mapping[str, object]]) -> int:
    return max(
        _row_int(row, "src_dst_port_conn_count"),
        _row_int(row, "src_dst_conn_count"),
    )


def _target_short_ratio(row: Optional[Mapping[str, object]]) -> float:
    return max(
        _row_float(row, "src_dst_port_short_ratio"),
        _row_float(row, "src_dst_short_ratio"),
        _row_float(row, "src_short_ratio"),
    )


def _target_failed_ratio(row: Optional[Mapping[str, object]]) -> float:
    return max(
        _row_float(row, "src_dst_port_failed_ratio"),
        _row_float(row, "src_dst_failed_ratio"),
        _row_float(row, "src_failed_ratio"),
    )


def _target_concentration_ratio(row: Optional[Mapping[str, object]]) -> float:
    return max(
        _row_float(row, "src_dst_port_conn_share"),
        _row_float(row, "src_dst_conn_share"),
    )


def _has_http_evidence(row: Optional[Mapping[str, object]]) -> bool:
    return (
        _row_int(row, "http_request_count") > 0
        or bool(_row_text(row, "http_top_host"))
        or bool(_row_text(row, "http_top_uri"))
    )


def _has_ssl_evidence(row: Optional[Mapping[str, object]]) -> bool:
    return (
        _row_int(row, "ssl_event_count") > 0
        or bool(_row_text(row, "ssl_top_sni"))
        or bool(_row_text(row, "ssl_top_cipher"))
    )


def _context_blob(row: Optional[Mapping[str, object]]) -> str:
    if row is None:
        return ""
    parts = [
        _row_text(row, "service"),
        _row_text(row, "http_top_host"),
        _row_text(row, "http_top_uri"),
        _row_text(row, "ssl_top_sni"),
        _row_text(row, "ssl_top_cipher"),
    ]
    return " ".join(part for part in parts if part).strip().lower()


def _context_has_any_token(
    row: Optional[Mapping[str, object]],
    tokens: tuple[str, ...],
) -> bool:
    blob = _context_blob(row)
    if not blob:
        return False
    return any(token in blob for token in tokens)


def _normalized_http_uri(row: Optional[Mapping[str, object]]) -> str:
    uri = _row_text(row, "http_top_uri")
    if not uri:
        return ""
    try:
        return unquote_plus(uri).strip().lower()
    except Exception:
        return uri.strip().lower()


def _looks_like_login_http_uri(row: Optional[Mapping[str, object]]) -> bool:
    uri = _normalized_http_uri(row)
    if not uri:
        return False
    return any(
        token in uri
        for token in (
            "/login",
            "login.php",
            "/signin",
            "/sign-in",
            "/auth",
            "user/login",
        )
    )


def _has_clear_sqli_uri_payload(row: Optional[Mapping[str, object]]) -> bool:
    uri = _normalized_http_uri(row)
    if not uri:
        return False
    return any(
        token in uri
        for token in (
            "' or 1=1",
            "\" or 1=1",
            "' or '1'='1",
            "\" or \"1\"=\"1",
            "union select",
            "information_schema",
            "sleep(",
            "benchmark(",
            "@@version",
            "load_file(",
            "into outfile",
        )
    )


def _has_clear_xss_uri_payload(row: Optional[Mapping[str, object]]) -> bool:
    uri = _normalized_http_uri(row)
    if not uri:
        return False
    if any(token in uri for token in ("<script", "</script", "javascript:", "onerror=", "onload=")):
        return True
    return (
        any(token in uri for token in ("<img", "<svg"))
        and "alert(" in uri
    )


def _has_heuristic_support(row: Optional[Mapping[str, object]]) -> bool:
    if row is None:
        return False
    heuristic_score = _row_float(row, "heuristic_score")
    heuristic_type = _row_text(row, "heuristic_type").lower()
    return heuristic_score > 0.0 or heuristic_type not in {"", "none"}


def _is_web_like_target(row: Optional[Mapping[str, object]], dst_port: int) -> bool:
    service = _row_text(row, "service").lower()
    dport = _safe_port(dst_port)
    return dport in HTTP_PORTS or service in {"http", "https", "ssl"}


def _is_dns_like_target(row: Optional[Mapping[str, object]], dst_port: int) -> bool:
    service = _row_text(row, "service").lower()
    dport = _safe_port(dst_port)
    return dport == 53 or service == "dns"


def _is_rpc_like_service(row: Optional[Mapping[str, object]]) -> bool:
    service = _row_text(row, "service").lower()
    return service in {"dce_rpc", "rpc", "msrpc", "epmap"} or service.endswith("_rpc")


def _has_trivial_web_http_context(
    row: Optional[Mapping[str, object]],
    dst_port: int,
    *,
    syn_score: int | None = None,
    burst_score: int | None = None,
) -> bool:
    if row is None:
        return False
    dport = _safe_port(dst_port)
    if not _is_web_like_target(row, dport):
        return False
    http_request_count = _row_int(row, "http_request_count")
    failed_ratio = _target_failed_ratio(row)
    if syn_score is None:
        syn_score = _syn_context_score(row)
    if burst_score is None:
        burst_score = _burst_score(row)
    return (
        http_request_count <= 1
        and not _has_heuristic_support(row)
        and syn_score < 2
        and failed_ratio < 0.20
        and burst_score < 6
    )


def _has_benign_http_browsing_aggregation_shape(
    row: Optional[Mapping[str, object]],
    dst_port: int,
    *,
    syn_score: int | None = None,
    burst_score: int | None = None,
) -> bool:
    if row is None:
        return False
    dport = _safe_port(dst_port)
    if not _is_web_like_target(row, dport):
        return False

    http_request_count = _row_int(row, "http_request_count")
    target_conn = _target_conn_count(row)
    target_concentration = _target_concentration_ratio(row)
    src_conn_count = _row_int(row, "src_conn_count")
    src_unique_targets = _row_int(row, "src_unique_targets")
    failed_ratio = _target_failed_ratio(row)
    http_status_failures = _row_int(row, "http_status_4xx_5xx_count")
    conn_state = _row_text(row, "conn_state").upper()
    duration = _row_float(row, "duration")
    http_top_host = _row_text(row, "http_top_host")
    dst_ip = _row_text(row, "dst_ip")
    orig_bytes = _row_float(row, "orig_bytes")
    resp_bytes = _row_float(row, "resp_bytes")
    has_named_host = bool(http_top_host and "." in http_top_host and any(ch.isalpha() for ch in http_top_host))
    external_target = bool(dst_ip) and not _is_private_ip(dst_ip)
    response_heavy = resp_bytes >= max(4096.0, orig_bytes * 3.0)

    if syn_score is None:
        syn_score = _syn_context_score(row)
    if burst_score is None:
        burst_score = _burst_score(row)

    browsing_context_hits = 0
    if has_named_host:
        browsing_context_hits += 1
    if external_target:
        browsing_context_hits += 1
    if response_heavy:
        browsing_context_hits += 1
    if conn_state == "SF" and http_status_failures == 0:
        browsing_context_hits += 1

    # Narrow guard for benign outbound browsing that got aggregated into a
    # single web target window. Real floods should usually fail one of these
    # checks via higher SYN/failure pressure, heuristics, or stronger burst.
    return bool(
        http_request_count >= 6
        and 12 <= target_conn <= 80
        and src_conn_count >= max(40, target_conn + 20)
        and src_unique_targets >= 4
        and 0.35 <= target_concentration < 0.60
        and not _has_heuristic_support(row)
        and syn_score < 2
        and failed_ratio < 0.20
        and http_status_failures <= 1
        and burst_score < 7
        and (not conn_state or conn_state == "SF")
        and duration < 10
        and browsing_context_hits >= 2
    )


def _has_diluted_internal_http_victim_path_shape(
    lbl: str,
    row: Optional[Mapping[str, object]],
    dst_port: int,
    *,
    syn_score: int | None = None,
    burst_score: int | None = None,
) -> bool:
    key = normalize_label(lbl)
    if row is None or key not in {"dos_hulk", "dos_slowloris"}:
        return False

    dport = _safe_port(dst_port)
    if not _is_web_like_target(row, dport) or not _is_internal_pair(row):
        return False
    if _fanout_is_scan_like(row):
        return False

    target_conn = _target_conn_count(row)
    target_concentration = _target_concentration_ratio(row)
    src_unique_ports = _row_int(row, "src_unique_ports")
    src_unique_targets = _row_int(row, "src_unique_targets")
    http_request_count = _row_int(row, "http_request_count")
    failed_ratio = _target_failed_ratio(row)
    flow_pps = _row_float(row, "flow_pkts_per_sec")
    bytes_per_s = _row_float(row, "bytes_per_s")
    duration = _row_float(row, "duration")

    if syn_score is None:
        syn_score = _syn_context_score(row)
    if burst_score is None:
        burst_score = _burst_score(row)

    if _has_benign_http_browsing_aggregation_shape(
        row,
        dport,
        syn_score=syn_score,
        burst_score=burst_score,
    ):
        return False

    if (
        src_unique_ports > 2
        or src_unique_targets > 3
        or target_concentration < 0.12
        or target_concentration >= 0.30
        or failed_ratio >= 0.35
    ):
        return False

    if key == "dos_hulk":
        return bool(
            http_request_count >= 12
            and target_conn >= 10
            and (burst_score >= 3 or flow_pps >= 35 or bytes_per_s >= 100_000)
        )

    return bool(
        duration >= 18
        and http_request_count >= 3
        and target_conn >= 8
        and flow_pps <= 25
        and bytes_per_s <= 60_000
    )


def _has_trivial_dns_flood_context(
    row: Optional[Mapping[str, object]],
    dst_port: int,
) -> bool:
    if row is None:
        return False
    if not _is_dns_like_target(row, dst_port):
        return False
    # A single DNS query without corroboration is too weak to confirm a DNS flood.
    return (
        _row_int(row, "dns_query_count") <= 1
        and _row_int(row, "dns_unique_queries") <= 1
        and not _has_heuristic_support(row)
    )


def _has_internal_rpc_portscan_chatter_shape(
    row: Optional[Mapping[str, object]]
) -> bool:
    if row is None:
        return False
    if not _is_internal_pair(row) or not _is_rpc_like_service(row):
        return False
    if _has_heuristic_support(row):
        return False
    # Match only the observed benign RPC chatter shape: internal traffic,
    # RPC-like service on an ephemeral port, modest port fanout, one dominant
    # peer conversation, and no reset-heavy signal.
    dport = _safe_port(_row_int(row, "dst_port"))
    conn_state = _row_text(row, "conn_state").upper()
    return (
        dport >= 49152
        and _row_int(row, "src_unique_ports") <= 15
        and _row_int(row, "src_unique_targets") >= 10
        and _row_float(row, "src_short_ratio") <= 0.50
        and _row_int(row, "src_dst_conn_count") >= 50
        and _row_float(row, "src_dst_conn_share") >= 0.70
        and _row_int(row, "src_dst_port_conn_count") <= 1
        and _row_float(row, "src_dst_port_conn_share") <= 0.05
        and _row_int(row, "flow_RST_flag_count") == 0
        and conn_state == "SF"
    )


def _nmap_single_target_scan_support_level(
    lbl: str,
    row: Optional[Mapping[str, object]],
) -> str:
    key = normalize_label(lbl)
    if row is None or key not in (SCAN_LABELS - {"portscan"}):
        return "none"
    if _has_internal_rpc_portscan_chatter_shape(row):
        return "none"

    src_conn_count = _row_int(row, "src_conn_count")
    unique_ports = _row_int(row, "src_unique_ports")
    unique_targets = _row_int(row, "src_unique_targets")
    dominant_target_conn = _row_int(row, "src_dst_conn_count")
    dominant_target_share = _row_float(row, "src_dst_conn_share")
    short_ratio = _row_float(row, "src_short_ratio")
    failed_ratio = _target_failed_ratio(row)
    syn_count = _row_int(row, "flow_SYN_flag_count")
    fin_count = _row_int(row, "flow_FIN_flag_count")
    rst_count = _row_int(row, "flow_RST_flag_count")
    ack_count = _row_int(row, "flow_ACK_flag_count")
    duration = _row_float(row, "duration")
    proto = _row_text(row, "proto").lower()

    if unique_targets > 2:
        return "none"
    if unique_ports < 12 or src_conn_count < 12:
        return "none"
    if dominant_target_conn < 10 or dominant_target_share < 0.70:
        return "none"

    if key == "nmap_fin_scan":
        if fin_count < 1 and rst_count < 1 and failed_ratio < 0.25:
            return "none"
        if (
            unique_ports >= 14
            and src_conn_count >= 14
            and dominant_target_share >= 0.85
            and (failed_ratio >= 0.30 or rst_count >= 1 or short_ratio >= 0.35)
        ):
            return "strong"
        return "moderate"

    if key == "nmap_xmas_tree_scan":
        if (
            fin_count < 1
            and rst_count < 1
            and failed_ratio < 0.25
            and ack_count < 1
        ):
            return "none"
        if (
            unique_ports >= 14
            and src_conn_count >= 14
            and dominant_target_share >= 0.85
            and (rst_count >= 1 or failed_ratio >= 0.30 or ack_count >= 1)
        ):
            return "strong"
        return "moderate"

    if key == "nmap_os_detection":
        if rst_count < 1 and failed_ratio < 0.30 and ack_count < 1:
            return "none"
        if (
            unique_ports >= 14
            and src_conn_count >= 14
            and dominant_target_share >= 0.85
            and (rst_count >= 1 or failed_ratio >= 0.45)
        ):
            return "strong"
        return "moderate"

    if key == "nmap_tcp_scan":
        if syn_count < 1 and rst_count < 1 and failed_ratio < 0.25:
            return "none"
        if (
            unique_ports >= 16
            and src_conn_count >= 16
            and dominant_target_share >= 0.85
            and (syn_count >= 1 or rst_count >= 1)
            and (failed_ratio >= 0.30 or short_ratio >= 0.45)
        ):
            return "strong"
        return "moderate"

    if key == "nmap_udp_scan":
        if proto != "udp" and failed_ratio < 0.10 and duration > 1.0:
            return "none"
        if (
            unique_ports >= 20
            and src_conn_count >= 20
            and dominant_target_share >= 0.85
            and (proto == "udp" or duration <= 0.5 or short_ratio >= 0.20)
        ):
            return "strong"
        if proto == "udp" or duration <= 1.0:
            return "moderate"
        return "none"

    return "none"


def _ssh_bruteforce_support_level(
    lbl: str,
    row: Optional[Mapping[str, object]],
    dst_port: int,
) -> str:
    key = normalize_label(lbl)
    if row is None or key not in {"ssh_patator", "metasploit_brute_force_ssh"}:
        return "none"

    dport = _safe_port(dst_port)
    service = _row_text(row, "service").lower()
    if dport != 22 and service != "ssh":
        return "none"

    target_conn = _target_conn_count(row)
    src_conn_count = _row_int(row, "src_conn_count")
    unique_targets = _row_int(row, "src_unique_targets")
    target_concentration = _target_concentration_ratio(row)
    short_ratio = _target_short_ratio(row)
    failed_ratio = _target_failed_ratio(row)
    rst_count = _row_int(row, "flow_RST_flag_count")
    ack_count = _row_int(row, "flow_ACK_flag_count")
    failure_like_ratio = max(
        failed_ratio,
        rst_count / max(target_conn, 1),
    )

    if target_conn < 6 or max(target_conn, src_conn_count) < 8:
        return "none"
    if unique_targets > 2 or target_concentration < 0.65:
        return "none"
    if failure_like_ratio < 0.20 and rst_count < 4:
        return "none"
    if short_ratio < 0.50 and rst_count < 6 and failed_ratio < 0.25:
        return "none"

    if (
        target_conn >= 10
        and target_concentration >= 0.80
        and short_ratio >= 0.70
        and (failed_ratio >= 0.15 or rst_count >= 6)
        and (failure_like_ratio >= 0.45 or rst_count >= 8 or ack_count >= 10)
    ):
        return "strong"
    if (
        target_conn >= 8
        and target_concentration >= 0.75
        and short_ratio >= 0.60
        and (failed_ratio >= 0.15 or rst_count >= 4)
    ):
        return "moderate"
    if (
        target_conn >= 6
        and target_concentration >= 0.70
        and failed_ratio >= 0.20
    ):
        return "weak"
    return "none"


def _webattack_specific_support_level(
    lbl: str,
    row: Optional[Mapping[str, object]],
    dst_port: int,
) -> str:
    key = normalize_label(lbl)
    if row is None or key not in WEBATTACK_LABELS:
        return "none"

    dport = _safe_port(dst_port)
    http_score = _http_context_score(row, dport)
    if http_score < 2 or not _has_http_evidence(row):
        return "none"

    http_request_count = _row_int(row, "http_request_count")
    http_status_failures = _row_int(row, "http_status_4xx_5xx_count")
    target_conn = _target_conn_count(row)
    target_concentration = _target_concentration_ratio(row)
    heuristic_support = _has_heuristic_support(row)

    if key == "webattack_bruteforce":
        if (
            not _looks_like_login_http_uri(row)
            or target_conn < 4
            or target_concentration < 0.50
        ):
            return "none"
        if (
            (http_status_failures >= 2 and target_conn >= 8)
            or (http_request_count >= 3 and target_conn >= 8 and heuristic_support)
        ):
            return "strong"
        if (
            http_status_failures >= 1
            and (http_request_count >= 1 or target_conn >= 6)
        ):
            return "moderate"
        return "none"

    if key == "webattack_sql_injection":
        if not _has_clear_sqli_uri_payload(row):
            return "none"
        if (
            http_status_failures >= 1
            or http_request_count >= 2
            or (target_conn >= 2 and target_concentration >= 0.50)
            or heuristic_support
        ):
            return "strong"
        return "none"

    if key == "webattack_xss":
        if not _has_clear_xss_uri_payload(row):
            return "none"
        if (
            (http_request_count >= 2 and target_conn >= 3)
            or http_status_failures >= 1
            or heuristic_support
        ):
            return "strong"
        if target_conn >= 2 and target_concentration >= 0.50:
            return "moderate"
        return "none"

    return "none"


def _arp_poisoning_support_level(
    row: Optional[Mapping[str, object]],
) -> str:
    if row is None or not _is_internal_pair(row):
        return "none"

    arp_packet_count = _row_int(row, "arp_packet_count")
    arp_reply_count = _row_int(row, "arp_reply_count")
    arp_conflicting_mac_count = _row_int(row, "arp_conflicting_mac_count")

    if arp_packet_count < 4 or arp_reply_count < 2:
        return "none"
    if arp_conflicting_mac_count >= 2 and arp_reply_count >= 4 and arp_packet_count >= 6:
        return "strong"
    if arp_conflicting_mac_count >= 2:
        return "moderate"
    return "none"


def _iot_context_support_level(
    lbl: str,
    row: Optional[Mapping[str, object]],
    dst_port: int,
) -> str:
    key = normalize_label(lbl)
    if row is None or key not in NON_ALERT_SUSPICIOUS_LABELS:
        return "none"

    dport = _safe_port(dst_port)
    service = _row_text(row, "service").lower()
    target_conn = _target_conn_count(row)
    src_conn_count = _row_int(row, "src_conn_count")
    target_concentration = _target_concentration_ratio(row)
    http_score = _http_context_score(row, dport)
    http_request_count = _row_int(row, "http_request_count")
    ssl_event_count = _row_int(row, "ssl_event_count")

    if key == "mqtt_publish":
        if dport not in (1883, 8883) and service != "mqtt":
            return "none"
        if (
            service == "mqtt"
            and target_conn >= 6
            and max(src_conn_count, target_conn) >= 8
            and target_concentration >= 0.60
        ):
            return "strong"
        if (
            target_conn >= 4
            and max(src_conn_count, target_conn) >= 6
            and target_concentration >= 0.50
        ):
            return "moderate"
        return "none"

    if key == "thing_speak":
        if dport not in HTTP_PORTS or http_score < 2:
            return "none"
        if not _context_has_any_token(row, ("thingspeak",)):
            return "none"
        if (
            target_concentration >= 0.50
            and (http_request_count >= 6 or ssl_event_count >= 3 or target_conn >= 5)
        ):
            return "strong"
        if (
            target_concentration >= 0.40
            and (http_request_count >= 2 or ssl_event_count >= 2 or target_conn >= 3)
        ):
            return "moderate"
        return "none"

    if dport not in HTTP_PORTS and dport not in (1883, 8883) and service not in {
        "mqtt",
        "http",
        "https",
        "ssl",
    }:
        return "none"
    if not _context_has_any_token(
        row,
        ("wipro", "smartbulb", "smart-bulb", "smart bulb", "bulb"),
    ):
        return "none"
    if (
        target_concentration >= 0.50
        and (ssl_event_count >= 3 or http_request_count >= 4 or target_conn >= 5)
        and max(src_conn_count, target_conn) >= 5
    ):
        return "strong"
    if (
        target_concentration >= 0.40
        and (ssl_event_count >= 1 or http_request_count >= 2 or target_conn >= 3)
        and max(src_conn_count, target_conn) >= 3
    ):
        return "moderate"
    return "none"


def _is_private_ip(value: str) -> bool:
    text = _clean_text(value)
    if not text:
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
    )


def _is_internal_pair(row: Optional[Mapping[str, object]]) -> bool:
    if row is None:
        return False
    return _is_private_ip(_row_text(row, "src_ip")) and _is_private_ip(
        _row_text(row, "dst_ip")
    )


def _fanout_is_scan_like(row: Optional[Mapping[str, object]]) -> bool:
    return _row_int(row, "src_unique_ports") >= 20 and _target_conn_count(row) <= 3


def _is_internal_auth_service(
    row: Optional[Mapping[str, object]],
    dst_port: int,
) -> bool:
    service = _row_text(row, "service").lower()
    dport = _safe_port(dst_port)
    if dport in INTERNAL_AUTH_PORTS:
        return True
    if service in INTERNAL_AUTH_SERVICES:
        return True
    return service.endswith("_rpc")


def _has_internal_auth_ddos_chatter_shape(
    row: Optional[Mapping[str, object]],
    dst_port: int,
    *,
    syn_score: int | None = None,
) -> bool:
    if row is None:
        return False
    dport = _safe_port(dst_port)
    if not _is_internal_pair(row) or not _is_internal_auth_service(row, dport):
        return False
    if _has_http_evidence(row) or _has_ssl_evidence(row) or _is_dns_like_target(row, dport):
        return False
    if _has_heuristic_support(row):
        return False
    if syn_score is None:
        syn_score = _syn_context_score(row)
    target_conn = _target_conn_count(row)
    src_conn_count = _row_int(row, "src_conn_count")
    duration = _row_float(row, "duration")
    bytes_total = _row_float(row, "bytes_total")
    return (
        syn_score < 3
        and target_conn < 25
        and src_conn_count < 40
        and duration < 0.05
        and bytes_total < 16_384
    )


def _burst_score(row: Optional[Mapping[str, object]]) -> int:
    score = 0
    target_conn = _target_conn_count(row)
    src_conn_count = _row_int(row, "src_conn_count")
    flow_pps = _row_float(row, "flow_pkts_per_sec")
    bytes_per_s = _row_float(row, "bytes_per_s")
    bytes_total = _row_float(row, "bytes_total")
    duration = _row_float(row, "duration")
    short_ratio = _target_short_ratio(row)
    rate_signal_is_reliable = not (
        duration > 0.0
        and duration < 0.05
        and target_conn < 25
        and src_conn_count < 40
        and bytes_total < 16_384
    )

    if target_conn >= 10:
        score += 1
    if target_conn >= 25:
        score += 1
    if target_conn >= 60:
        score += 1

    if target_conn == 0:
        if src_conn_count >= 40:
            score += 1
        if src_conn_count >= 120:
            score += 1

    if rate_signal_is_reliable:
        if flow_pps >= 30:
            score += 1
        if flow_pps >= 80:
            score += 1
        if bytes_per_s >= 50_000:
            score += 1
        if bytes_per_s >= 200_000:
            score += 1
    if short_ratio >= 0.50:
        score += 1
    if short_ratio >= 0.80:
        score += 1

    if _fanout_is_scan_like(row):
        score = max(0, score - 2)
    return score


def _syn_context_score(row: Optional[Mapping[str, object]]) -> int:
    syn_count = _row_int(row, "flow_SYN_flag_count")
    ack_count = _row_int(row, "flow_ACK_flag_count")
    conn_state = _row_text(row, "conn_state").upper()

    score = 0
    if syn_count >= 8:
        score += 1
    if syn_count >= 20:
        score += 1
    if syn_count > 0 and ack_count <= max(2, syn_count // 2):
        score += 1
    if conn_state in FAILED_STATES:
        score += 1
    if _target_failed_ratio(row) >= 0.40:
        score += 1
    return score


def _base_context_signal_level(row: Optional[Mapping[str, object]]) -> str:
    if row is None:
        return "none"

    heuristic_score = _row_float(row, "heuristic_score")
    target_conn = _target_conn_count(row)
    src_conn_count = _row_int(row, "src_conn_count")
    flow_pps = _row_float(row, "flow_pkts_per_sec")
    bytes_per_s = _row_float(row, "bytes_per_s")
    failed_ratio = _target_failed_ratio(row)
    short_ratio = _target_short_ratio(row)
    target_concentration = _target_concentration_ratio(row)
    syn_score = _syn_context_score(row)
    burst_score = _burst_score(row)
    http_score = _http_context_score(row, _safe_port(_row_int(row, "dst_port")))

    if (
        heuristic_score >= 0.85
        or burst_score >= 5
        or syn_score >= 4
        or (target_conn >= 25 and target_concentration >= 0.55)
    ):
        return "strong"
    if (
        heuristic_score >= 0.55
        or burst_score >= 3
        or syn_score >= 2
        or (target_conn >= 10 and target_concentration >= 0.40)
        or flow_pps >= 40
        or bytes_per_s >= 75_000
        or (http_score >= 2 and target_conn >= 6)
    ):
        return "moderate"
    if (
        heuristic_score > 0.0
        or burst_score >= 1
        or syn_score >= 1
        or (target_conn >= 4 and target_concentration >= 0.25)
        or src_conn_count >= 8
        or failed_ratio >= 0.15
        or short_ratio >= 0.60
        or flow_pps >= 15
        or bytes_per_s >= 20_000
        or http_score >= 2
    ):
        return "weak"
    return "none"


def is_rare_label(lbl: str) -> bool:
    return normalize_label(lbl) in RARE_LABELS


def _reason_prefix_for_label(lbl: str) -> str:
    key = normalize_label(lbl)
    return REASON_PREFIXES.get(key, f"Model flagged {lbl}")


def _has_focused_generic_ddos_context(
    row: Optional[Mapping[str, object]],
    dst_port: int,
) -> bool:
    if row is None:
        return False

    dport = _safe_port(dst_port)
    target_conn = _target_conn_count(row)
    target_concentration = _target_concentration_ratio(row)
    failed_ratio = _target_failed_ratio(row)
    syn_score = _syn_context_score(row)

    if _has_internal_auth_ddos_chatter_shape(row, dport, syn_score=syn_score):
        return False
    if _has_trivial_dns_flood_context(row, dport):
        return False

    return bool(
        target_concentration >= 0.90
        and target_conn >= 250
        and (syn_score >= 3 or failed_ratio >= 0.80)
    )


def _http_dos_support_level(
    lbl: str,
    row: Optional[Mapping[str, object]],
    dst_port: int,
) -> str:
    dport = _safe_port(dst_port)
    if row is None:
        return "none"

    http_score = _http_context_score(row, dport)
    if http_score < 2 or not _has_http_evidence(row):
        return "none"

    target_conn = _target_conn_count(row)
    target_concentration = _target_concentration_ratio(row)
    burst_score = _burst_score(row)
    duration = _row_float(row, "duration")
    http_request_count = _row_int(row, "http_request_count")
    http_status_failures = _row_int(row, "http_status_4xx_5xx_count")
    bytes_per_s = _row_float(row, "bytes_per_s")
    flow_pps = _row_float(row, "flow_pkts_per_sec")
    src_conn_count = _row_int(row, "src_conn_count")
    diluted_victim_path = _has_diluted_internal_http_victim_path_shape(
        lbl,
        row,
        dport,
        burst_score=burst_score,
    )

    if lbl == "dos_hulk":
        if (
            http_request_count >= 20
            and target_concentration >= 0.60
            and (burst_score >= 6 or flow_pps >= 80 or bytes_per_s >= 150_000)
        ):
            return "strong"
        if (
            http_request_count >= 10
            and target_concentration >= 0.45
            and (burst_score >= 4 or flow_pps >= 40 or target_conn >= 12)
        ):
            return "moderate"
        if diluted_victim_path:
            if (
                http_request_count >= 16
                and target_conn >= 10
                and (burst_score >= 4 or flow_pps >= 50 or bytes_per_s >= 150_000)
            ):
                return "strong"
            return "moderate"
        if (
            http_request_count >= 4
            and target_concentration >= 0.40
            and (burst_score >= 3 or target_conn >= 8)
        ):
            return "weak"
        return "none"

    if lbl == "dos_goldeneye":
        if (
            http_request_count >= 12
            and http_status_failures >= 2
            and target_concentration >= 0.50
            and (burst_score >= 4 or flow_pps >= 35 or target_conn >= 12)
        ):
            return "strong"
        if (
            http_request_count >= 6
            and http_status_failures >= 1
            and target_concentration >= 0.40
            and (burst_score >= 3 or target_conn >= 8)
        ):
            return "moderate"
        if (
            http_request_count >= 4
            and target_concentration >= 0.35
            and target_conn >= 6
        ):
            return "weak"
        return "none"

    if lbl == "dos_slowloris":
        if (
            duration >= 20
            and http_request_count >= 4
            and target_concentration >= 0.50
            and (target_conn >= 15 or src_conn_count >= 20)
        ):
            return "strong"
        if (
            duration >= 10
            and http_request_count >= 3
            and target_concentration >= 0.40
            and target_conn >= 10
        ):
            return "moderate"
        if diluted_victim_path:
            if duration >= 24 and http_request_count >= 4 and target_conn >= 9:
                return "strong"
            return "moderate"
        if duration >= 8 and http_request_count >= 2 and target_conn >= 8:
            return "weak"
        return "none"

    if lbl == "dos_slowhttptest":
        if (
            duration >= 15
            and http_request_count >= 6
            and target_concentration >= 0.50
            and target_conn >= 10
            and bytes_per_s <= 50_000
        ):
            return "strong"
        if (
            duration >= 8
            and http_request_count >= 4
            and target_concentration >= 0.40
            and target_conn >= 8
        ):
            return "moderate"
        if duration >= 6 and http_request_count >= 3 and target_conn >= 6:
            return "weak"
        return "none"

    if lbl == "ddos_slowloris":
        if (
            duration >= 20
            and http_request_count >= 6
            and target_concentration >= 0.60
            and target_conn >= 20
            and src_conn_count >= 30
        ):
            return "strong"
        if (
            duration >= 10
            and http_request_count >= 4
            and target_concentration >= 0.50
            and target_conn >= 12
        ):
            return "moderate"
        if duration >= 8 and http_request_count >= 3 and target_conn >= 10:
            return "weak"
        return "none"

    return "none"


def _confidence_thresholds(
    lbl: str,
    row: Optional[Mapping[str, object]] = None,
    confidence_mode: Optional[str] = None,
) -> tuple[float, float]:
    key = normalize_label(lbl)
    mode = _normalize_confidence_mode(confidence_mode)
    suspicious, confirm = CONFIDENCE_MODE_PRESETS.get(
        mode, (CONFIDENCE_SUSPICIOUS, CONFIDENCE_CONFIRM)
    )

    if key in HTTP_DOS_LABELS:
        suspicious = max(suspicious, 0.78)
        confirm = max(confirm, 0.93)
    elif key in {"dos", "ddos_slowloris"}:
        suspicious = max(suspicious, 0.76)
        confirm = max(confirm, 0.92)
    elif key in {"ddos", "dos_syn_hping"}:
        suspicious = max(suspicious, 0.80)
        confirm = max(confirm, 0.95)
    elif key in NON_ALERT_SUSPICIOUS_LABELS:
        suspicious = max(suspicious, 0.82)
        confirm = max(confirm, 0.93)

    if is_rare_label(key):
        confirm = max(confirm, RARE_CONFIRM)

    if key == "ddos" and _has_focused_generic_ddos_context(
        row, _row_int(row, "dst_port")
    ):
        suspicious = min(suspicious, 0.72)

    if row is not None and key in (HTTP_DOS_LABELS | {"ddos_slowloris", "dos_syn_hping"}):
        support = context_support_level(key, _row_int(row, "dst_port"), row=row)
        if key in (HTTP_DOS_LABELS | {"ddos_slowloris"}):
            if support == "strong":
                suspicious = min(suspicious, 0.72)
            elif support == "moderate":
                suspicious = min(suspicious, 0.75)
        elif key == "dos_syn_hping":
            if support == "strong":
                suspicious = min(suspicious, 0.74)
            elif support == "moderate":
                suspicious = min(suspicious, 0.77)

    return suspicious, confirm


def label_to_severity(lbl: str, ml_conf: float = 0.0) -> str:
    key = normalize_label(lbl)
    sev = LABEL_SEVERITY.get(key)

    if sev:
        if key in ("arp_poisioning", "arp_poisoning") and _safe_conf(ml_conf) >= 0.95:
            return "Critical"
        return sev

    if "benign" in key:
        return "Low"
    if "scan" in key or "nmap" in key or "port" in key:
        return "Medium"
    if "brute" in key or "patator" in key:
        return "High"
    if "bot" in key or "heartbleed" in key:
        return "Critical"
    if "ddos" in key:
        return "Critical"
    if "dos" in key:
        return "High"
    if "arp" in key and ("poison" in key or "poision" in key):
        return "High"
    return "Unknown"


def severity_base_score(sev: str) -> float:
    return SEVERITY_BASE_SCORES.get((sev or "").upper(), 0.30)


def severity_to_score(sev: str, conf: float) -> float:
    base = severity_base_score(sev)
    c = max(0.05, _safe_conf(conf))
    return max(0.0, min(1.0, base * c))


def severity_to_risk(sev: str) -> str:
    return SEVERITY_RISK.get((sev or "").capitalize(), "LOW")


def confidence_tier(
    lbl: str,
    ml_conf: float,
    row: Optional[Mapping[str, object]] = None,
    *,
    confidence_mode: Optional[str] = None,
) -> str:
    conf = _safe_conf(ml_conf)
    suspicious_floor, confirm_floor = _confidence_thresholds(
        lbl, row=row, confidence_mode=confidence_mode
    )

    if conf >= confirm_floor:
        return "confirmed"
    if conf >= suspicious_floor:
        return "suspicious"
    return "ignore"


def verdict_rank(verdict: str) -> int:
    return VERDICT_RANK.get(str(verdict or "Normal").capitalize(), 0)


def base_verdict_from_signal(
    ml_label: str,
    severity: str,
    confidence_tier_value: str,
    row: Optional[Mapping[str, object]] = None,
) -> str:
    lbl = normalize_label(ml_label)
    if lbl == "benign":
        return "Normal"

    sev = str(severity or "Unknown").capitalize()
    tier = str(confidence_tier_value or "").lower()
    base_signal = _base_context_signal_level(row)

    if sev in {"Low", "Unknown"} or tier == "ignore":
        return "Normal"

    if tier == "suspicious":
        if lbl in NON_ALERT_SUSPICIOUS_LABELS:
            return "Normal"
        return "Medium" if base_signal == "strong" else "Normal"

    if sev == "Critical":
        if base_signal == "strong":
            return "Critical"
        if base_signal == "moderate":
            return "High"
        if base_signal == "weak":
            return "Medium"
        return "Medium"

    if sev == "High":
        if base_signal in {"strong", "moderate"}:
            return "High"
        if base_signal == "weak":
            return "Medium"
        return "Low"

    if sev == "Medium":
        if base_signal in {"strong", "moderate"}:
            return "Medium"
        if base_signal == "weak":
            return "Low"
        return "Normal"

    return "Normal"


def validation_fail_reason(
    ml_label: str, dst_port: int, row: Optional[Mapping[str, object]] = None
) -> str:
    lbl = normalize_label(ml_label)
    dport = _safe_port(dst_port)
    http_score = _http_context_score(row, dport)
    target_conn = _target_conn_count(row)
    target_concentration = _target_concentration_ratio(row)
    burst_score = _burst_score(row)
    syn_score = _syn_context_score(row)
    http_request_count = _row_int(row, "http_request_count")
    http_status_failures = _row_int(row, "http_status_4xx_5xx_count")
    src_conn_count = _row_int(row, "src_conn_count")
    src_unique_ports = _row_int(row, "src_unique_ports")
    src_unique_targets = _row_int(row, "src_unique_targets")
    short_ratio = _row_float(row, "src_short_ratio")
    failed_ratio = _target_failed_ratio(row)
    duration = _row_float(row, "duration")
    conn_state = _row_text(row, "conn_state").upper()
    internal_pair = _is_internal_pair(row)
    rpc_like_service = _is_rpc_like_service(row)
    trivial_web_http_context = _has_trivial_web_http_context(
        row,
        dport,
        syn_score=syn_score,
        burst_score=burst_score,
    )
    trivial_dns_flood_context = _has_trivial_dns_flood_context(row, dport)
    internal_auth_ddos_chatter = _has_internal_auth_ddos_chatter_shape(
        row,
        dport,
        syn_score=syn_score,
    )
    nmap_single_target_scan_support = _nmap_single_target_scan_support_level(lbl, row)
    ssh_bruteforce_support = _ssh_bruteforce_support_level(lbl, row, dport)
    webattack_specific_support = _webattack_specific_support_level(lbl, row, dport)
    arp_poisoning_support = _arp_poisoning_support_level(row)
    iot_context_support = _iot_context_support_level(lbl, row, dport)
    benign_http_browsing_context = _has_benign_http_browsing_aggregation_shape(
        row,
        dport,
        syn_score=syn_score,
        burst_score=burst_score,
    )
    diluted_http_victim_path = _has_diluted_internal_http_victim_path_shape(
        lbl,
        row,
        dport,
        syn_score=syn_score,
        burst_score=burst_score,
    )

    if lbl in ("ssh_patator", "metasploit_brute_force_ssh") and dport != 22:
        return "Invalid context: SSH brute-force should target port 22"
    if lbl == "ftp_patator" and dport != 21:
        return "Invalid context: FTP brute-force should target port 21"
    if lbl == "heartbleed":
        service = _row_text(row, "service").lower()
        if dport not in TLS_PORTS and service not in {"ssl", "tls", "https"}:
            return "Suppressed: Heartbleed label lacks TLS/SSL context"
        if not _has_ssl_evidence(row):
            return "Suppressed: Heartbleed label needs TLS/SSL evidence"
    if "arp" in lbl and ("poison" in lbl or "poision" in lbl):
        if not _is_internal_pair(row):
            return "Suppressed: ARP poisoning label lacks local Layer2 context"
        if _row_int(row, "arp_packet_count") <= 0:
            return "Suppressed: ARP poisoning requires Layer2 evidence (ARP packets)"
        if _row_int(row, "arp_conflicting_mac_count") < 2:
            return "Suppressed: ARP poisoning needs conflicting MAC claims for the same IP"
        if arp_poisoning_support == "none":
            return "Suppressed: ARP poisoning needs repeated ARP reply pressure"
    if lbl == "mqtt_publish" and dport not in (1883, 8883):
        return "Suppressed: MQTT label but dst_port is not 1883/8883"
    if lbl == "thing_speak" and dport not in (80, 443):
        return "Suppressed: ThingSpeak label but dst_port is not 80/443"
    if lbl == "mqtt_publish" and iot_context_support == "none":
        return "Suppressed: MQTT label needs repeated focused MQTT activity"
    if lbl == "thing_speak" and iot_context_support == "none":
        return "Suppressed: ThingSpeak label needs ThingSpeak host or TLS context"
    if lbl == "wipro_bulb" and iot_context_support == "none":
        return "Suppressed: Wipro bulb label needs device-specific service context"

    if lbl in DOS_FAMILY_LABELS and _fanout_is_scan_like(row):
        return "Suppressed: fan-out pattern looks closer to scanning than focused DoS"
    if lbl in DOS_FAMILY_LABELS and internal_auth_ddos_chatter:
        return "Suppressed: internal auth chatter does not confirm DoS/DDoS"

    if lbl in DOS_FAMILY_LABELS and trivial_web_http_context:
        return "Suppressed: trivial HTTP evidence does not confirm web DoS/DDoS"
    if lbl in {"dos", "ddos"} and benign_http_browsing_context:
        return "Suppressed: aggregated outbound HTTP browsing does not confirm generic DoS/DDoS"

    if lbl in {"ssh_patator", "metasploit_brute_force_ssh"}:
        if ssh_bruteforce_support == "none":
            return "Suppressed: SSH brute-force label needs repeated failed attempts to one target"
    elif lbl in BRUTE_FORCE_LABELS:
        if failed_ratio < 0.20 or max(target_conn, src_conn_count) < 4:
            return "Suppressed: brute-force label needs repeated failed attempts"
    if lbl == "ftp_patator":
        if target_conn < 4:
            return "Suppressed: FTP brute-force label needs repeated attempts to the same target"
        if failed_ratio < 0.45 and target_conn < 6:
            return "Suppressed: FTP brute-force label needs stronger repeated failed attempts"

    if lbl in SCAN_LABELS:
        if _has_internal_rpc_portscan_chatter_shape(row):
            return "Demoted: internal RPC-like chatter does not look like a real scan"
        if src_unique_ports < 10 and src_conn_count < 30:
            return "Suppressed: scan label without enough port fanout"
        if (
            src_unique_targets < 2
            and src_unique_ports < 18
            and nmap_single_target_scan_support == "none"
        ):
            return "Suppressed: scan label lacks meaningful target or port fanout"
        if (
            src_unique_targets < 2
            and short_ratio < 0.55
            and failed_ratio < 0.20
            and src_unique_ports < 20
            and nmap_single_target_scan_support == "none"
        ):
            return "Suppressed: single-target scan label lacks strong short/failure pattern"
        if (
            short_ratio < 0.40
            and failed_ratio < 0.15
            and src_unique_ports < 18
            and nmap_single_target_scan_support == "none"
        ):
            return "Suppressed: scan label lacks short-connection scan pattern"
        if (
            src_unique_targets < 3
            and src_unique_ports < 12
            and nmap_single_target_scan_support == "none"
        ):
            return "Suppressed: scan label lacks target diversity"

    if lbl in WEBATTACK_LABELS:
        if http_score < 2 or not _has_http_evidence(row):
            return "Suppressed: web-attack label lacks real HTTP evidence"
        if (
            http_request_count < 2
            and http_status_failures < 1
            and webattack_specific_support == "none"
        ):
            return "Suppressed: web-attack label needs repeated HTTP activity"

    if lbl in HTTP_DOS_LABELS:
        if http_score < 2 or not _has_http_evidence(row):
            return "Suppressed: HTTP DoS label lacks reliable HTTP context"
        if http_request_count <= 1:
            return "Suppressed: trivial HTTP evidence does not confirm web DoS/DDoS"
        if (
            target_concentration < 0.30
            and target_conn < 18
            and not diluted_http_victim_path
        ):
            return "Suppressed: HTTP DoS label lacks focused target concentration"
        if lbl == "dos_slowloris":
            if (
                target_conn < 10
                and http_request_count < 5
                and not diluted_http_victim_path
            ):
                return "Suppressed: Slowloris needs sustained HTTP connection pressure"
            if conn_state == "SF" and http_request_count <= 2 and target_conn < 5:
                return "Suppressed: completed HTTP flow looks benign for Slowloris"
            if duration < 10 and burst_score < 4:
                return "Suppressed: Slowloris label without long-lived or bursty evidence"
        elif lbl == "dos_slowhttptest":
            if target_conn < 8 and http_request_count < 4:
                return "Suppressed: SlowHTTPTest needs repeated HTTP request pressure"
            if duration < 8 and _row_float(row, "bytes_per_s") > 20_000 and burst_score < 4:
                return "Suppressed: traffic is too ordinary for SlowHTTPTest"
        elif lbl == "dos_hulk":
            if http_request_count < 10 and target_conn < 15 and burst_score < 4:
                return "Suppressed: Hulk label without strong HTTP burst evidence"
        elif lbl == "dos_goldeneye":
            if http_request_count < 6 and target_conn < 12 and burst_score < 4:
                return "Suppressed: GoldenEye label without repeated HTTP pressure"

    if lbl == "dos_syn_hping":
        if syn_score < 2:
            return "Suppressed: SYN flood label requires strong SYN-heavy context"
        if target_conn < 10 and burst_score < 4:
            return "Suppressed: SYN flood label without sustained target pressure"
        if target_concentration < 0.35 and target_conn < 20:
            return "Suppressed: SYN flood label lacks focused target concentration"

    if lbl == "ddos_slowloris":
        if http_score < 2:
            return "Suppressed: DDoS Slowloris label lacks HTTP context"
        if http_request_count <= 1:
            return "Suppressed: trivial HTTP evidence does not confirm web DoS/DDoS"
        if target_conn < 12 and http_request_count < 6 and burst_score < 4:
            return "Suppressed: DDoS Slowloris label without sustained connection pressure"
        if target_concentration < 0.35 and target_conn < 20:
            return "Suppressed: DDoS Slowloris label lacks focused target concentration"

    if lbl == "ddos":
        if trivial_dns_flood_context:
            return "Suppressed: trivial DNS evidence does not confirm DNS flood"
        if burst_score < 4 and target_conn < 25:
            return "Suppressed: generic DDoS label needs clear burst evidence"
        if target_concentration < 0.45 and target_conn < 40:
            return "Suppressed: generic DDoS label lacks focused target concentration"
        if http_score < 1 and syn_score < 1 and _row_float(row, "flow_pkts_per_sec") < 50 and _row_float(row, "bytes_per_s") < 100_000:
            return "Suppressed: generic DDoS label lacks burst or protocol evidence"

    if lbl == "dos":
        if trivial_dns_flood_context:
            return "Suppressed: trivial DNS evidence does not confirm DNS flood"
        if burst_score < 3 and target_conn < 12:
            return "Suppressed: generic DoS label needs focused burst evidence"
        if target_concentration < 0.40 and target_conn < 24:
            return "Suppressed: generic DoS label lacks focused target concentration"
        if dport in HTTP_PORTS and http_score < 2 and syn_score < 1 and target_conn < 20:
            return "Suppressed: generic DoS label on web traffic without HTTP/SYN evidence"

    return ""


@dataclass
class SuppressionResult:
    suppressed: bool
    reason: str = ""


def _is_multicast(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_multicast
    except Exception:
        return False


def _is_broadcast_v4(ip: str) -> bool:
    return str(ip or "").endswith(".255")


def should_suppress(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    ml_label: str,
    row: Optional[Mapping[str, object]] = None,
) -> SuppressionResult:
    lbl = normalize_label(ml_label)
    dport = _safe_port(dst_port)
    dip = str(dst_ip or "")
    arp_poisoning_support = _arp_poisoning_support_level(row)

    if dport == 5353 and (_is_multicast(dip) or dip in ("224.0.0.251", "ff02::fb")):
        return SuppressionResult(True, "Noise: mDNS multicast traffic")
    if dport == 5355 and (_is_multicast(dip) or dip in ("224.0.0.252", "ff02::1:3")):
        return SuppressionResult(True, "Noise: LLMNR multicast traffic")
    if dport == 1900 and (_is_multicast(dip) or dip == "239.255.255.250"):
        return SuppressionResult(True, "Noise: SSDP multicast traffic")
    if dport in (67, 68) or _is_broadcast_v4(dip):
        return SuppressionResult(True, "Noise: broadcast/DHCP-like traffic")
    if (
        dport == 53
        and ("arp" in lbl and ("poison" in lbl or "poision" in lbl))
        and arp_poisoning_support == "none"
    ):
        return SuppressionResult(True, "Likely FP: ARP-poison label on DNS/53 flow")

    target_conn = _target_conn_count(row)
    if lbl in HTTP_DOS_LABELS and _http_context_score(row, dport) == 0 and target_conn <= 3:
        return SuppressionResult(True, "Suppressed: HTTP DoS label without matching HTTP context")

    if lbl in {"dos", "ddos"} and target_conn <= 2 and _row_float(row, "flow_pkts_per_sec") < 10 and _row_float(row, "bytes_per_s") < 10_000:
        return SuppressionResult(True, "Suppressed: isolated flow does not look like DoS")

    if (
        lbl in SCAN_LABELS
        and dport in LOCAL_NOISE_PORTS
        and _row_int(row, "src_unique_ports") < 10
    ):
        return SuppressionResult(True, "Suppressed: local-service noise does not look like scanning")

    return SuppressionResult(False, "")


def context_support_level(
    ml_label: str,
    dst_port: int,
    row: Optional[Mapping[str, object]] = None,
) -> str:
    lbl = normalize_label(ml_label)
    dport = _safe_port(dst_port)

    if lbl == "benign":
        return "strong"

    target_conn = _target_conn_count(row)
    burst_score = _burst_score(row)
    syn_score = _syn_context_score(row)
    http_score = _http_context_score(row, dport)
    failed_ratio = _target_failed_ratio(row)
    src_conn_count = _row_int(row, "src_conn_count")
    unique_ports = _row_int(row, "src_unique_ports")
    unique_targets = _row_int(row, "src_unique_targets")
    target_concentration = _target_concentration_ratio(row)
    http_request_count = _row_int(row, "http_request_count")
    http_status_failures = _row_int(row, "http_status_4xx_5xx_count")
    trivial_web_http_context = _has_trivial_web_http_context(
        row,
        dport,
        syn_score=syn_score,
        burst_score=burst_score,
    )
    trivial_dns_flood_context = _has_trivial_dns_flood_context(row, dport)
    rpc_like_service = _is_rpc_like_service(row)
    internal_pair = _is_internal_pair(row)
    internal_auth_ddos_chatter = _has_internal_auth_ddos_chatter_shape(
        row,
        dport,
        syn_score=syn_score,
    )
    benign_http_browsing_context = _has_benign_http_browsing_aggregation_shape(
        row,
        dport,
        syn_score=syn_score,
        burst_score=burst_score,
    )

    if lbl in DOS_FAMILY_LABELS:
        if internal_auth_ddos_chatter:
            return "none"
        if trivial_web_http_context or (
            lbl in {"dos", "ddos"} and benign_http_browsing_context
        ) or (
            lbl in {"dos", "ddos"} and trivial_dns_flood_context
        ):
            return "none"
        if lbl == "dos_syn_hping":
            if syn_score >= 4 and (target_conn >= 20 or burst_score >= 4):
                return "strong"
            if syn_score >= 2 and (target_conn >= 8 or burst_score >= 3):
                return "moderate"
            if syn_score >= 1:
                return "weak"
            return "none"

        if lbl in {"dos", "ddos"}:
            if (
                target_concentration >= 0.90
                and target_conn >= 250
                and (syn_score >= 3 or failed_ratio >= 0.80)
            ):
                return "strong"
            if (
                target_concentration >= 0.80
                and target_conn >= 80
                and (syn_score >= 2 or failed_ratio >= 0.60)
            ):
                return "moderate"
            if (
                target_concentration >= 0.70
                and target_conn >= 40
                and (syn_score >= 1 or failed_ratio >= 0.40)
            ):
                return "weak"

        if lbl in HTTP_DOS_LABELS or lbl == "ddos_slowloris":
            return _http_dos_support_level(lbl, row, dport)

        if http_score >= 3 and target_concentration >= 0.60 and (
            target_conn >= 40 or burst_score >= 6 or http_request_count >= 20
        ):
            return "strong"
        if (
            http_score >= 2
            and target_concentration >= 0.45
            and (target_conn >= 18 or burst_score >= 5 or http_request_count >= 8)
        ) or (
            lbl in {"dos", "ddos"}
            and target_concentration >= 0.50
            and burst_score >= 5
        ):
            return "moderate"
        if (
            http_score >= 2
            and target_concentration >= 0.40
            and target_conn >= 12
            and http_request_count >= 4
        ) or (burst_score >= 4 and target_concentration >= 0.45):
            return "weak"
        return "none"

    if lbl in SCAN_LABELS:
        if _has_internal_rpc_portscan_chatter_shape(row):
            return "none"
        nmap_single_target_scan_support = _nmap_single_target_scan_support_level(lbl, row)
        if nmap_single_target_scan_support != "none":
            return nmap_single_target_scan_support
        if unique_targets < 2 and unique_ports < 18:
            return "none"
        if (
            unique_targets < 2
            and _row_float(row, "src_short_ratio") < 0.55
            and failed_ratio < 0.20
            and unique_ports < 20
        ):
            return "none"
        if (
            src_conn_count >= 120
            and unique_ports >= 25
            and unique_targets >= 8
            and _row_float(row, "src_short_ratio") >= 0.60
        ):
            return "strong"
        if (
            src_conn_count >= 40
            and unique_ports >= 12
            and (unique_targets >= 3 or unique_ports >= 18)
            and _row_float(row, "src_short_ratio") >= 0.40
        ):
            return "moderate"
        if (
            unique_ports >= 10
            and src_conn_count >= 25
            and (unique_targets >= 2 or unique_ports >= 15)
            and _row_float(row, "src_short_ratio") >= 0.35
        ):
            return "weak"
        return "none"

    if lbl in BRUTE_FORCE_LABELS:
        ssh_bruteforce_support = _ssh_bruteforce_support_level(lbl, row, dport)
        if ssh_bruteforce_support != "none":
            return ssh_bruteforce_support
        if lbl == "ftp_patator":
            if failed_ratio >= 0.60 and target_conn >= 10:
                return "strong"
            if failed_ratio >= 0.45 and target_conn >= 6:
                return "moderate"
            if failed_ratio >= 0.30 and target_conn >= 4:
                return "weak"
            return "none"
        if failed_ratio >= 0.40 and max(target_conn, src_conn_count) >= 10:
            return "strong"
        if failed_ratio >= 0.25 and max(target_conn, src_conn_count) >= 6:
            return "moderate"
        if failed_ratio >= 0.20 and max(target_conn, src_conn_count) >= 4:
            return "weak"
        return "none"

    if lbl in WEBATTACK_LABELS:
        webattack_specific_support = _webattack_specific_support_level(lbl, row, dport)
        if webattack_specific_support != "none":
            return webattack_specific_support
        if http_score >= 3 and http_request_count >= 4 and http_status_failures >= 2:
            return "strong"
        if http_score >= 2 and http_request_count >= 2:
            return "moderate"
        if http_score >= 2 and _has_http_evidence(row):
            return "weak"
        return "none"

    if lbl == "heartbleed":
        if _row_int(row, "ssl_event_count") > 0 and _row_text(row, "service").lower() in {"ssl", "https"}:
            return "strong"
        if _row_int(row, "ssl_event_count") > 0:
            return "moderate"
        return "none"

    if lbl == "bot":
        if src_conn_count >= 40 and (failed_ratio >= 0.20 or _target_short_ratio(row) >= 0.70):
            return "strong"
        if src_conn_count >= 20:
            return "moderate"
        if src_conn_count >= 8:
            return "weak"
        return "none"

    if "arp" in lbl and ("poison" in lbl or "poision" in lbl):
        return _arp_poisoning_support_level(row)

    if lbl in NON_ALERT_SUSPICIOUS_LABELS:
        return _iot_context_support_level(lbl, row, dport)

    if _row_text(row, "service") or src_conn_count > 0:
        return "weak"
    return "none"


def support_level_to_multiplier(level: str) -> float:
    return {
        "none": 0.15,
        "weak": 0.35,
        "moderate": 0.70,
        "strong": 1.00,
    }.get(str(level or "").lower(), 0.50)


def verdict_score_cap(verdict: str) -> float:
    return {
        "Normal": 0.0,
        "Low": 0.30,
        "Medium": 0.60,
        "High": 0.82,
        "Critical": 0.97,
    }.get(str(verdict or "Normal").capitalize(), 0.0)


def verdict_score_floor(verdict: str) -> float:
    return {
        "Normal": 0.0,
        "Low": 0.20,
        "Medium": 0.40,
        "High": 0.65,
        "Critical": 0.85,
    }.get(str(verdict or "Normal").capitalize(), 0.0)


def verdict_from_context(
    ml_label: str,
    severity: str,
    confidence_tier_value: str,
    dst_port: int,
    suppressed: bool,
    row: Optional[Mapping[str, object]] = None,
) -> str:
    if bool(suppressed):
        return "Normal"

    lbl = normalize_label(ml_label)
    if lbl == "benign":
        return "Normal"

    sev = (severity or "Unknown").capitalize()
    tier = str(confidence_tier_value or "")
    if tier == "ignore":
        return "Normal"

    if lbl in NON_ALERT_SUSPICIOUS_LABELS:
        support = context_support_level(lbl, dst_port, row=row)
        if tier == "confirmed" and support in {"moderate", "strong"}:
            return "Low"
        return "Normal"

    if sev == "Low":
        return "Normal"

    support = context_support_level(lbl, dst_port, row=row)
    if tier == "suspicious":
        if lbl in NON_ALERT_SUSPICIOUS_LABELS:
            return "Normal"
        return "Medium" if support == "strong" else "Normal"

    if support == "none":
        return "Normal"
    if support == "weak":
        return "Normal"
    if support == "moderate":
        if sev == "Critical":
            return "High"
        if sev == "High":
            return "Medium"
        return sev if sev in ("Medium",) else "Medium"
    return sev if sev in ("Medium", "High", "Critical") else "Medium"


def summarize_evidence_for_reason(row: Optional[Mapping[str, object]]) -> list[str]:
    if not row:
        return []

    snippets: list[str] = []
    seen: set[str] = set()

    def add(text: str):
        clean = _clean_text(text)
        if not clean:
            return
        key = clean.lower()
        if key in seen:
            return
        seen.add(key)
        snippets.append(clean)

    heuristic_type = _row_text(row, "heuristic_type")
    heuristic_reason = _row_text(row, "heuristic_reason")
    if heuristic_reason:
        add(heuristic_reason.rstrip("."))
    elif heuristic_type and heuristic_type.lower() != "none":
        add(f"heuristic={heuristic_type}")

    src_conn_count = _row_int(row, "src_conn_count")
    target_conn = _target_conn_count(row)
    src_unique_ports = _row_int(row, "src_unique_ports")
    src_failed_ratio = _target_failed_ratio(row)
    src_short_ratio = _target_short_ratio(row)

    if target_conn > 0:
        add(f"{target_conn} target connections in window")
    elif src_conn_count > 0:
        add(f"{src_conn_count} connections in window")
    if src_unique_ports > 0:
        add(f"{src_unique_ports} unique destination ports")
    if src_failed_ratio >= 0.10:
        add(f"failed-connection ratio {src_failed_ratio:.2f}")
    if src_short_ratio >= 0.10:
        add(f"short-connection ratio {src_short_ratio:.2f}")

    conn_state = _row_text(row, "conn_state")
    if conn_state:
        add(f"conn_state={conn_state}")

    service = _row_text(row, "service")
    proto = _row_text(row, "proto")
    if service and service.lower() != "unknown":
        add(f"service={service}")
    elif proto:
        add(f"proto={proto}")

    duration = _row_float(row, "duration")
    if duration > 0:
        add(f"duration={duration:.2f}s")

    flow_pps = _row_float(row, "flow_pkts_per_sec")
    if flow_pps > 0:
        add(f"flow_pkts_per_sec={flow_pps:.2f}")

    bytes_per_s = _row_float(row, "bytes_per_s")
    if bytes_per_s > 0:
        add(f"bytes_per_s={bytes_per_s:.2f}")

    syn_count = _row_int(row, "flow_SYN_flag_count")
    if syn_count > 0:
        add(f"SYN count={syn_count}")

    orig_bytes = _row_float(row, "orig_bytes")
    resp_bytes = _row_float(row, "resp_bytes")
    if orig_bytes > 0 or resp_bytes > 0:
        add(f"bytes orig={orig_bytes:.0f} resp={resp_bytes:.0f}")

    dns_query_count = _row_int(row, "dns_query_count")
    if dns_query_count > 0:
        dns_top_query = _row_text(row, "dns_top_query")
        add(
            f"dns queries={dns_query_count}"
            + (f" top_query={dns_top_query}" if dns_top_query else "")
        )

    http_request_count = _row_int(row, "http_request_count")
    if http_request_count > 0:
        http_top_host = _row_text(row, "http_top_host")
        http_top_uri = _row_text(row, "http_top_uri")
        details = [f"http requests={http_request_count}"]
        if http_top_host:
            details.append(f"host={http_top_host}")
        if http_top_uri:
            details.append(f"uri={http_top_uri}")
        add(" ".join(details))

    ssl_event_count = _row_int(row, "ssl_event_count")
    if ssl_event_count > 0:
        ssl_top_sni = _row_text(row, "ssl_top_sni")
        add(
            f"tls events={ssl_event_count}"
            + (f" sni={ssl_top_sni}" if ssl_top_sni else "")
        )

    return snippets


def _compact_reason(prefix: str, fragments: list[str], conf: float) -> str:
    bits = [frag for frag in fragments if _clean_text(frag)]
    bits = bits[:3]
    bits.append(f"ml_confidence={conf:.2f}")
    return f"{prefix}: " + ", ".join(bits)


def build_reason(
    ml_label: str,
    ml_conf: float,
    dst_port: int,
    suppressed_reason: str = "",
    validation_reason: str = "",
    confidence_tier_value: str = "",
    row: Optional[Mapping[str, object]] = None,
) -> str:
    lbl = normalize_label(ml_label)
    conf = _safe_conf(ml_conf)

    if validation_reason:
        return str(validation_reason)
    if suppressed_reason:
        return str(suppressed_reason)
    if str(confidence_tier_value or "") == "ignore":
        threshold, _ = _confidence_thresholds(lbl)
        return f"Ignored: low ML confidence (<{threshold:.2f})"

    evidence = summarize_evidence_for_reason(row)
    dport = _safe_port(dst_port)
    service = _row_text(row, "service")
    target_conn = _target_conn_count(row)

    if "nmap" in lbl or "scan" in lbl:
        scan_evidence: list[str] = []
        if _row_int(row, "src_conn_count") > 0:
            scan_evidence.append(f"connection count {_row_int(row, 'src_conn_count')}")
        if _row_int(row, "src_unique_ports") > 0:
            scan_evidence.append(
                f"port fanout {_row_int(row, 'src_unique_ports')}"
            )
        if _row_int(row, "src_unique_targets") > 0:
            scan_evidence.append(
                f"target fanout {_row_int(row, 'src_unique_targets')}"
            )
        if _row_float(row, "src_short_ratio") >= 0.10:
            scan_evidence.append(
                f"short-connection ratio {_row_float(row, 'src_short_ratio'):.2f}"
            )
        return _compact_reason(
            _reason_prefix_for_label(lbl),
            scan_evidence or evidence or [f"dst_port={dport}"],
            conf,
        )

    if lbl in ("ssh_patator", "metasploit_brute_force_ssh"):
        brute_evidence = [f"target port {dport or 22}"]
        if _target_failed_ratio(row) >= 0.10:
            brute_evidence.append(
                f"failed-connection ratio {_target_failed_ratio(row):.2f}"
            )
        if service and service.lower() != "unknown":
            brute_evidence.append(f"service={service}")
        return _compact_reason(_reason_prefix_for_label(lbl), brute_evidence, conf)

    if lbl == "ftp_patator":
        brute_evidence = [f"target port {dport or 21}"]
        if _target_failed_ratio(row) >= 0.10:
            brute_evidence.append(
                f"failed-connection ratio {_target_failed_ratio(row):.2f}"
            )
        if service and service.lower() != "unknown":
            brute_evidence.append(f"service={service}")
        return _compact_reason(_reason_prefix_for_label(lbl), brute_evidence, conf)

    if lbl in DOS_FAMILY_LABELS:
        dos_evidence: list[str] = []
        if target_conn > 0:
            dos_evidence.append(f"target connections={target_conn}")
        elif _row_int(row, "src_conn_count") > 0:
            dos_evidence.append(f"source connections={_row_int(row, 'src_conn_count')}")
        if _target_failed_ratio(row) >= 0.10:
            dos_evidence.append(
                f"failed-connection ratio {_target_failed_ratio(row):.2f}"
            )
        if _row_int(row, "flow_SYN_flag_count") > 0:
            dos_evidence.append(f"SYN count={_row_int(row, 'flow_SYN_flag_count')}")
        if lbl in HTTP_DOS_LABELS or (
            _is_web_like_target(row, dport) and _row_int(row, "http_request_count") >= 3
        ):
            if _row_int(row, "http_request_count") > 0:
                dos_evidence.append(f"http requests={_row_int(row, 'http_request_count')}")
            if _row_text(row, "http_top_host"):
                dos_evidence.append(f"host={_row_text(row, 'http_top_host')}")
            if lbl == "dos_goldeneye" and _row_int(row, "http_status_4xx_5xx_count") > 0:
                dos_evidence.append(
                    f"http error responses={_row_int(row, 'http_status_4xx_5xx_count')}"
                )
            if lbl in {"dos_slowloris", "dos_slowhttptest", "ddos_slowloris"} and _row_float(row, "duration") > 0:
                dos_evidence.append(f"duration={_row_float(row, 'duration'):.2f}s")
        elif service and service.lower() != "unknown":
            dos_evidence.append(f"service={service}")
        elif _row_float(row, "flow_pkts_per_sec") > 0:
            dos_evidence.append(
                f"flow_pkts_per_sec={_row_float(row, 'flow_pkts_per_sec'):.2f}"
            )
        return _compact_reason(
            _reason_prefix_for_label(lbl),
            dos_evidence or evidence or [f"dst_port={dport}"],
            conf,
        )

    if "webattack" in lbl:
        web_evidence: list[str] = []
        if _row_text(row, "http_top_host"):
            web_evidence.append(f"host={_row_text(row, 'http_top_host')}")
        if _row_text(row, "http_top_uri"):
            web_evidence.append(f"uri={_row_text(row, 'http_top_uri')}")
        if _row_int(row, "http_status_4xx_5xx_count") > 0:
            web_evidence.append(
                f"http error responses={_row_int(row, 'http_status_4xx_5xx_count')}"
            )
        return _compact_reason(_reason_prefix_for_label(lbl), web_evidence or evidence or [lbl], conf)

    if "arp" in lbl and ("poison" in lbl or "poision" in lbl):
        return _compact_reason(
            _reason_prefix_for_label(lbl),
            [
                *(
                    [f"arp packets={_row_int(row, 'arp_packet_count')}"]
                    if _row_int(row, "arp_packet_count") > 0
                    else []
                ),
                *(
                    [f"arp replies={_row_int(row, 'arp_reply_count')}"]
                    if _row_int(row, "arp_reply_count") > 0
                    else []
                ),
                *(
                    [f"conflicting mac claims={_row_int(row, 'arp_conflicting_mac_count')}"]
                    if _row_int(row, "arp_conflicting_mac_count") > 0
                    else []
                ),
            ]
            or evidence
            or ["label suggests layer-2 poisoning pattern"],
            conf,
        )

    if lbl == "heartbleed":
        tls_evidence: list[str] = []
        if _row_text(row, "ssl_top_sni"):
            tls_evidence.append(f"sni={_row_text(row, 'ssl_top_sni')}")
        if _row_int(row, "ssl_event_count") > 0:
            tls_evidence.append(f"tls events={_row_int(row, 'ssl_event_count')}")
        if _row_text(row, "ssl_top_cipher"):
            tls_evidence.append(f"cipher={_row_text(row, 'ssl_top_cipher')}")
        return _compact_reason(_reason_prefix_for_label(lbl), tls_evidence or evidence, conf)

    if lbl == "bot":
        bot_evidence: list[str] = []
        if target_conn > 0:
            bot_evidence.append(f"target connections={target_conn}")
        if _row_int(row, "src_conn_count") > 0:
            bot_evidence.append(f"source connections={_row_int(row, 'src_conn_count')}")
        if _target_failed_ratio(row) >= 0.10:
            bot_evidence.append(
                f"failed-connection ratio {_target_failed_ratio(row):.2f}"
            )
        if _target_short_ratio(row) >= 0.10:
            bot_evidence.append(
                f"short-connection ratio {_target_short_ratio(row):.2f}"
            )
        return _compact_reason(_reason_prefix_for_label(lbl), bot_evidence or evidence, conf)

    if lbl in NON_ALERT_SUSPICIOUS_LABELS:
        iot_evidence: list[str] = []
        if dport > 0:
            iot_evidence.append(f"target port {dport}")
        if service and service.lower() != "unknown":
            iot_evidence.append(f"service={service}")
        if _row_text(row, "http_top_host"):
            iot_evidence.append(f"host={_row_text(row, 'http_top_host')}")
        if _row_text(row, "ssl_top_sni"):
            iot_evidence.append(f"sni={_row_text(row, 'ssl_top_sni')}")
        if _row_int(row, "http_request_count") > 0:
            iot_evidence.append(f"http requests={_row_int(row, 'http_request_count')}")
        elif _row_int(row, "ssl_event_count") > 0:
            iot_evidence.append(f"tls events={_row_int(row, 'ssl_event_count')}")
        elif target_conn > 0:
            iot_evidence.append(f"target connections={target_conn}")
        return _compact_reason(_reason_prefix_for_label(lbl), iot_evidence or evidence, conf)

    if "benign" in lbl:
        return "Classified as benign by model"
    if evidence:
        return _compact_reason(_reason_prefix_for_label(lbl), evidence, conf)
    return f"{_reason_prefix_for_label(lbl)}: dst_port={dport}, ml_confidence={conf:.2f}"
