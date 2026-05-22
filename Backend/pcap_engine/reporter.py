# backend/pcap_engine/reporter.py
from __future__ import annotations
import math
from collections import defaultdict
from datetime import datetime, timezone
import pandas as pd

SEV_ORDER = {"Normal": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SECURITY_SEVERITY_WEIGHTS = {
    "Low": 5.0,
    "Medium": 12.0,
    "High": 25.0,
    "Critical": 45.0,
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value, default=0.0):
    try:
        numeric = float(value) if value is not None else default
        return default if (math.isnan(numeric) or math.isinf(numeric)) else numeric
    except (TypeError, ValueError):
        return default


def _safe_int(value, default=0):
    try:
        return int(float(value)) if value is not None else default
    except (TypeError, ValueError):
        return default


def _safe_str(value, default=""):
    if value is None or (hasattr(value, "__float__") and str(value) == "nan"):
        return default
    text = str(value).strip()
    return text if text and text.lower() != "nan" else default


def _normalize_security_severity(value) -> str | None:
    severity = _safe_str(value).lower()
    if severity == "critical":
        return "Critical"
    if severity == "high":
        return "High"
    if severity == "medium":
        return "Medium"
    if severity == "low":
        return "Low"
    return None


def _normalize_security_confidence(value) -> float:
    confidence = _safe_float(value, 0.0)
    if confidence <= 0:
        return 0.0
    if confidence <= 1:
        return confidence
    if confidence <= 100:
        return confidence / 100.0
    return 1.0


def _normalize_security_count(value) -> int:
    return max(1, _safe_int(value, 1))


def _security_count_factor(count: int) -> float:
    softened = 1.0 + math.log(max(1, count))
    return min(softened, 2.6)


def _security_signal_metrics(severity: str, confidence: float, count: int) -> tuple[float, float]:
    weight = SECURITY_SEVERITY_WEIGHTS.get(severity, 0.0)
    if weight <= 0:
        return 0.0, 0.0

    count_factor = _security_count_factor(count)
    impact = weight * confidence * count_factor
    evidence_risk = min(0.98, (weight / 45.0) * confidence * count_factor)
    activity_risk = min(0.9, (weight / 45.0) * 0.45 * count_factor)
    risk = max(evidence_risk, activity_risk)
    return impact, risk


def _derive_risk_level(value: float) -> str:
    if value <= 0:
        return "Normal"
    if value < 0.20:
        return "Low"
    if value < 0.45:
        return "Medium"
    if value < 0.75:
        return "High"
    return "Critical"


def _score_from_overall_risk(value: float) -> float:
    risk = max(0.0, min(1.0, _safe_float(value, 0.0)))
    if risk <= 0:
        return 100.0

    if risk < 0.20:
        progress = risk / 0.20
        return 95.0 - (progress * 15.0)

    if risk < 0.45:
        progress = (risk - 0.20) / 0.25
        return 79.0 - (progress * 24.0)

    if risk < 0.75:
        progress = (risk - 0.45) / 0.30
        return 54.0 - (progress * 24.0)

    progress = (risk - 0.75) / 0.25
    return max(0.0, 29.0 - (progress * 29.0))


def _security_score_level(score: float) -> str:
    if score >= 90:
        return "Secure"
    if score >= 70:
        return "Warning"
    if score >= 40:
        return "Risky"
    return "Critical"


def _empty_security_severity_counts() -> dict[str, int]:
    return {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }


def _normalize_module_status(score: float) -> str:
    numeric = max(0.0, min(100.0, _safe_float(score, 0.0)))
    if numeric >= 90.0:
        return "secure"
    if numeric >= 70.0:
        return "warning"
    if numeric >= 40.0:
        return "risky"
    return "critical"


def _build_pcap_module_contract(
    *,
    generated_at: str | None,
    security_findings: dict[str, object],
    alerts_count: int,
    suspicious_count: int,
    cluster_count: int,
) -> dict[str, object]:
    module_score = round(
        max(0.0, min(100.0, _safe_float(security_findings.get("security_score"), 0.0))),
        1,
    )
    module_status = _normalize_module_status(module_score)
    alerts_total = max(0, _safe_int(alerts_count, 0))
    suspicious_total = max(0, _safe_int(suspicious_count, 0))
    cluster_total = max(0, _safe_int(cluster_count, 0))
    last_updated = _safe_str(generated_at, "") or None
    severity_counts = _empty_security_severity_counts()
    raw_severity_counts = security_findings.get("severity_counts")
    if isinstance(raw_severity_counts, dict):
        for key in severity_counts:
            severity_counts[key] = max(0, _safe_int(raw_severity_counts.get(key), 0))

    raw_top_risk = security_findings.get("top_risk")
    top_risk = None
    if isinstance(raw_top_risk, dict):
        normalized_severity = _normalize_security_severity(raw_top_risk.get("severity"))
        top_risk = {
            "name": _safe_str(raw_top_risk.get("name"), "Unknown threat"),
            "severity": normalized_severity.lower() if normalized_severity else None,
            "confidence": _normalize_security_confidence(raw_top_risk.get("confidence")),
        }
        if raw_top_risk.get("count") is not None:
            top_risk["count"] = max(0, _safe_int(raw_top_risk.get("count"), 0))
        if raw_top_risk.get("impact") is not None:
            top_risk["impact"] = round(
                max(0.0, _safe_float(raw_top_risk.get("impact"), 0.0)),
                2,
            )

    issues_count = max(
        alerts_total,
        suspicious_total,
        cluster_total,
    )

    return {
        "module": "pcap_analyzer",
        "module_score": module_score,
        "status": module_status,
        "status_source": "module_score_normalized",
        "summary": _safe_str(
            security_findings.get("security_summary"),
            "No PCAP analysis summary available.",
        ),
        "weight": 0.30,
        "weight_source": "placeholder_default",
        "issues_count": issues_count,
        "issue_count_mode": "max_signal",
        "issue_breakdown": {
            "alerts_count": alerts_total,
            "suspicious_count": suspicious_total,
            "cluster_count": cluster_total,
        },
        "top_risk": top_risk,
        "supporting_metrics": {
            "overall_risk": _safe_float(security_findings.get("overall_risk"), 0.0),
            "risk_level": _safe_str(security_findings.get("risk_level"), "Normal"),
            "risk_context_label": _safe_str(
                security_findings.get("risk_context_label"), "Unknown Context"
            ),
            "risk_display": _safe_str(
                security_findings.get("risk_display"),
                _safe_str(security_findings.get("risk_level"), "Normal"),
            ),
            "alerts_count": alerts_total,
            "suspicious_count": suspicious_total,
            "cluster_count": cluster_total,
            "severity_counts": severity_counts,
        },
        "points_earned": 0,
        "badges_earned": [],
        "gamification_available": False,
        "gamification_status": "not_implemented",
        "last_updated": last_updated,
        "last_updated_source": "report_generated_at",
        "source_type": "latest_pcap_analysis",
        "source_window": "current_analysis",
        "contract_meta": {
            "contract_version": "1.0",
            "status_source": "module_score_normalized",
            "weight_source": "placeholder_default",
            "last_updated_source": "report_generated_at",
            "gamification_status": "not_implemented",
        },
    }


def _build_risk_context_label(
    *,
    alerts_count: int,
    suspicious_count: int,
    cluster_count: int,
    severity_counts: dict[str, int],
    signals: list[dict],
) -> str:
    if alerts_count <= 0 and suspicious_count <= 0 and cluster_count <= 0 and not signals:
        return "No Significant Threats"

    high_or_critical_count = severity_counts.get("High", 0) + severity_counts.get("Critical", 0)
    max_confidence = max((_safe_float(signal.get("confidence"), 0.0) for signal in signals), default=0.0)
    has_repeated_high_or_critical = any(
        signal.get("severity") in {"High", "Critical"}
        and _safe_int(signal.get("count"), 1) > 1
        for signal in signals
    )
    has_clustering = (
        cluster_count > 0
        or len(signals) > 1
        or any(_safe_int(signal.get("count"), 1) > 1 for signal in signals)
        or suspicious_count > 2
        or alerts_count > 2
    )

    if severity_counts.get("Critical", 0) > 0 or has_repeated_high_or_critical:
        return "Active Attack Pattern"

    if high_or_critical_count > 1 and has_clustering:
        return "Active Attack Pattern"

    if has_clustering:
        return "Concentrated Threat Activity"

    if (
        len(signals) <= 1
        and alerts_count <= 1
        and suspicious_count <= 1
        and high_or_critical_count == 0
        and max_confidence < 0.45
    ):
        return "Isolated Event"

    if alerts_count > 0 or suspicious_count > 0 or max_confidence >= 0.35:
        return "Limited Suspicious Activity"

    return "Unknown Context"


def _build_risk_display(risk_level: str, risk_context_label: str | None) -> str:
    if risk_level == "Critical":
        prefix = "Critical Risk"
    elif risk_level == "High":
        prefix = "High Risk"
    elif risk_level == "Medium":
        prefix = "Moderate Risk"
    else:
        prefix = "Low Risk"

    context = _safe_str(risk_context_label, "Unknown Context")
    return prefix if context == "Unknown Context" else f"{prefix} ({context})"


def _pluralize(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _round_impact(value: float) -> float:
    return round(_safe_float(value, 0.0), 1)


def _build_score_explanation(
    *,
    overall_risk: float,
    final_score: float,
    alerts_count: int,
    suspicious_count: int,
    cluster_count: int,
    risk_context_label: str,
    severity_counts: dict[str, int],
    signals: list[dict],
    top_risk: dict | None,
) -> dict[str, object] | None:
    base_score = 100.0
    total_penalty = _round_impact(max(0.0, base_score - _safe_float(final_score, base_score)))

    if (
        total_penalty <= 0
        and alerts_count <= 0
        and suspicious_count <= 0
        and cluster_count <= 0
        and not signals
    ):
        return {
            "base_score": base_score,
            "risk_contributors": [
                {
                    "label": "No critical threats detected",
                    "impact": 0.0,
                    "details": "No promoted alerts or clustered threats materially reduced the score.",
                },
                {
                    "label": "No suspicious activity observed",
                    "impact": 0.0,
                    "details": "No suspicious events were counted in this analysis session.",
                },
            ],
            "final_score": _round_impact(final_score),
        }

    contributors: list[dict[str, object]] = []
    repeated_signals = sum(1 for signal in signals if _safe_int(signal.get("count"), 1) > 1)

    if top_risk:
        top_severity = _safe_str(top_risk.get("severity"), "Low")
        top_confidence = _safe_float(top_risk.get("confidence"), 0.0)
        contributors.append(
            {
                "label": f"{top_severity}-severity threat detected",
                "weight": max(1.0, SECURITY_SEVERITY_WEIGHTS.get(top_severity, 5.0) / 12.0)
                * max(top_confidence, 0.35),
                "details": (
                    f"Top threat {_safe_str(top_risk.get('name'), 'Unknown threat')} was "
                    f"classified as {top_severity.lower()} severity at {round(top_confidence * 100)}% confidence."
                ),
            }
        )

    if alerts_count > 0 or suspicious_count > 0:
        event_count = max(alerts_count, suspicious_count)
        contributors.append(
            {
                "label": "Suspicious activity observed",
                "weight": 0.9 + (min(event_count, 5) * 0.6),
                "details": f"{_pluralize(event_count, 'suspicious event')} contributed to the score reduction.",
            }
        )

    if cluster_count > 0 or repeated_signals > 0:
        cluster_value = max(cluster_count, repeated_signals)
        contributors.append(
            {
                "label": "Clustered activity increased risk",
                "weight": 1.1 + (min(cluster_value, 5) * 0.8),
                "details": f"{_pluralize(cluster_value, 'clustered threat group')} increased the score reduction.",
            }
        )

    if risk_context_label == "Active Attack Pattern":
        contributors.append(
            {
                "label": "Repeated attack patterns increased risk",
                "weight": 1.8
                + (severity_counts.get("Critical", 0) * 1.1)
                + (severity_counts.get("High", 0) * 0.6),
                "details": "Repeated high-severity or critical findings materially reduced the score.",
            }
        )

    if overall_risk > 0:
        label = (
            "Low overall risk limited impact"
            if overall_risk < 0.20
            else "Moderate overall risk reduced score"
            if overall_risk < 0.45
            else "Elevated overall risk reduced score"
        )
        contributors.append(
            {
                "label": label,
                "weight": max(0.7, overall_risk * 3.5),
                "details": f"Overall normalized risk settled at {overall_risk:.2f}.",
            }
        )

    if risk_context_label == "Isolated Event":
        contributors.append(
            {
                "label": "Limited event spread reduced impact",
                "weight": 0.6,
                "details": "Threat activity stayed isolated, which limited score reduction.",
            }
        )

    if risk_context_label == "No Significant Threats" or (
        severity_counts.get("High", 0) == 0
        and severity_counts.get("Critical", 0) == 0
        and cluster_count == 0
    ):
        contributors.append(
            {
                "label": "No critical threats detected",
                "weight": 0.5,
                "details": "No critical findings were present in the promoted results.",
            }
        )

    ranked = sorted(contributors, key=lambda item: _safe_float(item.get("weight"), 0.0), reverse=True)[
        : 4 if total_penalty > 8 else 3
    ]

    if not ranked:
        return None

    if total_penalty <= 0:
        return {
            "base_score": base_score,
            "risk_contributors": [
                {
                    "label": _safe_str(item.get("label"), "Score explanation unavailable"),
                    "impact": 0.0,
                    "details": _safe_str(item.get("details"), "No explainable score contributors were available."),
                }
                for item in ranked
            ],
            "final_score": _round_impact(final_score),
        }

    total_weight = sum(_safe_float(item.get("weight"), 0.0) for item in ranked)
    remaining_penalty = total_penalty
    allocated: list[dict[str, object]] = []

    for index, item in enumerate(ranked):
        is_last = index == len(ranked) - 1
        allocated_penalty = (
            remaining_penalty
            if is_last
            else _round_impact(total_penalty * _safe_float(item.get("weight"), 0.0) / max(total_weight, 0.0001))
        )
        remaining_penalty = _round_impact(max(0.0, remaining_penalty - allocated_penalty))
        allocated.append(
            {
                "label": _safe_str(item.get("label"), "Score factor"),
                "impact": -allocated_penalty,
                "details": _safe_str(item.get("details"), "This factor contributed to the current score."),
            }
        )

    return {
        "base_score": base_score,
        "risk_contributors": allocated,
        "final_score": _round_impact(final_score),
    }


def _normalize_ip_role(roles: set[str]) -> str:
    if "source" in roles and "destination" in roles:
        return "both"
    if "source" in roles:
        return "source"
    if "destination" in roles:
        return "destination"
    return "source"


def _build_risk_per_ip(alerts: list[dict], clusters: list[dict]) -> list[dict[str, object]]:
    primary_source = clusters if clusters else alerts
    signal_type = "cluster" if clusters else "alert"
    per_ip: dict[str, dict[str, object]] = {}

    for item in primary_source:
        signal = _build_security_signal(item, signal_type=signal_type)
        if signal is None:
            continue

        src_ip = _safe_str(item.get("src_ip") or item.get("source_ip"))
        dst_ip = _safe_str(item.get("dst_ip") or item.get("dest_ip"))
        if not src_ip and not dst_ip:
            continue

        ip_roles: dict[str, set[str]] = {}
        if src_ip:
            ip_roles.setdefault(src_ip, set()).add("source")
        if dst_ip:
            ip_roles.setdefault(dst_ip, set()).add("destination")

        for ip, roles in ip_roles.items():
            entry = per_ip.setdefault(
                ip,
                {
                    "ip": ip,
                    "roles": set(),
                    "threat_count": 0,
                    "suspicious_count": 0,
                    "max_confidence": 0.0,
                    "signals": [],
                },
            )
            entry["roles"].update(roles)
            entry["threat_count"] += 1
            entry["suspicious_count"] += 1
            entry["max_confidence"] = max(
                _safe_float(entry.get("max_confidence"), 0.0),
                _safe_float(signal.get("confidence"), 0.0),
            )
            entry["signals"].append(signal)

    rows: list[dict[str, object]] = []
    for entry in per_ip.values():
        signals = entry.get("signals", [])
        if not signals:
            continue

        combined_risk = 0.0
        for signal in signals:
            combined_risk = 1.0 - ((1.0 - combined_risk) * (1.0 - _safe_float(signal.get("risk"), 0.0)))

        top_signal = _select_top_risk(signals)
        rows.append(
            {
                "ip": _safe_str(entry.get("ip")),
                "role": _normalize_ip_role(entry.get("roles", set())),
                "threat_count": _safe_int(entry.get("threat_count"), 0),
                "suspicious_count": _safe_int(entry.get("suspicious_count"), 0),
                "top_severity": (
                    _safe_str(top_signal.get("severity"), "Low").lower()
                    if top_signal
                    else "low"
                ),
                "max_confidence": round(
                    _safe_float(entry.get("max_confidence"), 0.0), 4
                ),
                "ip_risk_score": round(max(0.0, min(1.0, combined_risk)) * 100.0, 1),
                "top_attack": (
                    _safe_str(top_signal.get("name"), "Unknown threat")
                    if top_signal
                    else "Unknown threat"
                ),
            }
        )

    rows.sort(
        key=lambda row: (
            _safe_float(row.get("ip_risk_score"), 0.0),
            SEV_ORDER.get(_safe_str(row.get("top_severity"), "low").capitalize(), 0),
            _safe_float(row.get("max_confidence"), 0.0),
            _safe_int(row.get("threat_count"), 0),
            _safe_str(row.get("ip")),
        ),
        reverse=True,
    )
    return rows


def _build_security_signal(item: dict, *, signal_type: str) -> dict | None:
    severity = _normalize_security_severity(item.get("severity"))
    if not severity:
        return None

    confidence = _normalize_security_confidence(
        item.get("max_threat_confidence")
        if signal_type == "cluster"
        else item.get("threat_confidence", item.get("confidence"))
    )
    count = _normalize_security_count(
        item.get("count_flows") if signal_type == "cluster" else item.get("count", 1)
    )
    impact, risk = _security_signal_metrics(severity, confidence, count)

    return {
        "name": _safe_str(
            item.get("attack_type")
            or item.get("ml_label")
            or item.get("label")
            or item.get("name"),
            "Unknown threat",
        ),
        "severity": severity,
        "confidence": confidence,
        "count": count,
        "impact": impact,
        "risk": risk,
        "signal_type": signal_type,
    }


def _select_top_risk(signals: list[dict]) -> dict | None:
    if not signals:
        return None

    ranked = sorted(
        signals,
        key=lambda signal: (
            SEV_ORDER.get(signal.get("severity", "Normal"), 0),
            _safe_float(signal.get("confidence"), 0.0),
            _safe_int(signal.get("count"), 1),
            _safe_float(signal.get("impact"), 0.0),
        ),
        reverse=True,
    )
    return ranked[0]


def _build_security_summary(
    *,
    alerts_count: int,
    suspicious_count: int,
    risk_level: str,
    risk_context_label: str,
    top_risk: dict | None,
    cluster_count: int,
    severity_counts: dict[str, int],
) -> str:
    if alerts_count <= 0 and suspicious_count <= 0 and cluster_count <= 0:
        return "No significant threats detected. Network activity appears normal."

    if severity_counts.get("Critical", 0) > 0 or risk_level == "Critical":
        return "High-impact attack patterns detected. Immediate review is recommended."

    if risk_level == "High":
        return "High-impact attack patterns detected. Immediate review is recommended."

    if risk_context_label == "Active Attack Pattern":
        return "High-impact attack patterns detected. Immediate review is recommended."

    if risk_context_label == "Concentrated Threat Activity" or cluster_count > 0:
        return "Suspicious clustered activity was observed. Investigate related flows."

    if severity_counts.get("High", 0) > 0:
        return "A high-severity event was detected. Review the top risk for verification."

    if alerts_count <= 1 and suspicious_count <= 1:
        return "A limited suspicious event was detected. Review the top risk for verification."

    if suspicious_count > 0 or severity_counts.get("Medium", 0) > 0:
        return "Limited suspicious activity was detected. Review the top risk for verification."

    if top_risk:
        return f"{top_risk.get('name', 'A threat')} remains the primary low-volume finding in this capture."

    return "Threat indicators were limited, but review the promoted findings for context."


def _build_security_trend(
    *,
    alerts_count: int,
    risk_level: str,
    cluster_count: int,
    severity_counts: dict[str, int],
) -> str:
    if alerts_count <= 0 and cluster_count <= 0:
        return "Stable - low clustered threat activity observed."

    if severity_counts.get("Critical", 0) > 0 or risk_level == "Critical":
        return "Concerning - critical traffic patterns detected in clustered analysis."

    if risk_level == "High":
        return "Concerning - high-risk traffic patterns detected in clustered analysis."

    if severity_counts.get("High", 0) > 0 or cluster_count > 0:
        return "Elevated - suspicious activity is concentrated in a small set of flows."

    return "Elevated - suspicious activity was promoted for review in this session."


def _build_security_findings(alerts: list[dict], clusters: list[dict]) -> dict[str, object]:
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

    for alert in alerts:
        severity = _normalize_security_severity(alert.get("severity"))
        if severity:
            severity_counts[severity] += 1

    primary_source = clusters if clusters else alerts
    signal_type = "cluster" if clusters else "alert"
    signals = [
        signal
        for signal in (
            _build_security_signal(item, signal_type=signal_type) for item in primary_source
        )
        if signal is not None
    ]
    meaningful_alerts_count = sum(severity_counts.values())
    meaningful_cluster_count = len(signals) if signal_type == "cluster" else 0
    has_incomplete_detail = len(signals) == 0 and (len(alerts) > 0 or len(clusters) > 0)

    combined_risk = 0.0
    for signal in signals:
        combined_risk = 1.0 - ((1.0 - combined_risk) * (1.0 - signal["risk"]))

    overall_risk = max(0.0, min(1.0, combined_risk))
    risk_level = _derive_risk_level(overall_risk)
    security_score = round(_score_from_overall_risk(overall_risk), 1)
    top_risk = _select_top_risk(signals)
    risk_context_label = _build_risk_context_label(
        alerts_count=meaningful_alerts_count,
        suspicious_count=meaningful_alerts_count,
        cluster_count=meaningful_cluster_count,
        severity_counts=severity_counts,
        signals=signals,
    )
    risk_display = _build_risk_display(risk_level, risk_context_label)
    score_explanation = (
        None
        if has_incomplete_detail
        else _build_score_explanation(
            overall_risk=overall_risk,
            final_score=security_score,
            alerts_count=meaningful_alerts_count,
            suspicious_count=meaningful_alerts_count,
            cluster_count=meaningful_cluster_count,
            risk_context_label=risk_context_label,
            severity_counts=severity_counts,
            signals=signals,
            top_risk=top_risk,
        )
    )

    return {
        "overall_risk": overall_risk,
        "risk_level": risk_level,
        "risk_context_label": risk_context_label,
        "risk_display": risk_display,
        "security_score": security_score,
        "score_explanation": score_explanation,
        "security_score_level": _security_score_level(security_score),
        "top_risk": {
            "name": top_risk["name"],
            "severity": str(top_risk["severity"]).lower(),
            "confidence": round(_safe_float(top_risk["confidence"], 0.0), 4),
            "count": _safe_int(top_risk["count"], 1),
            "impact": round(_safe_float(top_risk["impact"], 0.0), 2),
        }
        if top_risk
        else None,
        "security_summary": (
            "Analysis completed, but threat details were incomplete. Review the promoted findings for context."
            if has_incomplete_detail
            else _build_security_summary(
                alerts_count=meaningful_alerts_count,
                suspicious_count=meaningful_alerts_count,
                risk_level=risk_level,
                risk_context_label=risk_context_label,
                top_risk=top_risk,
                cluster_count=meaningful_cluster_count,
                severity_counts=severity_counts,
            )
        ),
        "security_trend": (
            "Current session has incomplete threat detail."
            if has_incomplete_detail
            else _build_security_trend(
                alerts_count=meaningful_alerts_count,
                risk_level=risk_level,
                cluster_count=meaningful_cluster_count,
                severity_counts=severity_counts,
            )
        ),
        "cluster_count": len(clusters),
        "severity_counts": {
            "low": severity_counts["Low"],
            "medium": severity_counts["Medium"],
            "high": severity_counts["High"],
            "critical": severity_counts["Critical"],
        },
    }


def cluster_alerts(df: pd.DataFrame, max_clusters: int | None = 100) -> list[dict]:
    """
    Cluster by (src_ip, dst_ip, ml_label) and summarize:
    - count
    - top dst_ports
    - max confidence
    - severity (max verdict)
    """
    if df is None or df.empty:
        return []

    # ignore suppressed + normal
    work = df.copy()
    if "suppressed" in work.columns:
        work = work[work["suppressed"] == False]
    work = work[work["verdict"].isin(["Medium", "High", "Critical"])]
    if work.empty:
        return []

    groups = defaultdict(list)
    for _, r in work.iterrows():
        key = (
            str(r.get("src_ip")),
            str(r.get("dst_ip")),
            str(r.get("ml_label")),
        )  # Added dst_ip here for a 3-tuple key
        groups[key].append(r)

    clustered = []
    for (src, dst, label), rows in groups.items():
        ports = [int(x.get("dst_port") or 0) for x in rows]
        # top ports by frequency
        freq = defaultdict(int)
        for p in ports:
            freq[p] += 1
        top_ports = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]

        max_conf = 0.0
        max_ml_conf = 0.0
        for x in rows:
            try:
                c = float(x.get("confidence") or 0.0)
                if not (math.isnan(c) or math.isinf(c)):
                    max_conf = max(max_conf, c)
            except (TypeError, ValueError):
                pass
            try:
                c_ml = float(x.get("ml_confidence") or 0.0)
                if not (math.isnan(c_ml) or math.isinf(c_ml)):
                    max_ml_conf = max(max_ml_conf, c_ml)
            except (TypeError, ValueError):
                pass
        # pick max verdict
        verdicts = [str(x.get("verdict") or "Normal") for x in rows]
        max_verdict = max(verdicts, key=lambda v: SEV_ORDER.get(v, 0))

        # dst_ip is already part of the cluster key, so keep the legacy list
        # shape but report the grouped destination directly.
        top_dst_ips = [(str(dst), int(len(rows)))]

        mconf = 0.0
        try:
            mconf = float(max_conf)
            if math.isnan(mconf) or math.isinf(mconf):
                mconf = 0.0
        except (TypeError, ValueError):
            mconf = 0.0
        try:
            ml_mconf = float(max_ml_conf)
            if math.isnan(ml_mconf) or math.isinf(ml_mconf):
                ml_mconf = 0.0
        except (TypeError, ValueError):
            ml_mconf = 0.0
        clustered.append(
            {
                "attack_type": str(label),
                "src_ip": str(src),
                "dst_ip": str(dst),
                "count_flows": int(len(rows)),
                "top_dst_ports": [
                    {"port": int(p), "count": int(c)} for p, c in top_ports
                ],
                "top_dst_ips": [
                    {"ip": str(ip), "count": int(c)} for ip, c in top_dst_ips
                ],
                "max_confidence": mconf,
                "max_threat_confidence": mconf,
                "max_ml_confidence": ml_mconf,
                "severity": str(max_verdict or "Normal"),
            }
        )

    # sort by severity then confidence
    clustered.sort(
        key=lambda x: (SEV_ORDER.get(x["severity"], 0), x["max_confidence"]),
        reverse=True,
    )
    if max_clusters is None or max_clusters <= 0:
        return clustered
    return clustered[: int(max_clusters)]


def build_report(
    final_df: pd.DataFrame,
    run_folder: str,
    pcap_path: str,
    max_alerts: int | None = None,
    max_clusters: int | None = 100,
    pipeline_meta: dict | None = None,
) -> dict:
    df = final_df.copy() if final_df is not None else pd.DataFrame()
    pipeline_meta = dict(pipeline_meta or {})

    def _safe_float(x, default=0.0):
        try:
            v = float(x) if x is not None else default
            return default if (math.isnan(v) or math.isinf(v)) else v
        except (TypeError, ValueError):
            return default

    def _safe_int(x, default=0):
        try:
            v = int(float(x)) if x is not None else default
            return v
        except (TypeError, ValueError):
            return default

    def _safe_str(x, default=""):
        if x is None or (hasattr(x, "__float__") and str(x) == "nan"):
            return default
        s = str(x).strip()
        return s if s and s.lower() != "nan" else default

    # timeline (flow level)
    timeline = []
    if not df.empty:
        for _, r in df.iterrows():
            try:
                ts = float(r.get("ts") or 0.0)
                ts = 0.0 if (math.isnan(ts) or math.isinf(ts)) else ts
            except (TypeError, ValueError):
                ts = 0.0
            timeline.append(
                {
                    "ts": ts,
                    "src_ip": _safe_str(r.get("src_ip")),
                    "dst_ip": _safe_str(r.get("dst_ip")),
                    "dst_port": _safe_int(r.get("dst_port")),
                    "ml_label": _safe_str(r.get("ml_label")),
                    "ml_confidence": _safe_float(r.get("ml_confidence")),
                    "classification_confidence": _safe_float(r.get("ml_confidence")),
                    "confidence": _safe_float(r.get("confidence")),
                    "threat_confidence": _safe_float(r.get("confidence")),
                    "verdict": _safe_str(r.get("verdict"), "Normal"),
                }
            )
        timeline.sort(key=lambda item: item.get("ts", 0.0))

    # alerts list (flow-level) for drilldown UI
    alerts = []
    if not df.empty:
        # return only non-suppressed, non-normal as "alerts"
        w = df.copy()
        if "suppressed" in w.columns:
            w = w[w["suppressed"] == False]
        w = w[w["verdict"].isin(["Medium", "High", "Critical"])]
        dedup_subset = ["src_ip", "dst_ip", "dst_port", "ml_label", "verdict"]
        if "time_bucket" in w.columns:
            dedup_subset.append("time_bucket")
        w = w.drop_duplicates(subset=dedup_subset)

        for _, r in w.iterrows():
            try:
                ts = float(r.get("ts") or 0.0)
                ts = 0.0 if (math.isnan(ts) or math.isinf(ts)) else ts
            except (TypeError, ValueError):
                ts = 0.0
            alerts.append(
                {
                    "type": "ML",
                    "ts": ts,
                    "src_ip": _safe_str(r.get("src_ip")),
                    "dst_ip": _safe_str(r.get("dst_ip")),
                    "dst_port": int(r.get("dst_port") or 0),
                    "ml_label": _safe_str(r.get("ml_label")),
                    "ml_confidence": _safe_float(r.get("ml_confidence")),
                    "classification_confidence": _safe_float(r.get("ml_confidence")),
                    "confidence": _safe_float(r.get("confidence")),
                    "threat_confidence": _safe_float(r.get("confidence")),
                    "severity": _safe_str(r.get("verdict"), "Normal"),
                    "reason": _safe_str(r.get("reason")),
                    "zeek_service": _safe_str(r.get("service")),
                    "zeek_conn_state": _safe_str(r.get("conn_state")),
                    "zeek_proto": _safe_str(r.get("proto")),
                    "zeek_duration": _safe_float(r.get("duration")),
                    "zeek_bytes": {
                        "orig": _safe_float(r.get("orig_bytes")),
                        "resp": _safe_float(r.get("resp_bytes")),
                    },
                    "dns_top_query": _safe_str(r.get("dns_top_query")),
                    "dns_query_count": _safe_int(r.get("dns_query_count")),
                    "http_top_host": _safe_str(r.get("http_top_host")),
                    "http_top_uri": _safe_str(r.get("http_top_uri")),
                    "http_request_count": _safe_int(r.get("http_request_count")),
                    "ssl_top_sni": _safe_str(r.get("ssl_top_sni")),
                    "ssl_event_count": _safe_int(r.get("ssl_event_count")),
                    "heuristic": {
                        "type": _safe_str(r.get("heuristic_type")),
                        "score": _safe_float(r.get("heuristic_score")),
                        "reason": _safe_str(r.get("heuristic_reason")),
                    },
                }
            )

        alerts.sort(
            key=lambda item: (SEV_ORDER.get(item["severity"], 0), item["confidence"]),
            reverse=True,
        )

        if max_alerts is not None and int(max_alerts) > 0:
            alerts = alerts[: int(max_alerts)]

    # clustered view (attack-level)
    clusters = cluster_alerts(df, max_clusters=max_clusters)

    # summary & overall risk
    total_flows = int(len(df)) if not df.empty else 0
    suspicious = sum(
        1 for a in alerts if a["severity"] in ("Medium", "High", "Critical")
    )
    malicious = sum(1 for a in alerts if a["severity"] in ("High", "Critical"))
    security_findings = _build_security_findings(alerts, clusters)
    risk_per_ip = _build_risk_per_ip(alerts, clusters)
    overall_risk = _safe_float(security_findings.get("overall_risk"), 0.0)
    risk_level = _safe_str(security_findings.get("risk_level"), "Normal")

    # top talkers (attacker candidates) from alerts/clusters
    top_attackers = []
    if clusters:
        freq = defaultdict(int)
        for c in clusters:
            freq[c["src_ip"]] += c["count_flows"]
        top_attackers = [
            {"src_ip": k, "count_flows": v}
            for k, v in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

    generated_at = _now_iso()
    module_contract = _build_pcap_module_contract(
        generated_at=generated_at,
        security_findings=security_findings,
        alerts_count=len(alerts),
        suspicious_count=suspicious,
        cluster_count=len(clusters),
    )

    return {
        "meta": {
            "generated_at": generated_at,
            "pcap_path": pcap_path,
            "run_folder": run_folder,
            "zeek_requested": bool(pipeline_meta.get("zeek_requested", False)),
            "zeek_enrichment_succeeded": bool(
                pipeline_meta.get("zeek_enrichment_succeeded", False)
            ),
            "zeek_evidence_available": bool(
                pipeline_meta.get("zeek_evidence_available", False)
            ),
            "analysis_mode": str(pipeline_meta.get("analysis_mode", "base_only")),
            "comparison": dict(pipeline_meta.get("comparison", {})),
            "pipeline": pipeline_meta,
        },
        "summary": {
            "total_flows": total_flows,
            "alerts_count": len(alerts),
            "suspicious": suspicious,
            "malicious": malicious,
            "overall_risk": overall_risk,
            "risk_level": risk_level,
            "risk_context_label": _safe_str(
                security_findings.get("risk_context_label"), "Unknown Context"
            ),
            "risk_display": _safe_str(
                security_findings.get("risk_display"), risk_level
            ),
            "top_attackers": top_attackers,
            "security_score": _safe_float(
                security_findings.get("security_score"), 100.0
            ),
            "score_explanation": security_findings.get("score_explanation"),
            "security_score_level": _safe_str(
                security_findings.get("security_score_level"), "Secure"
            ),
            "top_risk": security_findings.get("top_risk"),
            "security_summary": _safe_str(
                security_findings.get("security_summary")
            ),
            "summary": _safe_str(
                security_findings.get("security_summary")
            ),
            "security_trend": _safe_str(
                security_findings.get("security_trend")
            ),
            "cluster_count": _safe_int(
                security_findings.get("cluster_count"), len(clusters)
            ),
            "severity_counts": security_findings.get("severity_counts"),
        },
        "module_contract": module_contract,
        "risk_per_ip": risk_per_ip,
        "clusters": clusters,  # ✅ attack-level results
        "alerts": alerts,  # ✅ flow-level drilldown
        "timeline": timeline,  # ✅ time series
    }
