from __future__ import annotations

import pandas as pd

from .security_logic import (
    base_verdict_from_signal,
    build_reason,
    confidence_tier,
    context_support_level,
    label_to_severity,
    severity_to_score,
    should_suppress,
    support_level_to_multiplier,
    validation_fail_reason,
    verdict_rank,
    verdict_from_context,
    verdict_score_cap,
    verdict_score_floor,
)

HTTP_DOS_SUBTYPE_LABELS = {
    "dos_goldeneye",
    "dos_hulk",
    "dos_slowhttptest",
    "dos_slowloris",
    "ddos_slowloris",
}
GENERIC_DOS_LABELS = {"dos", "ddos"}
HTTP_TARGET_PORTS = {80, 443, 8000, 8080, 8081, 8443}


def _apply_http_subtype_preference(out: pd.DataFrame) -> pd.DataFrame:
    if out is None or out.empty:
        return out

    labels = out["ml_label"].fillna("").astype(str).str.lower()
    verdicts = out["verdict"].fillna("Normal").astype(str)
    support = out["support_level"].fillna("none").astype(str).str.lower()
    dports = pd.to_numeric(out["dst_port"], errors="coerce").fillna(0).astype(int)
    services = (
        out["service"].fillna("").astype(str).str.strip().str.lower()
        if "service" in out.columns
        else pd.Series("", index=out.index, dtype="object")
    )
    time_bucket = (
        pd.to_numeric(out["time_bucket"], errors="coerce").fillna(0).astype(int)
        if "time_bucket" in out.columns
        else pd.Series(0, index=out.index, dtype="int64")
    )

    surfaced_subtype_mask = (
        labels.isin(HTTP_DOS_SUBTYPE_LABELS)
        & verdicts.isin(["Medium", "High", "Critical"])
        & support.isin(["moderate", "strong"])
    )
    if not bool(surfaced_subtype_mask.any()):
        return out

    subtype_keys = out.loc[
        surfaced_subtype_mask,
        ["src_ip", "dst_ip", "dst_port"],
    ].copy()
    subtype_keys["time_bucket"] = time_bucket.loc[surfaced_subtype_mask].values
    subtype_keys = subtype_keys.drop_duplicates()

    if subtype_keys.empty:
        return out

    generic_mask = (
        labels.isin(GENERIC_DOS_LABELS)
        & verdicts.isin(["Medium", "High", "Critical"])
        & (
            dports.isin(HTTP_TARGET_PORTS)
            | services.isin({"http", "https", "ssl"})
        )
    )
    if not bool(generic_mask.any()):
        return out

    generic_keys = out.loc[generic_mask, ["src_ip", "dst_ip", "dst_port"]].copy()
    generic_keys["time_bucket"] = time_bucket.loc[generic_mask].values
    generic_keys["_shadowed"] = True
    generic_shadow = generic_keys.merge(
        subtype_keys,
        on=["src_ip", "dst_ip", "dst_port", "time_bucket"],
        how="inner",
    )
    if generic_shadow.empty:
        return out

    shadowed_keys = generic_shadow.drop_duplicates()
    shadowed_key_set = set(
        map(
            tuple,
            shadowed_keys[["src_ip", "dst_ip", "dst_port", "time_bucket"]]
            .to_numpy()
            .tolist(),
        )
    )
    if not shadowed_key_set:
        return out

    shadow_mask = generic_mask & pd.Series(
        list(
            zip(
                out["src_ip"].astype(str),
                out["dst_ip"].astype(str),
                dports,
                time_bucket,
            )
        ),
        index=out.index,
    ).isin(shadowed_key_set)
    if not bool(shadow_mask.any()):
        return out

    existing_suppression_reason = out["suppressed_reason"].fillna("").astype(str)
    out.loc[
        shadow_mask & existing_suppression_reason.eq(""),
        "suppressed_reason",
    ] = (
        "Suppressed: subtype-specific HTTP DoS evidence already explains "
        "this target window"
    )
    out.loc[shadow_mask, "suppressed"] = True
    out.loc[shadow_mask, "verdict"] = "Normal"
    return out


def fuse_scores(df: pd.DataFrame, *, confidence_mode: str | None = None) -> pd.DataFrame:
    """
    Keep the existing architecture:
    ML prediction + heuristic score + validation + suppression + verdict.
    The final score is now context-aware and capped by the final verdict so the
    report risk level stays aligned with the validated outcome.
    """
    if df is None or df.empty:
        return pd.DataFrame()

    out = df.copy()
    for col in ("src_ip", "dst_ip", "src_port", "dst_port", "ml_label", "ml_confidence"):
        if col not in out.columns:
            out[col] = None

    if "heuristic_score" not in out.columns:
        out["heuristic_score"] = 0.0

    out["src_port"] = pd.to_numeric(out["src_port"], errors="coerce").fillna(0).astype(int)
    out["dst_port"] = pd.to_numeric(out["dst_port"], errors="coerce").fillna(0).astype(int)
    out["ml_confidence"] = pd.to_numeric(out["ml_confidence"], errors="coerce").fillna(0.0).astype(float)
    out["heuristic_score"] = pd.to_numeric(out["heuristic_score"], errors="coerce").fillna(0.0).astype(float)
    out["ml_label"] = out["ml_label"].fillna("").astype(str)

    suppression_results = out.apply(
        lambda row: should_suppress(
            str(row.get("src_ip") or ""),
            str(row.get("dst_ip") or ""),
            int(row.get("dst_port") or 0),
            str(row.get("ml_label") or ""),
            row=row,
        ),
        axis=1,
    )
    out["suppressed"] = suppression_results.apply(lambda result: bool(result.suppressed))
    out["suppressed_reason"] = suppression_results.apply(lambda result: str(result.reason or ""))

    out["severity"] = out.apply(
        lambda row: label_to_severity(
            row.get("ml_label"), float(row.get("ml_confidence") or 0.0)
        ),
        axis=1,
    )
    out["ml_score"] = out.apply(
        lambda row: severity_to_score(
            row.get("severity"), float(row.get("ml_confidence") or 0.0)
        ),
        axis=1,
    )
    out["confidence_tier"] = out.apply(
        lambda row: confidence_tier(
            row.get("ml_label"),
            float(row.get("ml_confidence") or 0.0),
            row=row,
            confidence_mode=confidence_mode,
        ),
        axis=1,
    )

    val_reasons = out.apply(
        lambda row: validation_fail_reason(
            row.get("ml_label"), row.get("dst_port"), row=row
        ),
        axis=1,
    )
    out["validation_failed"] = val_reasons.astype(str).str.len() > 0
    out["validation_reason"] = val_reasons.astype(str)

    out["support_level"] = out.apply(
        lambda row: context_support_level(
            row.get("ml_label"), row.get("dst_port"), row=row
        ),
        axis=1,
    )
    out["support_multiplier"] = out["support_level"].apply(support_level_to_multiplier)

    out["signal_verdict"] = out.apply(
        lambda row: base_verdict_from_signal(
            row.get("ml_label"),
            row.get("severity"),
            row.get("confidence_tier"),
            row=row,
        ),
        axis=1,
    )

    out.loc[out["validation_failed"] == True, "suppressed"] = True
    out.loc[out["confidence_tier"] == "ignore", "suppressed"] = True

    out["verdict"] = out.apply(
        lambda row: verdict_from_context(
            row.get("ml_label"),
            row.get("severity"),
            row.get("confidence_tier"),
            row.get("dst_port"),
            bool(row.get("suppressed")),
            row=row,
        ),
        axis=1,
    )
    out = _apply_http_subtype_preference(out)
    out["support_promoted"] = out.apply(
        lambda row: verdict_rank(row.get("verdict")) > verdict_rank(row.get("signal_verdict")),
        axis=1,
    )
    out["support_demoted"] = out.apply(
        lambda row: verdict_rank(row.get("verdict")) < verdict_rank(row.get("signal_verdict")),
        axis=1,
    )

    # Keep heuristics as a supporting hint, not a dominant risk amplifier.
    raw_score = (0.95 * out["ml_score"]) + (0.05 * out["heuristic_score"])
    context_scaled = raw_score * out["support_multiplier"]
    out["verdict_cap"] = out["verdict"].apply(verdict_score_cap)
    out["verdict_floor"] = out["verdict"].apply(verdict_score_floor)
    out["support_floor_factor"] = out["support_level"].map(
        {"none": 0.0, "weak": 0.0, "moderate": 0.5, "strong": 1.0}
    ).fillna(0.0)
    out["effective_verdict_floor"] = (
        out["verdict_floor"] * out["support_floor_factor"]
    )
    out["final_score"] = pd.to_numeric(context_scaled, errors="coerce").fillna(0.0).clip(lower=0.0, upper=1.0)
    out["final_score"] = out[["final_score", "verdict_cap"]].min(axis=1)
    verdict_mask = out["verdict"].astype(str) != "Normal"
    out.loc[verdict_mask, "final_score"] = out.loc[
        verdict_mask, ["final_score", "effective_verdict_floor"]
    ].max(axis=1)
    out.loc[out["verdict"] == "Normal", "final_score"] = 0.0

    out["reason"] = out.apply(
        lambda row: build_reason(
            row.get("ml_label"),
            float(row.get("ml_confidence") or 0.0),
            int(row.get("dst_port") or 0),
            suppressed_reason=str(row.get("suppressed_reason") or ""),
            validation_reason=str(row.get("validation_reason") or ""),
            confidence_tier_value=str(row.get("confidence_tier") or ""),
            row=row.to_dict(),
        ),
        axis=1,
    )

    out["confidence"] = out["final_score"].astype(float)
    out.drop(
        columns=[
            "verdict_cap",
            "verdict_floor",
            "support_floor_factor",
            "effective_verdict_floor",
        ],
        errors="ignore",
        inplace=True,
    )
    return out
