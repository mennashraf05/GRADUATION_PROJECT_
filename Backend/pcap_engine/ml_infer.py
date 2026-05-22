import logging
import os
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd


LOGGER = logging.getLogger(__name__)
SAFE_CATEGORICAL_DEFAULTS = {
    "ip_prot": "unknown",
    "service": "unknown",
}
META_COLS = ["src_ip", "dst_ip", "src_port", "dst_port", "ts"]
METADATA_ONLY_COLS = ["src_ip", "dst_ip", "ts"]


class FeatureSchemaError(RuntimeError):
    pass


def load_model_bundle(model_path: str):
    p = Path(model_path)
    if not p.exists():
        raise FileNotFoundError(f"Model bundle not found: {p}")

    bundle = joblib.load(str(p))
    if not isinstance(bundle, (list, tuple)) or len(bundle) != 5:
        raise FeatureSchemaError(
            "Invalid model bundle format. Expected "
            "(model, label_encoder, proto_encoder, service_encoder, trained_columns)."
        )
    return bundle


def _debug_enabled(debug: bool | None = None) -> bool:
    if debug is not None:
        return bool(debug)
    return str(os.getenv("PCAP_PIPELINE_DEBUG", "false")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _clean_text(value, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return default
    return text


def _normalize_encoder_value(value, encoder, unknown: str = "unknown") -> str:
    classes = set(getattr(encoder, "classes_", []))
    text = _clean_text(value, default=unknown)

    if text in classes:
        return text

    lowered = {str(cls).lower(): str(cls) for cls in classes}
    lowered_match = lowered.get(text.lower())
    if lowered_match:
        return lowered_match

    try:
        numeric = float(text)
        candidates = [str(numeric), f"{numeric:.1f}"]
        if numeric.is_integer():
            candidates.extend([str(int(numeric)), f"{int(numeric)}.0"])
        for candidate in candidates:
            if candidate in classes:
                return candidate
    except (TypeError, ValueError):
        pass

    if unknown in classes:
        return unknown

    raise FeatureSchemaError(
        f"Unknown categorical value '{text}' cannot be mapped safely because "
        f"'{unknown}' is not available in encoder classes."
    )


def _align_to_trained_columns(
    df: pd.DataFrame,
    trained_columns: list[str],
    *,
    debug: bool = False,
) -> tuple[pd.DataFrame, dict]:
    work = df.copy()
    missing = [col for col in trained_columns if col not in work.columns]
    unexpected = [col for col in work.columns if col not in trained_columns]
    current_order = [col for col in work.columns if col in trained_columns]
    order_mismatch = current_order != trained_columns[: len(current_order)]
    generated_model_features = [col for col in work.columns if col in trained_columns]

    safe_missing = [col for col in missing if col in SAFE_CATEGORICAL_DEFAULTS]
    dangerous_missing = [col for col in missing if col not in SAFE_CATEGORICAL_DEFAULTS]
    extra_metadata_fields = [col for col in unexpected if col in METADATA_ONLY_COLS]
    passthrough_fields = [col for col in unexpected if col in META_COLS and col not in extra_metadata_fields]
    unexpected_non_model = [col for col in unexpected if col not in META_COLS]

    LOGGER.info(
        "Inference schema check | trained_feature_count=%s | generated_feature_count=%s | missing_required=%s | safe_missing=%s | extra_metadata=%s | passthrough=%s | unexpected_non_model=%s | order_mismatch=%s",
        len(trained_columns),
        len(generated_model_features),
        dangerous_missing,
        safe_missing,
        extra_metadata_fields,
        passthrough_fields,
        unexpected_non_model,
        order_mismatch,
    )
    LOGGER.info(
        "Inference schema detail | trained_model_features=%s | generated_pcap_features=%s",
        trained_columns,
        generated_model_features,
    )

    if dangerous_missing:
        raise FeatureSchemaError(
            "Inference feature schema mismatch. Missing required model features: "
            + ", ".join(dangerous_missing)
        )

    for col in safe_missing:
        work[col] = SAFE_CATEGORICAL_DEFAULTS[col]

    aligned = work.reindex(columns=trained_columns).copy()
    if debug:
        LOGGER.debug(
            "Aligned inference frame | rows=%s | cols=%s",
            len(aligned),
            len(aligned.columns),
        )

    return aligned, {
        "missing": missing,
        "unexpected": unexpected,
        "dangerous_missing": dangerous_missing,
        "safe_missing": safe_missing,
        "generated_model_features": generated_model_features,
        "extra_metadata_fields": extra_metadata_fields,
        "unexpected_non_model": unexpected_non_model,
        "order_mismatch": order_mismatch,
    }


def encode_categorical_series(
    series: pd.Series,
    encoder,
    *,
    unknown: str = "unknown",
) -> pd.Series:
    normalized = series.apply(
        lambda value: _normalize_encoder_value(value, encoder, unknown)
    )
    encoded = encoder.transform(normalized)
    return pd.Series(encoded, index=series.index, dtype="int64")


def prepare_inference_frame(
    df: pd.DataFrame,
    trained_columns: list[str],
    *,
    proto_encoder=None,
    service_encoder=None,
    debug: bool | None = None,
) -> tuple[pd.DataFrame, dict]:
    debug_enabled = _debug_enabled(debug)
    work, schema_info = _align_to_trained_columns(
        df, list(trained_columns), debug=debug_enabled
    )

    if "ip_prot" in work.columns and proto_encoder is not None:
        work["ip_prot"] = encode_categorical_series(
            work["ip_prot"],
            proto_encoder,
            unknown=SAFE_CATEGORICAL_DEFAULTS["ip_prot"],
        )

    if "service" in work.columns and service_encoder is not None:
        work["service"] = encode_categorical_series(
            work["service"],
            service_encoder,
            unknown=SAFE_CATEGORICAL_DEFAULTS["service"],
        )

    numeric_cols = [
        col for col in trained_columns if col not in SAFE_CATEGORICAL_DEFAULTS
    ]
    for col in numeric_cols:
        original = work[col]
        coerced = pd.to_numeric(original, errors="coerce")
        invalid_count = int(coerced.isna().sum() - original.isna().sum())
        if invalid_count > 0 and debug_enabled:
            LOGGER.debug(
                "Numeric coercion introduced NaN values | column=%s | invalid_count=%s",
                col,
                invalid_count,
            )
        work[col] = coerced.fillna(0.0)

    X = work.loc[:, trained_columns].copy()
    if debug_enabled:
        LOGGER.debug(
            "Prepared inference frame | shape=%s | missing_columns=%s",
            X.shape,
            len(schema_info["missing"]),
        )
    return X, schema_info


def predict_flows(
    df: pd.DataFrame,
    model_path: str,
    *,
    debug: bool | None = None,
) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()

    debug_enabled = _debug_enabled(debug)
    model, label_encoder, proto_encoder, service_encoder, trained_columns = (
        load_model_bundle(model_path)
    )

    meta_df = pd.DataFrame(index=df.index)
    for col in META_COLS:
        meta_df[col] = df[col] if col in df.columns else None

    X, schema_info = prepare_inference_frame(
        df,
        list(trained_columns),
        proto_encoder=proto_encoder,
        service_encoder=service_encoder,
        debug=debug_enabled,
    )
    if debug_enabled:
        LOGGER.debug(
            "Running model inference | shape=%s | missing_columns=%s",
            X.shape,
            len(schema_info["missing"]),
        )

    preds = model.predict(X)
    probs = model.predict_proba(X) if hasattr(model, "predict_proba") else None
    labels = (
        label_encoder.inverse_transform(preds)
        if label_encoder is not None
        else preds.astype(str)
    )
    confidences = probs.max(axis=1) if probs is not None else [0.0] * len(X)

    label_counts = Counter(map(str, labels))
    LOGGER.info("Inference label distribution | %s", dict(sorted(label_counts.items())))
    if debug_enabled:
        LOGGER.debug(
            "Inference output | unique_labels=%s | schema_missing=%s | schema_unexpected=%s",
            len(label_counts),
            schema_info["missing"],
            schema_info["unexpected"],
        )

    out = meta_df.copy()
    out["src_port"] = pd.to_numeric(out["src_port"], errors="coerce").fillna(0).astype(int)
    out["dst_port"] = pd.to_numeric(out["dst_port"], errors="coerce").fillna(0).astype(int)
    out["ts"] = pd.to_numeric(out["ts"], errors="coerce").fillna(0.0).astype(float)
    out["ml_label"] = labels
    out["ml_confidence"] = pd.Series(confidences, index=out.index, dtype="float64").fillna(0.0)
    return out
