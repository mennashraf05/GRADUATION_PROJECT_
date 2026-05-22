import pandas as pd


FAILED_STATES = {"REJ", "S0", "RSTO", "RSTR", "SH", "SHR"}


def _coerce_numeric(work: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    for col in columns:
        if col not in work.columns:
            work[col] = 0
        work[col] = pd.to_numeric(work[col], errors="coerce").fillna(0)
    return work


def _pick_numeric_series(
    work: pd.DataFrame,
    primary: str,
    fallback: str,
) -> pd.Series:
    primary_series = (
        pd.to_numeric(work[primary], errors="coerce").fillna(0)
        if primary in work.columns
        else pd.Series(0, index=work.index, dtype="float64")
    )
    fallback_series = (
        pd.to_numeric(work[fallback], errors="coerce").fillna(0)
        if fallback in work.columns
        else pd.Series(0, index=work.index, dtype="float64")
    )
    return primary_series.where(primary_series > 0, fallback_series)


def _derive_failed_indicator(work: pd.DataFrame) -> pd.Series:
    conn_state = (
        work["conn_state"].fillna("").astype(str).str.strip().str.upper()
        if "conn_state" in work.columns
        else pd.Series("", index=work.index, dtype="object")
    )
    state_failed = conn_state.isin(FAILED_STATES).astype(int)

    syn_count = (
        pd.to_numeric(work["flow_SYN_flag_count"], errors="coerce").fillna(0)
        if "flow_SYN_flag_count" in work.columns
        else pd.Series(0, index=work.index, dtype="float64")
    )
    ack_count = (
        pd.to_numeric(work["flow_ACK_flag_count"], errors="coerce").fillna(0)
        if "flow_ACK_flag_count" in work.columns
        else pd.Series(0, index=work.index, dtype="float64")
    )
    rst_count = (
        pd.to_numeric(work["flow_RST_flag_count"], errors="coerce").fillna(0)
        if "flow_RST_flag_count" in work.columns
        else pd.Series(0, index=work.index, dtype="float64")
    )
    bwd_pkts = (
        pd.to_numeric(work["bwd_pkts_tot"], errors="coerce").fillna(0)
        if "bwd_pkts_tot" in work.columns
        else pd.Series(0, index=work.index, dtype="float64")
    )
    duration = pd.to_numeric(work["duration"], errors="coerce").fillna(0)

    approx_failed = (
        (rst_count > 0)
        | ((syn_count > 0) & (ack_count <= 0))
        | ((syn_count >= 2) & (bwd_pkts <= 0) & (duration < 1.0))
    ).astype(int)

    has_conn_state = conn_state != ""
    return state_failed.where(has_conn_state, approx_failed).astype(int)


def build_flow_context_features(df: pd.DataFrame, window_s: int = 60) -> pd.DataFrame:
    if df is None or df.empty:
        return df

    work = df.copy().rename(
        columns={
            "id.orig_h": "src_ip",
            "id.orig_p": "src_port",
            "id.resp_h": "dst_ip",
            "id.resp_p": "dst_port",
        }
    )

    for col in ["src_ip", "dst_ip", "conn_state"]:
        if col not in work.columns:
            work[col] = ""
        work[col] = work[col].fillna("").astype(str).str.strip()

    if "duration" not in work.columns and "flow_duration" in work.columns:
        work["duration"] = work["flow_duration"]

    work = _coerce_numeric(
        work,
        [
            "src_port",
            "dst_port",
            "duration",
            "orig_bytes",
            "resp_bytes",
            "fwd_bytes_tot",
            "bwd_bytes_tot",
            "ts",
        ],
    )

    work["time_bucket"] = (work["ts"] // max(int(window_s or 60), 1)).astype(int)
    orig_bytes = _pick_numeric_series(work, "orig_bytes", "fwd_bytes_tot")
    resp_bytes = _pick_numeric_series(work, "resp_bytes", "bwd_bytes_tot")
    work["bytes_total"] = orig_bytes + resp_bytes
    work["bytes_ratio"] = orig_bytes / (resp_bytes + 1)
    work["is_short"] = (work["duration"] < 1).astype(int)
    work["is_long"] = (work["duration"] > 60).astype(int)
    work["is_failed"] = _derive_failed_indicator(work)
    count_col = "uid"
    if count_col not in work.columns:
        count_col = "_flow_counter_uid"
        work[count_col] = pd.RangeIndex(start=0, stop=len(work), step=1)

    src_group = work.groupby(["src_ip", "time_bucket"])
    target_group = work.groupby(["src_ip", "dst_ip", "time_bucket"])
    target_port_group = work.groupby(["src_ip", "dst_ip", "dst_port", "time_bucket"])

    work["src_conn_count"] = src_group[count_col].transform("count")
    work["src_unique_ports"] = src_group["dst_port"].transform("nunique")
    work["src_unique_targets"] = src_group["dst_ip"].transform("nunique")
    work["src_failed_ratio"] = src_group["is_failed"].transform("mean").fillna(0.0)
    work["src_short_ratio"] = src_group["is_short"].transform("mean").fillna(0.0)

    work["src_dst_conn_count"] = target_group[count_col].transform("count")
    work["src_dst_failed_ratio"] = target_group["is_failed"].transform("mean").fillna(0.0)
    work["src_dst_short_ratio"] = target_group["is_short"].transform("mean").fillna(0.0)

    work["src_dst_port_conn_count"] = target_port_group[count_col].transform("count")
    work["src_dst_port_failed_ratio"] = (
        target_port_group["is_failed"].transform("mean").fillna(0.0)
    )
    work["src_dst_port_short_ratio"] = (
        target_port_group["is_short"].transform("mean").fillna(0.0)
    )

    src_conn_denominator = work["src_conn_count"].clip(lower=1)
    work["src_dst_conn_share"] = (
        pd.to_numeric(work["src_dst_conn_count"], errors="coerce").fillna(0)
        / src_conn_denominator
    )
    work["src_dst_port_conn_share"] = (
        pd.to_numeric(work["src_dst_port_conn_count"], errors="coerce").fillna(0)
        / src_conn_denominator
    )
    return work


def build_flow_features(df: pd.DataFrame, window_s: int = 60):
    return build_flow_context_features(df, window_s=window_s)
