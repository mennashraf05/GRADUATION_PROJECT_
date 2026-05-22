import pandas as pd


def _apply_heuristic(
    work: pd.DataFrame,
    condition: pd.Series,
    *,
    score: float,
    heuristic_type: str,
    reason: str,
) -> None:
    update_mask = condition & (work["heuristic_score"] < score)
    work.loc[update_mask, "heuristic_score"] = score
    work.loc[update_mask, "heuristic_type"] = heuristic_type
    work.loc[update_mask, "heuristic_reason"] = reason


def apply_heuristics(df: pd.DataFrame):
    if df is None or df.empty:
        work = pd.DataFrame() if df is None else df.copy()
        work["heuristic_score"] = pd.Series(dtype="float64")
        work["heuristic_type"] = pd.Series(dtype="object")
        work["heuristic_reason"] = pd.Series(dtype="object")
        return work

    work = df.copy()
    for col in [
        "src_conn_count",
        "src_unique_ports",
        "src_unique_targets",
        "src_short_ratio",
        "src_dst_conn_count",
        "src_dst_conn_share",
        "src_dst_port_conn_count",
        "is_long",
        "bytes_total",
        "flow_pkts_per_sec",
        "bytes_per_s",
    ]:
        if col not in work.columns:
            work[col] = 0

    work["heuristic_score"] = 0.0
    work["heuristic_type"] = "None"
    work["heuristic_reason"] = ""

    src_conn_count = pd.to_numeric(work["src_conn_count"], errors="coerce").fillna(0)
    src_unique_ports = pd.to_numeric(work["src_unique_ports"], errors="coerce").fillna(0)
    src_unique_targets = pd.to_numeric(
        work["src_unique_targets"], errors="coerce"
    ).fillna(0)
    src_short_ratio = pd.to_numeric(work["src_short_ratio"], errors="coerce").fillna(0)
    src_dst_conn_count = pd.to_numeric(
        work["src_dst_conn_count"], errors="coerce"
    ).fillna(0)
    src_dst_conn_share = pd.to_numeric(
        work["src_dst_conn_share"], errors="coerce"
    ).fillna(0)
    src_dst_port_conn_count = pd.to_numeric(
        work["src_dst_port_conn_count"], errors="coerce"
    ).fillna(0)
    bytes_total = pd.to_numeric(work["bytes_total"], errors="coerce").fillna(0)
    flow_pkts_per_sec = pd.to_numeric(
        work["flow_pkts_per_sec"], errors="coerce"
    ).fillna(0)
    bytes_per_s = pd.to_numeric(work["bytes_per_s"], errors="coerce").fillna(0)
    is_long = pd.to_numeric(work["is_long"], errors="coerce").fillna(0)

    # Keep scan heuristics conservative so they support validation instead of
    # turning ordinary browsing bursts into alerts.
    scan_condition = (
        (src_conn_count >= 120)
        & (src_unique_ports >= 25)
        & (src_short_ratio >= 0.60)
        & (src_unique_targets >= 10)
    )
    _apply_heuristic(
        work,
        scan_condition,
        score=0.70,
        heuristic_type="PortScan",
        reason=(
            "High connection count + many ports + mostly short connections"
        ),
    )

    # Treat beacon-like traffic as a weak supporting hint only. A long-lived
    # low-volume flow can still be benign, so the score stays deliberately low.
    beacon_condition = (
        (is_long == 1)
        & (bytes_total < 1024)
        & (src_conn_count >= 20)
        & (src_unique_ports <= 3)
        & (src_dst_conn_share >= 0.40)
    )
    _apply_heuristic(
        work,
        beacon_condition,
        score=0.45,
        heuristic_type="Beaconing",
        reason=(
            "Long duration + low bytes + repeated traffic to a small target set"
        ),
    )

    # Focused burst support is intentionally strict. We only hint at DoS-like
    # behavior when traffic is concentrated on one target and the packet/byte
    # rate is clearly elevated.
    focused_burst_condition = (
        (src_unique_ports <= 3)
        & (src_unique_targets <= 2)
        & (src_dst_conn_share >= 0.55)
        & (src_dst_conn_count >= 25)
        & (src_dst_port_conn_count >= 12)
        & ((flow_pkts_per_sec >= 40) | (bytes_per_s >= 100_000))
        & (src_short_ratio <= 0.70)
    )
    _apply_heuristic(
        work,
        focused_burst_condition,
        score=0.35,
        heuristic_type="FocusedBurst",
        reason=(
            "Sustained concentrated traffic to one target with elevated packet or byte rate"
        ),
    )

    return work
