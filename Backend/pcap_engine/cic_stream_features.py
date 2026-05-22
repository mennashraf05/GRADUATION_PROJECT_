import csv
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd


LOGGER = logging.getLogger(__name__)


@dataclass
class RunningStats:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0
    min_v: float = float("inf")
    max_v: float = float("-inf")
    tot: float = 0.0

    def add(self, x: float):
        if x is None:
            return
        x = float(x)
        self.n += 1
        self.tot += x
        self.min_v = min(self.min_v, x)
        self.max_v = max(self.max_v, x)
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    def std(self) -> float:
        if self.n <= 1:
            return 0.0
        return math.sqrt(self.m2 / (self.n - 1))

    def min(self) -> float:
        return 0.0 if self.min_v == float("inf") else float(self.min_v)

    def max(self) -> float:
        return 0.0 if self.max_v == float("-inf") else float(self.max_v)

    def avg(self) -> float:
        return float(self.mean) if self.n > 0 else 0.0

    def total(self) -> float:
        return float(self.tot)


FlowKey = Tuple[str, str, int, int, int]  # src, dst, sport, dport, proto


@dataclass
class FlowAgg:
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_len: RunningStats = field(default_factory=RunningStats)
    bwd_len: RunningStats = field(default_factory=RunningStats)
    flow_len: RunningStats = field(default_factory=RunningStats)
    last_fwd_ts: Optional[float] = None
    last_bwd_ts: Optional[float] = None
    last_flow_ts: Optional[float] = None
    fwd_iat: RunningStats = field(default_factory=RunningStats)
    bwd_iat: RunningStats = field(default_factory=RunningStats)
    flow_iat: RunningStats = field(default_factory=RunningStats)
    fin_cnt: int = 0
    syn_cnt: int = 0
    rst_cnt: int = 0
    psh_fwd_cnt: int = 0
    psh_bwd_cnt: int = 0
    ack_cnt: int = 0
    urg_fwd_cnt: int = 0
    urg_bwd_cnt: int = 0
    ece_cnt: int = 0
    cwr_cnt: int = 0
    IDLE_THRESH: float = 2.0
    active_stats: RunningStats = field(default_factory=RunningStats)
    idle_stats: RunningStats = field(default_factory=RunningStats)
    active_start: Optional[float] = None

    def update_time(self, ts: float):
        if self.first_ts is None:
            self.first_ts = ts
            self.active_start = ts
        if self.last_ts is not None:
            gap = ts - self.last_ts
            if gap > self.IDLE_THRESH:
                if self.active_start is not None:
                    self.active_stats.add(self.last_ts - self.active_start)
                self.idle_stats.add(gap)
                self.active_start = ts
        self.last_ts = ts

    def update_iat(self, ts: float, direction: str):
        if self.last_flow_ts is not None:
            self.flow_iat.add(ts - self.last_flow_ts)
        self.last_flow_ts = ts

        if direction == "fwd":
            if self.last_fwd_ts is not None:
                self.fwd_iat.add(ts - self.last_fwd_ts)
            self.last_fwd_ts = ts
        else:
            if self.last_bwd_ts is not None:
                self.bwd_iat.add(ts - self.last_bwd_ts)
            self.last_bwd_ts = ts

    def update_flags(self, flags_int: int, direction: str):
        if flags_int & FIN:
            self.fin_cnt += 1
        if flags_int & SYN:
            self.syn_cnt += 1
        if flags_int & RST:
            self.rst_cnt += 1
        if flags_int & ACK:
            self.ack_cnt += 1
        if flags_int & ECE:
            self.ece_cnt += 1
        if flags_int & CWR:
            self.cwr_cnt += 1
        if direction == "fwd":
            if flags_int & PSH:
                self.psh_fwd_cnt += 1
            if flags_int & URG:
                self.urg_fwd_cnt += 1
        else:
            if flags_int & PSH:
                self.psh_bwd_cnt += 1
            if flags_int & URG:
                self.urg_bwd_cnt += 1

    def add_packet(self, ts: float, pkt_len: int, direction: str, flags_int: int):
        self.update_time(ts)
        self.update_iat(ts, direction)
        self.update_flags(flags_int, direction)

        self.flow_len.add(pkt_len)
        if direction == "fwd":
            self.fwd_pkts += 1
            self.fwd_bytes += pkt_len
            self.fwd_len.add(pkt_len)
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt_len
            self.bwd_len.add(pkt_len)

    def finalize(self):
        if (
            self.first_ts is not None
            and self.last_ts is not None
            and self.active_start is not None
        ):
            self.active_stats.add(self.last_ts - self.active_start)


@dataclass
class BidirectionalFlow:
    """
    Group packets by an unordered flow pair, but keep the first observed
    packet direction as forward for CIC directional fields.
    """

    forward_key: FlowKey
    reverse_key: FlowKey
    agg: FlowAgg = field(default_factory=FlowAgg)


def _to_int(x: str) -> int:
    try:
        return int(x)
    except Exception:
        return 0


def _pick_ip(ip4_src, ip4_dst, ip6_src, ip6_dst) -> Tuple[str, str]:
    src = ip4_src or ip6_src or ""
    dst = ip4_dst or ip6_dst or ""
    return src, dst


def _ports(tcp_s, tcp_d, udp_s, udp_d) -> Tuple[int, int]:
    if tcp_s or tcp_d:
        return _to_int(tcp_s), _to_int(tcp_d)
    return _to_int(udp_s), _to_int(udp_d)


def _parse_flags(v: str) -> int:
    if not v:
        return 0
    s = str(v).strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s)
    except Exception:
        return 0


def _canonical_pair(
    src: str, dst: str, sport: int, dport: int, proto: int
) -> tuple[tuple[FlowKey, FlowKey], FlowKey, FlowKey]:
    original = (src, dst, sport, dport, proto)
    reverse = (dst, src, dport, sport, proto)
    pair = (original, reverse) if original <= reverse else (reverse, original)
    return pair, original, reverse


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def build_cic_features_from_tshark_csv(csv_path: str) -> pd.DataFrame:
    """
    Read tshark-exported packet rows and aggregate them into CIC-like flow
    features. Forward/backward is based on the first observed packet in the
    bidirectional flow, not on lexicographic endpoint ordering.
    """
    flows: Dict[Tuple[FlowKey, FlowKey], BidirectionalFlow] = {}

    p = Path(csv_path)
    if not p.exists():
        return pd.DataFrame()

    rows_seen = 0
    parsed_rows = 0
    parse_errors = 0
    logged_parse_errors = 0
    max_logged_parse_errors = 5

    with p.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row_index, row in enumerate(reader, start=1):
            rows_seen += 1
            if not row:
                continue

            try:
                ts = float(row[0].strip('"')) if row[0] else None
                if ts is None:
                    continue

                ip_src = row[1].strip('"') if len(row) > 1 else ""
                ip_dst = row[2].strip('"') if len(row) > 2 else ""
                ip6_src = row[3].strip('"') if len(row) > 3 else ""
                ip6_dst = row[4].strip('"') if len(row) > 4 else ""

                tcp_s = row[5].strip('"') if len(row) > 5 else ""
                tcp_d = row[6].strip('"') if len(row) > 6 else ""
                udp_s = row[7].strip('"') if len(row) > 7 else ""
                udp_d = row[8].strip('"') if len(row) > 8 else ""

                proto = _to_int(row[9].strip('"')) if len(row) > 9 else 0
                # These model-compatible CIC "*payload*" fields currently use
                # tshark frame length, not pure L4 payload length.
                pkt_len = _to_int(row[10].strip('"')) if len(row) > 10 else 0
                flags = _parse_flags(row[11].strip('"')) if len(row) > 11 else 0

                src, dst = _pick_ip(ip_src, ip_dst, ip6_src, ip6_dst)
                if not src or not dst:
                    continue

                sport, dport = _ports(tcp_s, tcp_d, udp_s, udp_d)
                pair, original_key, reverse_key = _canonical_pair(
                    src, dst, sport, dport, proto
                )

                flow = flows.get(pair)
                if flow is None:
                    flow = BidirectionalFlow(
                        forward_key=original_key,
                        reverse_key=reverse_key,
                    )
                    flows[pair] = flow

                direction = "fwd" if original_key == flow.forward_key else "bwd"
                flow.agg.add_packet(ts, pkt_len, direction, flags)
                parsed_rows += 1
            except Exception as exc:
                parse_errors += 1
                if logged_parse_errors < max_logged_parse_errors:
                    LOGGER.warning(
                        "CIC parser row skipped | row_index=%s | error=%s | sample=%s",
                        row_index,
                        str(exc),
                        row[:4],
                    )
                    logged_parse_errors += 1
                continue

    out_rows: List[Dict[str, Any]] = []
    for flow in flows.values():
        agg = flow.agg
        agg.finalize()
        src, dst, sport, dport, proto = flow.forward_key

        duration = 0.0
        if agg.first_ts is not None and agg.last_ts is not None:
            duration = max(0.0, agg.last_ts - agg.first_ts)

        flow_pkts = agg.fwd_pkts + agg.bwd_pkts
        flow_bytes = agg.fwd_bytes + agg.bwd_bytes
        bytes_per_s = (flow_bytes / duration) if duration > 0 else 0.0
        pkt_per_s = (flow_pkts / duration) if duration > 0 else 0.0
        down_up_ratio = (agg.bwd_bytes / agg.fwd_bytes) if agg.fwd_bytes > 0 else 0.0

        out_rows.append(
            {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "ip_prot": proto,
                "ts": agg.first_ts,
                "flow_duration": duration,
                "fwd_pkts_tot": agg.fwd_pkts,
                "bwd_pkts_tot": agg.bwd_pkts,
                "fwd_bytes_tot": agg.fwd_bytes,
                "bwd_bytes_tot": agg.bwd_bytes,
                "flow_pkts_per_sec": pkt_per_s,
                "bytes_per_s": bytes_per_s,
                "down_up_ratio": down_up_ratio,
                "fwd_pkts_payload.min": agg.fwd_len.min(),
                "fwd_pkts_payload.max": agg.fwd_len.max(),
                "fwd_pkts_payload.tot": agg.fwd_len.total(),
                "fwd_pkts_payload.avg": agg.fwd_len.avg(),
                "fwd_pkts_payload.std": agg.fwd_len.std(),
                "bwd_pkts_payload.min": agg.bwd_len.min(),
                "bwd_pkts_payload.max": agg.bwd_len.max(),
                "bwd_pkts_payload.tot": agg.bwd_len.total(),
                "bwd_pkts_payload.avg": agg.bwd_len.avg(),
                "bwd_pkts_payload.std": agg.bwd_len.std(),
                "flow_pkts_payload.min": agg.flow_len.min(),
                "flow_pkts_payload.max": agg.flow_len.max(),
                "flow_pkts_payload.tot": agg.flow_len.total(),
                "flow_pkts_payload.avg": agg.flow_len.avg(),
                "flow_pkts_payload.std": agg.flow_len.std(),
                "fwd_iat.min": agg.fwd_iat.min(),
                "fwd_iat.max": agg.fwd_iat.max(),
                "fwd_iat.tot": agg.fwd_iat.total(),
                "fwd_iat.avg": agg.fwd_iat.avg(),
                "fwd_iat.std": agg.fwd_iat.std(),
                "bwd_iat.min": agg.bwd_iat.min(),
                "bwd_iat.max": agg.bwd_iat.max(),
                "bwd_iat.tot": agg.bwd_iat.total(),
                "bwd_iat.avg": agg.bwd_iat.avg(),
                "bwd_iat.std": agg.bwd_iat.std(),
                "flow_iat.min": agg.flow_iat.min(),
                "flow_iat.max": agg.flow_iat.max(),
                "flow_iat.tot": agg.flow_iat.total(),
                "flow_iat.avg": agg.flow_iat.avg(),
                "flow_iat.std": agg.flow_iat.std(),
                "flow_FIN_flag_count": agg.fin_cnt,
                "flow_SYN_flag_count": agg.syn_cnt,
                "flow_RST_flag_count": agg.rst_cnt,
                "fwd_PSH_flag_count": agg.psh_fwd_cnt,
                "bwd_PSH_flag_count": agg.psh_bwd_cnt,
                "flow_ACK_flag_count": agg.ack_cnt,
                "fwd_URG_flag_count": agg.urg_fwd_cnt,
                "bwd_URG_flag_count": agg.urg_bwd_cnt,
                "flow_ECE_flag_count": agg.ece_cnt,
                "flow_CWR_flag_count": agg.cwr_cnt,
                "active.min": agg.active_stats.min(),
                "active.max": agg.active_stats.max(),
                "active.tot": agg.active_stats.total(),
                "active.avg": agg.active_stats.avg(),
                "active.std": agg.active_stats.std(),
                "idle.min": agg.idle_stats.min(),
                "idle.max": agg.idle_stats.max(),
                "idle.tot": agg.idle_stats.total(),
                "idle.avg": agg.idle_stats.avg(),
                "idle.std": agg.idle_stats.std(),
                "service": "unknown",
            }
        )

    df = pd.DataFrame(out_rows)
    df.attrs["parse_errors"] = parse_errors
    df.attrs["parsed_rows"] = parsed_rows
    df.attrs["rows_seen"] = rows_seen
    if parse_errors > 0:
        LOGGER.info(
            "CIC parser completed | csv=%s | rows_seen=%s | parsed_rows=%s | parse_errors=%s",
            csv_path,
            rows_seen,
            parsed_rows,
            parse_errors,
        )
        if parsed_rows == 0 or (parse_errors / max(parsed_rows, 1)) >= 0.25:
            LOGGER.warning(
                "CIC parser error rate is high | csv=%s | parsed_rows=%s | parse_errors=%s",
                csv_path,
                parsed_rows,
                parse_errors,
            )
    if df.empty:
        return df
    return df
