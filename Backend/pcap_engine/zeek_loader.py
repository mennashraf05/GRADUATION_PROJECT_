import json
from pathlib import Path
import pandas as pd


def _load_zeek_json_log(run_folder, filename, required_columns):
    run_folder = Path(run_folder)
    log_path = run_folder / filename

    if not log_path.exists():
        return pd.DataFrame(columns=required_columns)

    rows = []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except Exception:
                continue

    if not rows:
        return pd.DataFrame(columns=required_columns)

    df = pd.DataFrame(rows)

    for col in required_columns:
        if col not in df.columns:
            df[col] = None

    return df


def load_conn(run_folder):
    required_columns = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
    ]
    return _load_zeek_json_log(run_folder, "conn.log", required_columns)


def load_dns(run_folder):
    required_columns = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "query",
        "qtype_name",
        "answers",
        "rcode_name",
    ]
    return _load_zeek_json_log(run_folder, "dns.log", required_columns)


def load_http(run_folder):
    required_columns = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "method",
        "host",
        "uri",
        "status_code",
        "user_agent",
    ]
    return _load_zeek_json_log(run_folder, "http.log", required_columns)


def load_ssl(run_folder):
    required_columns = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "server_name",
        "ja3",
        "version",
        "cipher",
    ]
    return _load_zeek_json_log(run_folder, "ssl.log", required_columns)
