import json
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import xgboost as xgb

# ==== paths (عدّلهم حسب مكان ملفاتك) ====
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(exist_ok=True)

RT_IOT_PATH = DATA_DIR / "RT_IOT2022.csv"
LYCOS_TRAIN_PATH = DATA_DIR / "train_set_LYCOS.csv"  # أو train_set.csv عندك
LYCOS_TEST_PATH = DATA_DIR / "test_set_LYCOS.csv"  # أو test_set.csv
LYCOS_CV_PATH = DATA_DIR / "crossval_set_LYCOS.csv"

OUT_MODEL = MODEL_DIR / "threat_model_pcap65.pkl"
OUT_METRICS = MODEL_DIR / "metrics_pcap65.json"

PCAP_CONTRACT_COLS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "ip_prot",
    "ts",
    "flow_duration",
    "fwd_pkts_tot",
    "bwd_pkts_tot",
    "fwd_bytes_tot",
    "bwd_bytes_tot",
    "flow_pkts_per_sec",
    "bytes_per_s",
    "down_up_ratio",
    "fwd_pkts_payload.min",
    "fwd_pkts_payload.max",
    "fwd_pkts_payload.tot",
    "fwd_pkts_payload.avg",
    "fwd_pkts_payload.std",
    "bwd_pkts_payload.min",
    "bwd_pkts_payload.max",
    "bwd_pkts_payload.tot",
    "bwd_pkts_payload.avg",
    "bwd_pkts_payload.std",
    "flow_pkts_payload.min",
    "flow_pkts_payload.max",
    "flow_pkts_payload.tot",
    "flow_pkts_payload.avg",
    "flow_pkts_payload.std",
    "fwd_iat.min",
    "fwd_iat.max",
    "fwd_iat.tot",
    "fwd_iat.avg",
    "fwd_iat.std",
    "bwd_iat.min",
    "bwd_iat.max",
    "bwd_iat.tot",
    "bwd_iat.avg",
    "bwd_iat.std",
    "flow_iat.min",
    "flow_iat.max",
    "flow_iat.tot",
    "flow_iat.avg",
    "flow_iat.std",
    "flow_FIN_flag_count",
    "flow_SYN_flag_count",
    "flow_RST_flag_count",
    "fwd_PSH_flag_count",
    "bwd_PSH_flag_count",
    "flow_ACK_flag_count",
    "fwd_URG_flag_count",
    "bwd_URG_flag_count",
    "flow_ECE_flag_count",
    "flow_CWR_flag_count",
    "active.min",
    "active.max",
    "active.tot",
    "active.avg",
    "active.std",
    "idle.min",
    "idle.max",
    "idle.tot",
    "idle.avg",
    "idle.std",
    "service",
]
META_COLS = ["src_ip", "dst_ip", "ts"]
FEATURE_COLS = [c for c in PCAP_CONTRACT_COLS if c not in META_COLS]


def load_csv(p: Path) -> pd.DataFrame:
    if not p.exists():
        return pd.DataFrame()
    df = pd.read_csv(p)
    # clean label
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()
        df = df[df["label"].notna()]
        df = df[~df["label"].isin(["", "unknown", "nan", "None"])]
    return df


def main():
    parts = [
        load_csv(RT_IOT_PATH),
        load_csv(LYCOS_TRAIN_PATH),
        load_csv(LYCOS_TEST_PATH),
        load_csv(LYCOS_CV_PATH),
    ]
    df = pd.concat([p for p in parts if not p.empty], ignore_index=True)
    # ---- Clean label early (IMPORTANT) ----
    df["label"] = df["label"].astype(str).str.strip()
    df = df[~df["label"].isin(["", "unknown", "nan", "None"])].copy()

    print("After label clean rows:", len(df))
    if df.empty or "label" not in df.columns:
        raise RuntimeError("No data loaded or missing 'label'.")

    # Keep metadata-only columns separate from required model features so the
    # saved metrics reflect the real train/infer contract.
    missing_metadata = [c for c in META_COLS if c not in df.columns]
    missing_feature_cols = [c for c in FEATURE_COLS if c not in df.columns]
    missing = [c for c in PCAP_CONTRACT_COLS if c not in df.columns]

    if missing:
        defaults = {
            c: ("unknown" if c in ("ip_prot", "service") else 0) for c in missing
        }
        df = df.assign(**defaults).copy()  # ✅ يزيل fragmentation

    # keep only what we need
    df = df[PCAP_CONTRACT_COLS + ["label"]].copy()
    print("Final DF rows:", len(df), "cols:", len(df.columns))
    print("Unique labels:", df["label"].nunique())
    print("Top labels:\n", df["label"].value_counts().head(10))
    print("ALL LABELS (sorted):")
    print(sorted(df["label"].unique()))

    print("LABEL COUNTS (full):")
    print(df["label"].value_counts())
    # encoders
    proto_encoder = LabelEncoder()
    service_encoder = LabelEncoder()
    label_encoder = LabelEncoder()

    proto_vals = df["ip_prot"].fillna("unknown").astype(str)
    svc_vals = df["service"].fillna("unknown").astype(str)
    lbl_vals = df["label"].astype(str)

    # make sure "unknown" exists for proto/service only
    proto_encoder.fit(np.unique(np.append(proto_vals.unique(), ["unknown"])))
    service_encoder.fit(np.unique(np.append(svc_vals.unique(), ["unknown"])))
    label_encoder.fit(lbl_vals.unique())

    # transform proto/service
    def safe_transform(enc, s, unknown="unknown"):
        s = s.fillna(unknown).astype(str)
        classes = set(enc.classes_)
        s = s.apply(lambda x: x if x in classes else unknown)
        return enc.transform(s)

    df["ip_prot"] = safe_transform(proto_encoder, df["ip_prot"])
    df["service"] = safe_transform(service_encoder, df["service"])
    y = label_encoder.transform(df["label"])

    X = df[FEATURE_COLS].copy()
    # numeric cleanup
    for c in X.columns:
        if c not in ("ip_prot", "service"):
            X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0)

    # split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # SMOTE (خفيف)
    y_series = pd.Series(y_train)
    class_counts = y_series.value_counts()  # counts per class id (safe)
    min_class_size = int(class_counts.min())

    min_class = int(class_counts[class_counts > 0].min())
    k = min(5, max(1, min_class - 1))
    smote = SMOTE(random_state=42, k_neighbors=k)
    X_train, y_train = smote.fit_resample(X_train, y_train)

    # train model
    model = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=42,
        eval_metric="mlogloss",
        tree_method="hist",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # eval
    y_pred = model.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    labels_used = np.unique(y_test)
    label_names = label_encoder.inverse_transform(labels_used)

    rep = classification_report(
        y_test,
        y_pred,
        labels=labels_used,
        target_names=label_names,
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(y_test, y_pred, labels=labels_used).tolist()

    metrics = {
        "accuracy": acc,
        "macro_f1": float(rep.get("macro avg", {}).get("f1-score", 0.0)),
        "labels": [str(x) for x in label_names],
        "confusion_matrix": cm,
        "num_features": int(len(FEATURE_COLS)),
        "feature_cols": FEATURE_COLS,
        "metadata_only_cols": META_COLS,
        "missing_metadata_cols": missing_metadata,
        "missing_required_feature_cols": missing_feature_cols,
    }
    missing_ratio = len(missing_feature_cols) / len(FEATURE_COLS) if FEATURE_COLS else 0
    metrics["missing_contract_cols"] = missing_feature_cols
    metrics["missing_ratio"] = missing_ratio
    OUT_METRICS.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # save bundle
    trained_columns = FEATURE_COLS[:]  # IMPORTANT: only features (no src_ip/dst_ip/ts)
    joblib.dump(
        (model, label_encoder, proto_encoder, service_encoder, trained_columns),
        str(OUT_MODEL),
    )

    print("Saved:", OUT_MODEL)
    print("Accuracy:", acc)
    print("Features:", len(trained_columns))


if __name__ == "__main__":
    main()
