# AI / ML Detection Evidence

## Model Files

| File | Purpose | Evidence |
|---|---|---|
| `Backend/model/threat_model_pcap65.pkl` | Runtime PCAP model bundle | `Backend/app.py` `MODEL_PATH`; `Backend/pcap_engine/ml_infer.py` |
| `Backend/model/threat_model.pkl` | Older/alternate model file | Present in model folder; runtime PCAP path uses `threat_model_pcap65.pkl` |
| `Backend/model/label_encoder.pkl` | Separate encoder file | Present, but runtime PCAP65 bundle expects encoder inside model bundle |
| `Backend/model/metrics_pcap65.json` | PCAP65 metrics and feature contract | Loaded by admin governance/version logic and inspected directly |
| `Backend/model/metrics.json` | Older/alternate metrics | Present, not the runtime PCAP65 metrics path |
| `Backend/train_pcap65_model.py` | Training script | Confirms XGBoost, SMOTE, LabelEncoders, bundle format |

## Model Type

Confirmed by `Backend/train_pcap65_model.py`: `xgboost.XGBClassifier` multiclass classifier with `n_estimators=250`, `max_depth=8`, `learning_rate=0.08`, `tree_method="hist"`.

Safe wording: “The training script builds an XGBoost multiclass classifier for the PCAP65 model.”

## Bundle Contents

`Backend/pcap_engine/ml_infer.py` `load_model_bundle` expects exactly:

```text
(model, label_encoder, proto_encoder, service_encoder, trained_columns)
```

`Backend/train_pcap65_model.py` writes that same tuple with `joblib.dump`.

## Feature Columns

`Backend/model/metrics_pcap65.json` lists `num_features: 62`.

Feature columns:

```text
src_port, dst_port, ip_prot, flow_duration, fwd_pkts_tot, bwd_pkts_tot,
fwd_bytes_tot, bwd_bytes_tot, flow_pkts_per_sec, bytes_per_s, down_up_ratio,
fwd_pkts_payload.min, fwd_pkts_payload.max, fwd_pkts_payload.tot,
fwd_pkts_payload.avg, fwd_pkts_payload.std, bwd_pkts_payload.min,
bwd_pkts_payload.max, bwd_pkts_payload.tot, bwd_pkts_payload.avg,
bwd_pkts_payload.std, flow_pkts_payload.min, flow_pkts_payload.max,
flow_pkts_payload.tot, flow_pkts_payload.avg, flow_pkts_payload.std,
fwd_iat.min, fwd_iat.max, fwd_iat.tot, fwd_iat.avg, fwd_iat.std,
bwd_iat.min, bwd_iat.max, bwd_iat.tot, bwd_iat.avg, bwd_iat.std,
flow_iat.min, flow_iat.max, flow_iat.tot, flow_iat.avg, flow_iat.std,
flow_FIN_flag_count, flow_SYN_flag_count, flow_RST_flag_count,
fwd_PSH_flag_count, bwd_PSH_flag_count, flow_ACK_flag_count,
fwd_URG_flag_count, bwd_URG_flag_count, flow_ECE_flag_count,
flow_CWR_flag_count, active.min, active.max, active.tot, active.avg,
active.std, idle.min, idle.max, idle.tot, idle.avg, idle.std, service
```

Metadata-only columns: `src_ip`, `dst_ip`, `ts`.

## Output Labels / Classes

`metrics_pcap65.json` labels:

`ARP_poisioning`, `DDOS_Slowloris`, `DOS_SYN_Hping`, `MQTT_Publish`, `Metasploit_Brute_Force_SSH`, `NMAP_FIN_SCAN`, `NMAP_OS_DETECTION`, `NMAP_TCP_scan`, `NMAP_UDP_SCAN`, `NMAP_XMAS_TREE_SCAN`, `Thing_Speak`, `Wipro_bulb`, `benign`, `bot`, `ddos`, `dos_goldeneye`, `dos_hulk`, `dos_slowhttptest`, `dos_slowloris`, `ftp_patator`, `heartbleed`, `portscan`, `ssh_patator`, `webattack_bruteforce`, `webattack_sql_injection`, `webattack_xss`.

## Prediction Functions

- `Backend/pcap_engine/ml_infer.py` `predict_flows`: predicts labels and `ml_confidence` using `predict_proba().max(axis=1)` when available.
- `Backend/app.py` `run_ml_inference`: attaches `ml_label` and `ml_confidence` to the CIC dataframe and checks row-count consistency.

## Confidence Logic

Evidence:
- `Backend/pcap_engine/security_logic.py`: `CONFIDENCE_MODE_PRESETS` with Balanced `(0.70, 0.88)`, Strict `(0.78, 0.92)`, Relaxed `(0.62, 0.84)`.
- `confidence_tier` returns tiers used by `scorer.py`.
- `scorer.py` suppresses rows when `confidence_tier == "ignore"`.

## Severity Mapping

Evidence:
- `Backend/pcap_engine/security_logic.py` `LABEL_SEVERITY` maps labels to `Low`, `Medium`, `High`, `Critical`.
- `label_to_severity` uses label and confidence.
- `severity_to_score`, `severity_to_risk`, `verdict_from_context` produce score/risk/verdict semantics.

## Score Fusion

Evidence:
- `Backend/pcap_engine/scorer.py` `fuse_scores`.
- Formula in code: `raw_score = (0.95 * ml_score) + (0.05 * heuristic_score)`.
- Then `context_scaled = raw_score * support_multiplier`, verdict cap/floor logic, Normal rows forced to `final_score = 0.0`.

## Heuristic Rules

Evidence: `Backend/pcap_engine/heuristics.py`.

- `PortScan`: high connection count, many ports, mostly short connections, many targets, score `0.70`.
- `Beaconing`: long duration, low bytes, repeated traffic to small target set, score `0.45`.
- `FocusedBurst`: concentrated target traffic with elevated packet/byte rate, score `0.35`.

## False-Positive Reduction / Validation

Code-supported mechanisms:
- Confidence modes and ignore tier.
- `validation_fail_reason`.
- `should_suppress` for multicast/broadcast/noise and weak signals.
- `context_support_level` requires context support before promoting verdict.
- HTTP DoS subtype preference suppresses generic DoS when subtype-specific evidence explains same target window.
- Conservative heuristics comments explicitly say heuristics support validation rather than turning ordinary browsing bursts into alerts.

Evidence:
- `Backend/pcap_engine/security_logic.py`.
- `Backend/pcap_engine/scorer.py`.
- `Backend/pcap_engine/heuristics.py`.

## Metrics Available

From `Backend/model/metrics_pcap65.json`:

- Accuracy: `0.9808836341008089`
- Macro-F1: `0.9064385448656961`
- Confusion matrix: present.
- Labels: present.
- Feature columns: present.

No precision/recall/weighted-F1 values were found in `metrics_pcap65.json`.

From `Backend/model/metrics.json`:

- Overall accuracy: `0.9994734739823523`
- Macro-F1: `0.936641991669158`
- Per-class F1: present.
- Confusion matrix: present.

Use `metrics_pcap65.json` for PCAP65 runtime model claims unless owner confirms otherwise.

## Limitations

- Metrics file does not name the final evaluation dataset explicitly.
- Do not infer production accuracy from code.
- Do not claim precision/recall unless owner supplies a classification report containing them.
