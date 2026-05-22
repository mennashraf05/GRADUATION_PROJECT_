# PCAP Model and Metrics Deep Check

## Inspected Files

- `Backend/model/threat_model_pcap65.pkl`
- `Backend/model/threat_model.pkl`
- `Backend/model/label_encoder.pkl`
- `Backend/model/metrics_pcap65.json`
- `Backend/model/metrics.json`
- `Backend/model/readme.txt`
- `Backend/train_pcap65_model.py`
- `Backend/pcap_engine/ml_infer.py`

## Runtime Model

Runtime PCAP model path:
- `Backend/app.py`: `MODEL_PATH = MODEL_DIR / "threat_model_pcap65.pkl"`.

Model bundle contract:
- `Backend/pcap_engine/ml_infer.py` `load_model_bundle` expects 5-tuple `(model, label_encoder, proto_encoder, service_encoder, trained_columns)`.

Training script output:
- `Backend/train_pcap65_model.py` writes `threat_model_pcap65.pkl` and `metrics_pcap65.json`.

## Model Type

Confirmed from training script:
- `xgboost.XGBClassifier`.
- Multiclass labels through `LabelEncoder`.
- Categorical encoders for `ip_prot` and `service`.
- `SMOTE` used on training split before model fitting.

Do not claim the pickle was opened and introspected; evidence is from training script and runtime bundle contract.

## Metrics in `metrics_pcap65.json`

Explicit values:
- Accuracy: `0.9808836341008089`.
- Macro-F1: `0.9064385448656961`.
- Confusion matrix: present.
- Dataset name: not present.
- Precision: not present.
- Recall: not present.
- Weighted-F1: not present.
- Classification report: not present as full precision/recall report.

Labels: 26 labels listed in `04_ai_ml_detection_evidence.md`.

Feature count:
- `num_features`: `62`.

Contract notes in metrics file:
- `metadata_only_cols`: `src_ip`, `dst_ip`, `ts`.
- `missing_metadata_cols`: `src_ip`, `dst_ip`, `ts`.
- `missing_required_feature_cols`: `fwd_bytes_tot`, `bwd_bytes_tot`.
- `missing_contract_cols`: `fwd_bytes_tot`, `bwd_bytes_tot`.
- `missing_ratio`: `0.03225806451612903`.

Important limitation:
- The metrics file itself reports missing contract columns. The pipeline separately validates runtime CIC features; ask owner whether this metrics file is final and how to explain missing columns.

## Metrics in `metrics.json`

Explicit values:
- Overall accuracy: `0.9994734739823523`.
- Macro-F1: `0.936641991669158`.
- Per-class F1: present.
- Confusion matrix: present.
- Labels: 14 labels.

Status:
- Older/alternate metrics. Runtime PCAP65 path uses `metrics_pcap65.json` for admin governance/version and `threat_model_pcap65.pkl` for inference.

## No Metrics Found For

For the PCAP65 metrics file:
- Precision values.
- Recall values.
- Weighted-F1.
- Dataset name.
- Train/test sample counts.

Safe statement:
- “No precision, recall, weighted-F1, or dataset-name fields were found in the inspected PCAP65 metrics file.”
