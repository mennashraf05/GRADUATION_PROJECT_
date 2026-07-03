# 07 - AI/ML Deep Dive

## Confirmed AI/ML parts

### PCAP ML

- Runtime inference: `Backend/pcap_engine/ml_infer.py`.
- Pipeline integration: `run_pcap_pipeline`, `run_ml_inference`, `build_base_detection_frame` in `Backend/app.py`.
- Model artifacts: `Backend/model/threat_model.pkl`, `Backend/model/threat_model_pcap65.pkl`, `Backend/model/label_encoder.pkl`.
- Metrics files: `Backend/model/metrics.json`, `Backend/model/metrics_pcap65.json`.
- Training script: `Backend/train_pcap65_model.py`.

Inputs:
- CIC-like flow features from `build_cic_features_from_tshark_csv`.
- `metrics_pcap65.json` lists 62 feature columns, including ports, protocol, duration, packet/byte totals, payload stats, IAT stats, TCP flags, active/idle stats, and `service`.
- Metadata-only columns include `src_ip`, `dst_ip`, `ts`.

Processing:
- `load_model_bundle` expects `(model, label_encoder, proto_encoder, service_encoder, trained_columns)`.
- `prepare_inference_frame` aligns generated columns to trained columns and raises `FeatureSchemaError` for missing required features.
- `predict_flows` outputs predicted labels and confidence.
- `security_logic.py` maps labels to severity/verdict and applies suppression/context support.
- `reporter.py` builds security score/risk report.

Outputs:
- attack label, confidence, severity/risk, verdict/reasons, report summary, dashboard security score.

Metrics safe to mention:
- `metrics.json`: `overall_accuracy = 0.9994734739823523`, `macro_f1 = 0.936641991669158`.
- `metrics_pcap65.json`: `accuracy = 0.9808836341008089`, `macro_f1 = 0.9064385448656961`, 26 labels and 62 features.
- Safe wording: "دي metrics محفوظة في ملفات المشروع، وليست ضمان production accuracy."

Metrics not available:
- لا يوجد من الفحص الحالي دليل على production evaluation حديث.
- لا يوجد model card كامل أو dataset split details كافية داخل docs التي فحصناها.

### Phishing ML

- Files: `Backend/phishing_scanner/ml.py`, `url_features.py`, `risk.py`, `train.py`.
- Runtime endpoint: `scan_url` in `Backend/phishing_scanner/scan.py`.
- Input: URL string.
- Feature extraction: `extract_features(url)`.
- Output: `ml_result` ثم `calculate_risk` يحولها إلى `risk_score` و `category`.
- VirusTotal is not ML; it is reputation enrichment from `virustotal.py`, controlled by `VIRUSTOTAL_API_KEY`.

Limitations:
- Accuracy metrics for phishing were not found in the inspected files like PCAP metrics.
- The final category is ML + rules + optional reputation, not pure model output.

### Identity risk scoring

- Files: `Backend/services/identity_web_scraper/scoring.py`, database/findings functions.
- This is more rule/scoring than confirmed trained ML.
- Safe wording: "risk scoring لل findings" وليس "AI dark web detection" إلا لو owner يثبت dataset/model.

### Vault AI behavior analysis

- Endpoint: `/api/ai/vault/analyze` -> `analyze_my_vault_behavior` in `Backend/app.py`.
- Frontend callers: `DashboardPage.tsx`, `SimpleDashboard.tsx`, `ChatbotWorkspacePage.tsx`.
- Based on vault/activity behavior inside app; no separate trained model file confirmed for vault.
- Safe wording: "behavior/risk analysis" وليس "ML model مؤكد" إلا لو الكود يثبت model منفصل.

### Chatbot LLM

- Files: `Backend/llm_providers/ollama_provider.py`, `gemini_provider.py`, `router.py`, `prompts.py`.
- Endpoints: `/api/chatbot/llm`, `/api/chatbot/pcap`, `/api/chatbot/identity`.
- Input: user message + module context.
- Processing: safe context builders in `Backend/app.py`, route to provider, fallback rule-based answer.
- Output: answer, provider/model status.
- Limitations: depends on `OLLAMA_ENABLED`, Ollama service, or `GEMINI_ENABLED` + `GEMINI_API_KEY`.

## Difference between confidence, risk score, and security score

- Model confidence: probability/confidence returned by ML inference for a predicted class. Evidence: `predict_flows` uses `predict_proba` max confidence.
- Risk score: module-specific risk value, e.g. phishing `final_risk_score` or PCAP `risk_level` derived from severity/context.
- Security score: user/dashboard-friendly score, especially PCAP score in `reporter.py`, where higher is better and risk lowers the score.

## Safe wording for graduation book

"النظام يستخدم ML في تحليل PCAP وتصنيف flows، ويستخدم model/rules في phishing URL risk assessment. النتائج تساعد في decision support وليست ضمان لاكتشاف كل الهجمات. الأرقام المذكورة هي metrics محفوظة في ملفات المشروع."

## Unsafe wording to avoid

- "Production accuracy is 98%/99%" بدون توضيح أنها file-reported.
- "AI detects all threats."
- "Dark web AI scanner" إذا لم يتم إثبات مصادر dark web من الكود.
- "Real-time IDS/IPS."
