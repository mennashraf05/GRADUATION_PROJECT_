# Claims Verification Table

| Possible claim | Evidence from code | Evidence file/function | Status | Safe wording | Unsafe wording |
|---|---|---|---|---|---|
| The module analyzes PCAP files. | Upload routes accept `.pcap/.pcapng` and run pipeline. | `Backend/app.py` `analyze_pcap`, `run_pcap_pipeline` | Verified | The module analyzes uploaded PCAP/PCAPNG files. | The module monitors live traffic in real time. |
| Analysis is asynchronous. | Jobs submitted to ThreadPoolExecutor; frontend polls status. | `jobs.py` `submit`; `PcapAnalyzerPage.tsx` polling | Verified | Analysis runs as a background job with polling. | It uses a distributed queue like Celery. |
| The module uses tshark. | `run_tshark_export` builds and runs tshark command. | `tshark_runner.py` | Verified | Packet fields are exported with tshark. | It works without tshark installed. |
| The module uses Zeek. | Optional Zeek runner and loader. | `zeek_runner.py`, `zeek_loader.py`, `run_pcap_pipeline` | Partially Verified | Optional Zeek enrichment is supported when enabled and available. | Zeek is always used successfully. |
| The module uses Suricata. | No inspected PCAP code confirms Suricata. | Search result/code inspection | Not Confirmed | Cannot confirm Suricata from code. | The system uses Suricata signatures. |
| The model is XGBoost. | Training script uses `xgb.XGBClassifier`. | `Backend/train_pcap65_model.py` | Verified for training script | The PCAP65 training script uses XGBoost. | The pickle was independently verified as XGBoost. |
| Runtime model predicts labels and confidence. | `predict_flows` calls `predict`, `predict_proba`. | `ml_infer.py` | Verified | Runtime inference returns `ml_label` and `ml_confidence`. | Confidence is calibrated probability. |
| Accuracy is 98.09%. | `metrics_pcap65.json` has accuracy `0.9808836341008089`. | `Backend/model/metrics_pcap65.json` | Verified | The metrics file reports accuracy of about 98.09%. | The deployed system is 98.09% accurate in production. |
| Macro-F1 is 90.64%. | metrics file has macro_f1 `0.9064385448656961`. | `metrics_pcap65.json` | Verified | The metrics file reports macro-F1 of about 90.64%. | The system has guaranteed high F1 on all captures. |
| Precision/recall are available. | Not in `metrics_pcap65.json`. | `metrics_pcap65.json` | Not Confirmed | Precision/recall were not found in inspected PCAP65 metrics. | Precision and recall are high. |
| Heuristics are used. | `apply_heuristics` adds PortScan/Beaconing/FocusedBurst. | `heuristics.py` | Verified | Heuristics provide supporting signals. | Heuristics alone detect all attacks. |
| Score fusion exists. | ML score 95%, heuristic 5%, support multiplier, verdict caps/floors. | `scorer.py` `fuse_scores` | Verified | Final per-flow scores fuse ML, heuristic, and context validation. | The score is a formal probability of compromise. |
| False positives are reduced. | Suppression, validation, confidence thresholds exist. | `security_logic.py`, `scorer.py` | Partially Verified | The code includes mechanisms intended to suppress weak/noisy detections. | The system eliminates false positives. |
| Reports include alerts/clusters/timeline/risk per IP. | `build_report` returns these top-level keys. | `reporter.py` | Verified | Reports include summary, alerts, clusters, timeline, and risk per IP. | Reports include packet payloads. |
| Alerts are stored in the database. | `PcapAlertRecord`, persistence functions. | `Backend/app.py` | Verified | PCAP alert records are persisted for users. | Every flow is stored as a database alert. |
| Raw artifacts are encrypted. | Encryption only if env enabled/key present. | `Backend/app.py` artifact protection functions | Partially Verified | Optional artifact encryption exists. | Raw PCAPs are always encrypted. |
| Users cannot access other users' jobs. | Ownership checks use user id and scope. | `_pcap_job_matches_context` | Verified | Job access is owner-scoped. | Access control is impossible to bypass. |
| Admins can monitor PCAP operations. | Admin overview endpoint/UI. | `admin_pcap_overview`, admin React component | Verified | Admins can view PCAP job/queue/report overview. | Admin console provides full SOC-grade monitoring. |
| Evidence ZIP export exists. | Builds zip from report/state/Zeek logs. | `_build_job_evidence_bundle` | Verified | Evidence ZIP is available when Zeek evidence files exist. | Evidence ZIP is always available. |
