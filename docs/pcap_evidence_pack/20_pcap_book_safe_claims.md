# PCAP Book-Safe Claims Final Filter

## A. Safe Claims

- Sentinel AI includes a PCAP analysis module for uploaded `.pcap` and `.pcapng` files.
- The module creates background jobs and exposes progress/status polling.
- Uploaded PCAPs are saved with generated UUID filenames rather than original user filenames.
- The backend enforces a 15 GB upload limit.
- The pipeline uses `tshark` to export selected packet fields to CSV.
- The pipeline extracts CIC-style bidirectional flow features.
- The runtime inference function loads a joblib model bundle and returns labels plus confidence values.
- The PCAP65 training script uses XGBoost.
- The code applies heuristic signals for port scan, beaconing, and focused burst patterns.
- The code applies context validation, support levels, suppression rules, and confidence modes before promoting alerts.
- Reports include `meta`, `summary`, `module_contract`, `risk_per_ip`, `clusters`, `alerts`, and `timeline`.
- Users can download report JSON for completed jobs.
- Users can download an evidence ZIP when evidence files are available.
- Users can cancel queued/running jobs.
- PCAP alert records are stored in the `pcap_alert` database table and linked to `user_id` and `job_id`.
- Admins can view a PCAP overview and export report/evidence artifacts.
- Optional Zeek enrichment is supported when enabled and available.
- Optional artifact encryption exists when configured.
- The PCAP65 metrics file reports accuracy `0.9808836341008089` and macro-F1 `0.9064385448656961`.

## B. Needs External Reference

- PCAP files are useful for network forensics.
- Flow-based intrusion detection reduces processing complexity compared with raw-packet inspection.
- Machine learning can help identify attack patterns in network traffic.
- IDS systems can suffer from false positives and false negatives.
- Zeek is commonly used for network security monitoring.
- tshark/Wireshark CLI can extract packet fields from capture files.
- XGBoost is a gradient-boosting method suitable for tabular classification.
- CIC-style features are common in intrusion-detection datasets.

## C. Unsafe Claims

- The system detects all attacks.
- The system works in real time.
- The system blocks attacks automatically.
- The system protects against all threats.
- The system is enterprise-grade.
- The model is highly accurate in production.
- Precision/recall/weighted-F1 are known for PCAP65.
- Suricata is used.
- Zeek is always used.
- Evidence ZIP is always available.
- Raw PCAP artifacts are always encrypted.
- The system stores no sensitive data.
- Reports contain no private information.
- The frontend Network Security Score is the same as the backend report `security_score`.
