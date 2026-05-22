# Questions for Project Owner

## Technical Confirmation

- Is `Backend/model/threat_model_pcap65.pkl` the final model used in the submitted project?
- Is `Backend/model/metrics_pcap65.json` the official metrics file to cite?
- Was `PCAP_PROTECT_ARTIFACTS` enabled in the final demo/deployment?
- Was local-path analysis (`/analyze-local`) used by the UI or only for backend/dev testing?
- Should the book mention the active-job reuse/deduplication feature?

## Screenshots Needed

- Which PCAP sample should be used for screenshots?
- Should screenshots use a benign capture, malicious capture, or both?
- Are IP addresses, DNS names, HTTP URIs, and paths in screenshots allowed, or should they be blurred/sanitized?
- Should admin screenshots be included in the main chapter or appendix?

## Model Metrics

- Can the reported accuracy `0.9808836341008089` and macro-F1 `0.9064385448656961` be included?
- Do you have precision, recall, weighted-F1, or full classification report for PCAP65?
- What exact test split or dataset produced `metrics_pcap65.json`?
- Were metrics measured before or after SMOTE?

## Dataset / Training

- Which datasets were used: `RT_IOT2022.csv`, `train_set_LYCOS.csv`, `test_set_LYCOS.csv`, `crossval_set_LYCOS.csv`, or others?
- Are dataset sources/citations available?
- Were any labels renamed or merged?
- Was data preprocessing documented outside code?

## External Tools Installed

- Was Wireshark/tshark installed natively on Windows for the final run?
- Was WSL installed and used?
- Was Zeek installed at `/usr/local/zeek/bin/zeek`?
- Was `editcap` available for large-file chunking?
- Was Suricata ever used manually outside this codebase? Code does not confirm it.

## Report Wording

- Should the book call `summary.security_score` a “security score” or “PCAP module score”?
- Should frontend-derived `NetworkSecurityScoreCard` be described separately from backend report score?
- Should Zeek be described as optional enrichment?
- Should evidence export be described as “available when Zeek evidence exists”?

## Limitations

- What limitations should be openly stated: file upload only, no live capture, external tool dependency, possible false positives, model trained on specific datasets?
- Are raw PCAP files retained after cleanup in the final environment?
- Are HTTP URI/DNS/SNI fields considered sensitive in project documentation?

## Future Work

- Should future work include live packet capture?
- Should future work include Suricata integration?
- Should future work include model retraining UI or dataset management?
- Should future work include stronger privacy redaction for exported reports?
