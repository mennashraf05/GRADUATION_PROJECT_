# PCAP Pipeline Evidence

## Pipeline Steps

| Step | Input | Processing logic | Output | Evidence | Limitations |
|---|---|---|---|---|---|
| Upload handling | Multipart file named `file` | Checks request size, requires filename, extension `.pcap`/`.pcapng`, saves UUID filename in `BASE_RUN_FOLDER` | Stored PCAP path | `Backend/app.py` `analyze_pcap` | File magic/header validation not confirmed |
| Local path handling | JSON `pcap_path` | Resolves path and requires it to be inside `LOCAL_PCAP_ALLOWED_ROOT` | Existing PCAP path | `Backend/app.py` `_resolve_analyze_local_path`, `analyze_local` | Local analysis is backend-side only; UI evidence not confirmed |
| Job creation | Upload/local path plus owner/options | Builds `analysis_key`; `create_or_reuse_active` either reuses queued/running matching job or creates new UUID job | `JobState`, `state.json` | `Backend/app.py` `_build_analysis_key`; `Backend/pcap_engine/jobs.py` | Reuse only active jobs, not completed reports |
| Background execution | Job ID and pipeline closure | `JobRegistry.submit` runs `fn()` in `ThreadPoolExecutor`, writes `report.json` on success | async job | `Backend/pcap_engine/jobs.py` `submit` | Not Celery/Redis; process-local executor |
| Polling/status | Job ID | Reads memory or disk state; inlines report when done | JSON status/report | `Backend/app.py` `get_job` | Poll interval recommended 600000 ms by backend; frontend initially polls faster |
| Packet extraction | PCAP file | `run_tshark_export` calls native Windows `tshark` or WSL fallback, exports selected fields to CSV | packet CSV | `Backend/pcap_engine/tshark_runner.py` | Requires `tshark`; WSL fallback requires Windows absolute path |
| Large-file handling | Large PCAP | If native `tshark` and `editcap` exist and file size crosses threshold, splits into chunks; retries memory-pressure chunks with smaller chunk sizes | combined CSV | `tshark_runner.py` | `editcap` optional; default chunk threshold 4 GB |
| Feature extraction | packet CSV | Aggregates bidirectional flows into CIC-like fields with duration, packet/byte counts, payload stats, IAT stats, TCP flags, active/idle stats | CIC dataframe | `Backend/pcap_engine/cic_stream_features.py` | Empty output raises `No flows extracted` in pipeline |
| ML contract validation | CIC dataframe | Checks required features against `EXPECTED_CIC65` and model trained columns | validation pass/fail | `Backend/app.py` `_validate_cic_ml_contract` and `EXPECTED_CIC65` | Metrics file notes missing required cols in training file; runtime generated fields are validated |
| ML prediction | CIC dataframe | Loads joblib bundle `(model, label_encoder, proto_encoder, service_encoder, trained_columns)`, aligns columns, encodes categoricals, predicts labels and probabilities | dataframe with `ml_label`, `ml_confidence` | `Backend/pcap_engine/ml_infer.py` | Model type confirmed by training script, not by pickle inspection |
| Flow context features | ML-enriched flows | Adds time bucket, bytes totals, short/long flags, failed indicators, source/target counts, fanout, failed/short ratios | dataframe | `Backend/pcap_engine/flow_features.py` | Window defaults to 60 seconds |
| Heuristic analysis | Context dataframe | Applies PortScan, Beaconing, FocusedBurst heuristic scores/reasons | `heuristic_score/type/reason` | `Backend/pcap_engine/heuristics.py` | Heuristics are supporting hints only |
| Optional Zeek run | PCAP path | If `include_zeek`, starts Zeek in parallel through WSL command | Zeek run folder/logs | `Backend/app.py` `run_pcap_pipeline`; `Backend/pcap_engine/zeek_runner.py` | Fails open to base-only if load fails; Zeek path hardcoded |
| Zeek evidence loading | Zeek log folder | Loads `conn.log`, `dns.log`, `http.log`, `ssl.log` JSON lines | pandas dataframes | `Backend/pcap_engine/zeek_loader.py` | Only these four log types loaded by loader |
| ARP evidence | packet CSV | Pipeline calls `summarize_arp_evidence(packet_csv)` and merges if non-empty | ARP summary evidence | `Backend/app.py` `run_pcap_pipeline` | Function is in `app.py`; exact fields depend on implementation |
| Score fusion | Base/enriched dataframe | `fuse_scores` computes severity, confidence tier, validation, support level, verdict, final_score; ML 95%, heuristic 5%, support multiplier, verdict caps/floors | final scored dataframe | `Backend/pcap_engine/scorer.py` | Final score is per-flow risk-like confidence, not model accuracy |
| Alert generation | final dataframe | `build_report` filters non-suppressed Medium/High/Critical rows, deduplicates, builds alert objects | `alerts` list | `Backend/pcap_engine/reporter.py` | Low/Normal/suppressed rows do not become alerts |
| Clusters | final dataframe | Groups by `src_ip`, `dst_ip`, `ml_label`; keeps Medium/High/Critical non-suppressed rows | `clusters` list | `reporter.py` `cluster_alerts` | Max clusters defaults to 100 unless set |
| Risk per IP | alerts/clusters | Computes combined risk per IP from signals | `risk_per_ip` list | `reporter.py` `_build_risk_per_ip` | Uses alerts/clusters only |
| Report generation | final dataframe and pipeline meta | Builds `meta`, `summary`, `module_contract`, `risk_per_ip`, `clusters`, `alerts`, `timeline` | report dict then `report.json` | `reporter.py` `build_report`; `jobs.py` `submit` | Report contains paths; do not expose sensitive paths in book examples |
| Alert persistence | completed job report | Builds summary/detail alert records for `PcapAlertRecord` | DB records | `Backend/app.py` `_persist_pcap_alert_records` | Only for jobs with owner user ID |
| Export/download | completed job | Sends `report.json` or builds ZIP with report/state/Zeek logs | JSON/ZIP download | `Backend/app.py` `export_job_artifact`, `_build_job_evidence_bundle` | Evidence ZIP unavailable without Zeek files |
| Cancellation | queued/running job | Marks cancelled and terminates active subprocesses best effort | cancelled state | `Backend/app.py` `cancel_pcap_job`; `jobs.py` `request_cancel` | Cannot guarantee external process killed instantly |
| Cleanup | base run folder/jobs folder | Background scheduler deletes stale artifacts/job folders after retention periods | deleted stale files/folders | `Backend/pcap_engine/cleanup.py` | Terminal statuses in cleanup are `done` and `error`; `cancelled` handling in cleanup not confirmed |

## Confirmed Tools

- `tshark`: confirmed in `tshark_runner.py`.
- `editcap`: confirmed as optional chunking helper in `tshark_runner.py`.
- Zeek: confirmed optional enrichment through `zeek_runner.py`.
- Suricata: cannot confirm from code.
