# Backend PCAP Evidence

## Backend Files

| File | Important functions/classes | Purpose | Related endpoints | What it proves |
|---|---|---|---|---|
| `Backend/app.py` | `analyze_pcap`, `analyze_local`, `run_pcap_pipeline`, `get_job`, `list_jobs`, `cancel_pcap_job`, `export_job_artifact`, `list_pcap_alerts`, `dismiss_visible_pcap_alerts`, `admin_pcap_overview`, `admin_export_pcap_job_artifact`, `PcapAlertRecord` | Flask routes, auth/ownership, pipeline orchestration, DB alert persistence, admin monitoring/export | All PCAP routes | PCAP module is implemented end-to-end in backend |
| `Backend/pcap_engine/jobs.py` | `JobState`, `JobRegistry`, `create_or_reuse_active`, `submit`, `request_cancel`, `list_recent` | In-memory job registry plus `state.json` persistence | Used by `/analyze-pcap`, `/job/<id>`, `/jobs`, cancel/export/admin | Analysis runs as background jobs persisted under `_jobs` |
| `Backend/pcap_engine/tshark_runner.py` | `run_tshark_export`, `TsharkExportError`, `_find_tshark_windows`, `_run_chunked_export` | Exports packet fields from PCAP to CSV using `tshark`; can split large captures with `editcap` | Pipeline step | `tshark` is confirmed; `editcap` used for chunk fallback |
| `Backend/pcap_engine/cic_stream_features.py` | `build_cic_features_from_tshark_csv`, `FlowAgg`, `BidirectionalFlow`, `RunningStats` | Converts packet CSV to CIC-like bidirectional flow features | Pipeline step | Feature extraction from packet rows is implemented |
| `Backend/pcap_engine/ml_infer.py` | `load_model_bundle`, `prepare_inference_frame`, `predict_flows`, `FeatureSchemaError` | Loads joblib bundle and runs ML predictions/confidence | Pipeline step | ML inference uses saved bundle with model, encoders, columns |
| `Backend/pcap_engine/flow_features.py` | `build_flow_context_features`, `build_flow_features` | Adds context features such as connection counts, fanout, failed ratios | Pipeline step | Context validation features exist |
| `Backend/pcap_engine/heuristics.py` | `apply_heuristics` | Adds heuristic score/type/reason for PortScan, Beaconing, FocusedBurst | Pipeline step | Heuristic analysis exists |
| `Backend/pcap_engine/security_logic.py` | `label_to_severity`, `confidence_tier`, `validation_fail_reason`, `should_suppress`, `context_support_level`, `verdict_from_context`, `build_reason` | Maps ML labels to severities, suppresses weak/noisy signals, validates context | Used by `scorer.py` | False-positive reduction and severity logic are code-supported |
| `Backend/pcap_engine/scorer.py` | `fuse_scores` | Combines ML score and heuristic score, applies support multiplier, caps/floors by verdict | Pipeline step | Score fusion is implemented |
| `Backend/pcap_engine/reporter.py` | `build_report`, `cluster_alerts`, `_build_risk_per_ip`, `_build_security_findings` | Builds JSON report structure | `/job/<id>`, export endpoints | Report schema and dashboard metrics are generated |
| `Backend/pcap_engine/zeek_runner.py` | `prepare_zeek_run_folder`, `run_zeek` | Runs Zeek through WSL, using `/usr/local/zeek/bin/zeek` | Optional pipeline enrichment | Zeek usage is confirmed but environment-dependent |
| `Backend/pcap_engine/zeek_loader.py` | `load_conn`, `load_dns`, `load_http`, `load_ssl` | Loads Zeek JSON logs | Optional pipeline enrichment | Zeek evidence fields are loaded |
| `Backend/pcap_engine/cleanup.py` | `start_cleanup_scheduler`, `run_cleanup_pass`, `clean_stale_artifacts`, `clean_stale_job_folders` | Deletes stale artifacts/jobs while protecting active jobs | App startup | Cleanup behavior exists |
| `Backend/train_pcap65_model.py` | `main` | Training script for PCAP65 XGBoost model bundle and metrics | Not runtime endpoint | Confirms model type and bundle contents |
| `Backend/model/metrics_pcap65.json` | JSON metrics | Final-looking PCAP65 metrics file | Admin governance/model version | Metrics exist; safe values only from file |
| `Backend/tests/test_pcap_*` | regression tests | Tests route contracts, scoring, artifact protection, alert persistence | Test-only | Tests exist, but do not prove production deployment |

## Endpoint Evidence

| Method | Route | Access | Input | Output | Main function | Evidence | Notes |
|---|---|---|---|---|---|---|---|
| POST | `/pcap/analyze`, `/analyze-pcap` | Authenticated user context required | `multipart/form-data` file; optional `include_zeek`, `confidence_mode`, `max_alerts`, `max_clusters` | `202` with `job_id`, `status`, `poll`; may include `reused` | `analyze_pcap` | `Backend/app.py` | Validates `.pcap/.pcapng`, 15 GB max |
| POST | `/pcap/analyze-local`, `/analyze-local` | Authenticated user context required | JSON `pcap_path`; optional `include_zeek`, `confidence_mode`, `max_alerts`, `max_clusters` | `202` with job fields | `analyze_local` | `Backend/app.py` | Path restricted to `LOCAL_PCAP_ALLOWED_ROOT` |
| GET | `/job/<job_id>`, `/pcap/status/<job_id>`, `/pcap/result/<job_id>` | Job owner only | Path `job_id` | Job status, progress, report inline when done | `get_job` | `Backend/app.py` | Adds `Retry-After` for queued/running |
| GET | `/jobs`, `/pcap/jobs` | Owner only | Query `limit` | `{jobs, count}` | `list_jobs` | `Backend/app.py` | Filters with `_pcap_job_matches_context` |
| POST | `/api/pcap/cancel/<job_id>`, `/pcap/cancel/<job_id>` | Job owner only | Path `job_id` | `ok`, `status`, `message`, `process_terminated` | `cancel_pcap_job` | `Backend/app.py` | Best-effort subprocess termination |
| GET | `/pcap/report/<job_id>`, `/job/<job_id>/export?type=report|evidence` | Job owner only | Path `job_id`, query `type` for `/job/.../export` | JSON file or ZIP | `export_job_artifact` | `Backend/app.py` | Evidence ZIP requires Zeek files |
| GET | `/api/pcap/alerts`, `/pcap/alerts` | Authenticated user | Query `limit`, `include_dismissed` | PCAP alert feed | `list_pcap_alerts` | `Backend/app.py` | Backfills alerts from completed jobs |
| POST | `/api/pcap/alerts/clear`, `/api/pcap/alerts/dismiss-visible`, `/pcap/alerts/clear`, `/pcap/alerts/dismiss-visible` | Authenticated user | JSON `alert_ids` or `dismiss_all_visible` | dismissal counts | `dismiss_visible_pcap_alerts` | `Backend/app.py` | Ownership scoped |
| GET | `/api/admin/pcap/overview` | Admin only | Query `limit` | Admin summary/jobs/engine/timeline payload | `admin_pcap_overview` | `Backend/app.py` | Reads all jobs, not user-scoped |
| GET | `/api/admin/pcap/jobs/<job_id>/export?type=report|evidence` | Admin only | Path `job_id`, query `type` | JSON file or ZIP | `admin_export_pcap_job_artifact` | `Backend/app.py` | Logs admin export action |

## Limitations

- Backend route code does not confirm Suricata.
- Zeek success depends on WSL and Zeek path.
- `tshark` must be installed or available through WSL.
- Some report/admin values are derived from job/report metadata, not separate DB tables.
