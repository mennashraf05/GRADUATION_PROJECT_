# PCAP Deep Reference

This document is a maintenance reference for the current PCAP analysis and detection subsystem as implemented in the backend codebase on March 17, 2026. It is intentionally grounded in the current code paths, data contracts, logs, and frontend consumer behavior. It is not a redesign proposal.

## 1. Purpose of the PCAP subsystem

### What this subsystem does

The PCAP subsystem ingests a packet capture, converts it into flow-level features, applies an ML model plus context-aware security logic, optionally enriches the flows with Zeek-derived evidence, and produces a JSON report plus optional exportable evidence artifacts.

At a high level it answers:

- What flows were present in the capture?
- What did the model think those flows were?
- Which flows should actually be surfaced as alerts after validation, suppression, and context checks?
- Did Zeek evidence strengthen or weaken those decisions?
- What report can the frontend render and what artifacts can operators export?

### What inputs it accepts

There are two request entry modes for analysis:

1. Uploaded file mode:
   - Route: `/pcap/analyze` or `/analyze-pcap`
   - Request: multipart form-data
   - Required:
     - `file` with extension `.pcap` or `.pcapng`
   - Optional:
     - `include_zeek`
     - `max_alerts`
     - `max_clusters`

2. Local file mode:
   - Route: `/pcap/analyze-local` or `/analyze-local`
   - Request: JSON body
   - Required:
     - `pcap_path`
   - Optional:
     - `include_zeek`
     - `max_alerts`
     - `max_clusters`

Local file mode is restricted to `ANALYZE_LOCAL_ALLOWED_ROOT`. It does not allow arbitrary filesystem traversal.

### What outputs it produces

The subsystem produces:

- A background job record tracked by `JobRegistry`
- A job state JSON file persisted under `Backend/pcap_runs/_jobs/<job_id>/state.json`
- A report JSON file under `Backend/pcap_runs/_jobs/<job_id>/report.json`
- Optional Zeek evidence directory containing `conn.log`, `dns.log`, `http.log`, `ssl.log`
- Optional evidence bundle ZIP containing:
  - `report.json`
  - `state.json`
  - `zeek/conn.log`
  - `zeek/dns.log`
  - `zeek/http.log`
  - `zeek/ssl.log`

The main API-facing JSON outputs are:

- `202 Accepted` job creation or reuse response
- `GET /job/<job_id>` status payload, optionally with inline report when complete
- `GET /job/<job_id>/export?type=report`
- `GET /job/<job_id>/export?type=evidence`

### Main operating modes

#### No-Zeek mode

Pipeline:

`tshark -> CIC features -> ML inference -> base context features -> heuristics -> fuse_scores -> comparison/report`

Behavior:

- No Zeek process is launched
- No conn/dns/http/ssl evidence is merged
- Final scoring log stage is `final_no_zeek`
- `pipeline_meta.analysis_mode` becomes `base_only`

#### Zeek-enriched mode

Pipeline:

`tshark + parallel Zeek -> CIC features -> ML inference -> base context features -> heuristics -> load Zeek evidence -> merge evidence -> fuse_scores -> comparison -> report`

Behavior:

- Zeek runs in parallel while tshark export and CIC extraction proceed
- Evidence is loaded from Zeek JSON logs and merged back onto the flow frame
- The system computes both:
  - `base_scored`
  - `final_df` after evidence
- It logs:
  - `base_pre_evidence`
  - evidence merge coverage lines
  - `Detection comparison`
  - `post_evidence`
- `pipeline_meta.analysis_mode` becomes `enriched` only if evidence was actually applied to at least one final row

### Typical job lifecycle from upload to exported report

1. Request reaches `/analyze-pcap` or `/analyze-local`.
2. Auth context is resolved to either:
   - authenticated user ownership, or
   - localhost fallback client ownership for local development PCAP routes.
3. The request is normalized into an `analysis_key`.
4. `JobRegistry.create_or_reuse_active()` either:
   - returns an existing equivalent active job, or
   - creates a new queued job.
5. `jobs.submit()` transitions the job to `running` and starts the pipeline in a background worker.
6. The pipeline writes progress and artifact paths into job state as it advances.
7. On success:
   - `report.json` is written
   - job status becomes `done`
8. On failure:
   - traceback is stored in job state
   - job status becomes `error`
9. Frontend polls `GET /job/<job_id>` until completion.
10. Report or evidence can be exported once the job is `done`.
11. Cleanup later removes stale artifacts while protecting active jobs.

## 2. End-to-end pipeline overview

This section follows the actual execution chain implemented in the backend.

### Stage 1: Request entry

#### Uploaded analysis entry

- Route: `/pcap/analyze` or `/analyze-pcap`
- Input:
  - multipart `file`
  - optional `include_zeek`, `max_alerts`, `max_clusters`
- Processing:
  - reject oversized request by `MAX_FILE_SIZE`
  - resolve PCAP request context
  - validate extension `.pcap` or `.pcapng`
  - measure upload size
  - save file under `BASE_RUN_FOLDER` with a UUID filename
  - compute `analysis_key` using:
    - file sample fingerprint
    - owner scope
    - `include_zeek`
    - `max_alerts`
    - `max_clusters`
  - deduplicate via `jobs.create_or_reuse_active()`
- Output:
  - `202` with new or reused `job_id`
- Failure cases:
  - `400`: invalid file type, no file
  - `401`: unauthorized non-local request
  - `413`: file too large
  - `500`: unexpected exception
- Helpful logs:
  - `Reusing active PCAP job | route=/analyze-pcap | job_id=... | status=...`
  - `PCAP auth fallback enabled for localhost | route=/analyze-pcap | reason=...`

#### Local analysis entry

- Route: `/pcap/analyze-local` or `/analyze-local`
- Input:
  - JSON with `pcap_path`
  - optional `include_zeek`, `max_alerts`, `max_clusters`
- Processing:
  - resolve auth context
  - validate that `pcap_path` is under `ANALYZE_LOCAL_ALLOWED_ROOT`
  - compute `analysis_key` using:
    - resolved local path
    - file size
    - file `mtime_ns`
    - owner scope
    - options
  - deduplicate via `jobs.create_or_reuse_active()`
- Output:
  - `202` with new or reused `job_id`
- Failure cases:
  - `400`: missing `pcap_path`, file missing, invalid path
  - `403`: path outside allowed root
  - `401`: unauthorized non-local request
  - `500`: unexpected exception

### Stage 2: Job creation and tracking

- Code owner:
  - `Backend/pcap_engine/jobs.py`
- Input:
  - `upload_path`
  - owner IDs
  - `analysis_key`
- Processing:
  - create `JobState`
  - persist `state.json`
  - background `submit()` flips job to `running`
  - pipeline updates state using `jobs.update(...)`
- Output:
  - in-memory and persisted job state
- Failure cases:
  - state file load/write issues
  - callback exceptions
- Helpful logs:
  - no dedicated creation log, but route reuse log and downstream progress logs confirm state movement

Job lifecycle states in backend:

- `queued`
- `running`
- `done`
- `error`

The frontend normalizes `error` to `failed` for display, but backend persistence uses `error`.

### Stage 3: tshark packet export

- Code owner:
  - `Backend/pcap_engine/tshark_runner.py`
- Input:
  - original PCAP path
  - output CSV path under `BASE_RUN_FOLDER`
- Processing:
  - prefer native Windows `tshark.exe`
  - fallback to `wsl tshark` if native binary is unavailable
  - export packet-level fields expected by CIC aggregation
  - write CSV directly to disk
- Output:
  - packet CSV
- Exported columns:
  - `frame.time_epoch`
  - `ip.src`
  - `ip.dst`
  - `ipv6.src`
  - `ipv6.dst`
  - `tcp.srcport`
  - `tcp.dstport`
  - `udp.srcport`
  - `udp.dstport`
  - `ip.proto`
  - `frame.len`
  - `tcp.flags`
- Failure cases:
  - PCAP file missing
  - tshark not found
  - timeout
  - memory pressure
  - non-zero exit code
  - partial CSV cleanup failure
- Helpful logs:
  - `Starting tshark export | mode=native-windows | pcap=... | pcap_size=... | out_csv=... | tshark=... | timeout_s=...`
  - `tshark export completed | mode=native-windows | pcap=... | out_csv=... | elapsed_s=... | output_size=...`
  - `Packet export ready | packet_csv=...`

Success pattern from current logs:

```text
Starting tshark export | mode=native-windows | pcap_size=71.83 MB ...
tshark export completed | mode=native-windows | elapsed_s=2.33 | output_size=5.10 MB
Packet export ready | packet_csv=...
```

For very large captures the same stage can take several minutes and produce hundreds of MB of CSV.

### Stage 4: CIC feature extraction

- Code owner:
  - `Backend/pcap_engine/cic_stream_features.py`
- Input:
  - packet CSV from tshark
- Processing:
  - parse each packet row
  - choose IPv4 or IPv6 addresses
  - choose TCP or UDP ports
  - canonicalize bidirectional flow pair
  - keep the first observed direction as forward
  - accumulate packet counts, byte counts, IAT stats, active/idle stats, flag counts
  - emit a CIC-like flow frame with fixed expected columns
- Output:
  - flow-level DataFrame with the `EXPECTED_CIC65` schema
  - DataFrame attrs:
    - `parse_errors`
    - `parsed_rows`
    - `rows_seen`
- Failure cases:
  - parser error rate so high that no rows survive
  - emitted schema missing or extra columns relative to `EXPECTED_CIC65`
  - empty DataFrame
- Helpful logs:
  - row-level parse warnings for up to 5 bad rows
  - `CIC feature extraction | flow_count=... | parse_errors=... | missing=[] | extra=[]`

Important nuance:

- The `*payload*` fields currently use tshark `frame.len`, not pure layer-4 payload length. This is explicitly called out in the CIC extractor code comment and matters if someone tries to compare these features to a textbook CICFlowMeter implementation.

### Stage 5: ML inference

- Code owner:
  - `Backend/app.py::run_ml_inference`
  - `Backend/pcap_engine/ml_infer.py`
- Input:
  - CIC feature DataFrame
  - trained model bundle at `MODEL_PATH`
- Processing:
  - load bundle `(model, label_encoder, proto_encoder, service_encoder, trained_columns)`
  - align inference frame to `trained_columns`
  - only `ip_prot` and `service` may be safely auto-filled with `unknown`
  - encode categoricals
  - coerce all non-categorical trained columns to numeric
  - predict labels and probabilities
  - attach `ml_label` and `ml_confidence` back to the original flow rows
- Output:
  - original flow frame plus:
    - `ml_label`
    - `ml_confidence`
- Failure cases:
  - missing model bundle
  - invalid bundle format
  - dangerous missing required features
  - mismatch between prediction row count and input row count
- Helpful logs:
  - `Inference schema check | missing=[] | safe_missing=[] | unexpected=['src_ip', 'dst_ip', 'ts'] | order_mismatch=False`
  - `Inference label distribution | {...}`
  - `ML inference completed | flow_count=... | labels={...}`

Important nuance:

- `unexpected=['src_ip', 'dst_ip', 'ts']` is normal. Those are metadata columns retained for traceability but not part of the trained model feature matrix.

### Stage 6: Base context feature building

- Code owner:
  - `Backend/app.py::build_base_detection_frame`
  - `Backend/pcap_engine/flow_features.py`
  - `Backend/pcap_engine/heuristics.py`
- Input:
  - CIC flow frame with `ml_label` and `ml_confidence`
- Processing:
  - normalize ports
  - derive per-source and per-target context in `build_flow_context_features()`
  - ensure all `BASE_FLOW_CONTEXT_COLS` exist
  - apply heuristics
  - attach flow merge keys
- Output:
  - base detection frame with:
    - ML columns
    - context columns
    - heuristic columns
    - merge keys
- Failure cases:
  - missing key fields used in flow context derivation
  - unsafe future edits that change naming or semantics of context columns

### Stage 7: Optional Zeek background run

- Code owner:
  - `Backend/pcap_engine/zeek_runner.py`
  - orchestration in `Backend/app.py::run_pcap_pipeline`
- Input:
  - original PCAP path
- Processing:
  - create a unique Zeek run directory under `BASE_RUN_FOLDER`
  - run Zeek under WSL with JSON log output enabled
  - keep Zeek in parallel with tshark/CIC/ML stages
  - timeout scales roughly with file size:
    - min 5 minutes
    - max 1 hour
    - approximately 2 seconds per MB
- Output:
  - Zeek run directory
  - JSON logs such as `conn.log`, `dns.log`, `http.log`, `ssl.log`
- Failure cases:
  - invalid non-Windows path
  - Zeek missing in WSL path
  - non-zero Zeek exit
  - timeout
- Helpful logs:
  - `Starting Zeek run | pcap=... | run_folder=...`
  - `Zeek run completed | run_folder=... | log_files=...`
  - `Zeek background task completed | job_id=... | run_folder=...`

### Stage 8: Zeek evidence loading and summarization

- Code owner:
  - `Backend/pcap_engine/zeek_loader.py`
  - `Backend/app.py::load_zeek_evidence`
- Input:
  - Zeek run directory
- Processing:
  - load JSON lines logs into DataFrames
  - ensure required columns exist per log type
  - build conn context features
  - assign `time_bucket`
  - derive direct and pair merge keys
  - summarize DNS, HTTP, and SSL into per-flow-per-bucket evidence rows
- Output:
  - `conn_df`
  - `dns_ev`
  - `http_ev`
  - `ssl_ev`
- Failure cases:
  - missing or malformed Zeek logs
  - empty evidence frames
  - evidence load exception after Zeek succeeded
- Helpful logs:
  - `Zeek evidence loaded | conn=... | dns=... | http=... | ssl=...`

### Stage 9: Score fusion and verdict generation

- Code owner:
  - `Backend/pcap_engine/scorer.py`
  - `Backend/pcap_engine/security_logic.py`
- Input:
  - no-Zeek mode:
    - base detection frame
  - Zeek mode:
    - base detection frame enriched with conn/dns/http/ssl evidence
- Processing:
  - apply suppression checks
  - map label to severity
  - compute base ML score
  - derive confidence tier
  - run validation checks
  - derive context support level
  - derive signal verdict
  - derive final verdict
  - compute support promotion/demotion flags
  - blend ML score and heuristic score
  - multiply by support multiplier
  - cap by verdict
  - floor by verdict for non-Normal
  - set Normal final score to zero
  - build human-readable reason
- Output:
  - scored DataFrame with:
    - `severity`
    - `ml_score`
    - `confidence_tier`
    - `validation_failed`
    - `validation_reason`
    - `support_level`
    - `support_multiplier`
    - `signal_verdict`
    - `verdict`
    - `support_promoted`
    - `support_demoted`
    - `final_score`
    - `confidence`
    - `reason`
- Failure cases:
  - canonical scoring API drift between `security_logic.py` and `scorer.py`
  - broken assumptions about context/evidence field names
- Helpful logs:
  - `Detection scoring | stage=base_pre_evidence ...`
  - `Detection scoring | stage=post_evidence ...`
  - `Detection scoring | stage=final_no_zeek ...`

### Stage 10: Comparison between base and enriched outputs

- Code owner:
  - `Backend/app.py::build_detection_comparison_summary`
- Input:
  - `base_scored`
  - final enriched frame after evidence and rescoring
- Processing:
  - build a deterministic comparison key from flow identity plus stable sort fields
  - compare verdicts for matching rows
  - summarize alert-level changes and row-set drift
- Output:
  - comparison summary containing:
    - `compared_rows`
    - `changed_by_evidence_up`
    - `changed_by_evidence_down`
    - `base_only_rows`
    - `enriched_only_rows`
    - plus embedded base/enriched alert summaries
- Helpful logs:
  - `Detection comparison | job_id=... | summary={...}`

### Stage 11: Report generation

- Code owner:
  - `Backend/pcap_engine/reporter.py`
- Input:
  - final scored frame
  - `pcap_path`
  - `max_alerts`
  - `max_clusters`
  - `pipeline_meta`
- Processing:
  - build `timeline` from all rows
  - build `alerts` from non-suppressed Medium/High/Critical rows
  - build `clusters` from grouped alert rows
  - compute summary risk metrics
  - sanitize floats and ints for JSON safety
- Output:
  - report dict with:
    - `meta`
    - `summary`
    - `clusters`
    - `alerts`
    - `timeline`
- Failure cases:
  - unsafe report contract changes that break frontend normalizers
  - NaN or inf leakage if sanitizer behavior is bypassed

### Stage 12: Job status and export endpoints

- Status:
  - `GET /job/<job_id>`
  - returns metadata and, when done, inlines report JSON
- History:
  - `GET /jobs`
  - returns filtered job list for current owner
- Exports:
  - `GET /job/<job_id>/export?type=report`
  - `GET /job/<job_id>/export?type=evidence`
  - `GET /job/<job_id>/export?type=bundle`
  - `GET /pcap/report/<job_id>` shorthand for report export

Failure cases:

- `404` job not found
- `403` job ownership mismatch
- `409` export requested before job completion
- `404` report or evidence artifact missing

Helpful runtime behavior:

- `GET /job/<job_id>` is intentionally lightweight
- active jobs return:
  - `poll_after_ms`
  - `Retry-After`
- polling does not recompute the pipeline

## 3. File-by-file responsibility map

### `Backend/app.py`

Purpose:

- Main orchestration file for the Flask backend.
- Contains the PCAP request routes, PCAP pipeline, comparison logic, evidence merge logic, report/export glue, polling safeguards, localhost fallback auth handling, and cleanup bootstrap.

Important PCAP functions:

- `_resolve_analyze_local_path`
- `_measure_upload_size`
- `_build_file_sample_fingerprint`
- `_build_local_analysis_source_key`
- `_build_analysis_key`
- `_reuse_existing_analysis_job`
- `run_ml_inference`
- `build_base_detection_frame`
- `_stable_comparison_frame`
- `build_detection_comparison_summary`
- `_log_scoring_summary`
- `load_zeek_evidence`
- `_summary_fallback_guard`
- `_merge_frame_with_fallback`
- `merge_conn_evidence`
- `merge_summary_evidence`
- `fill_evidence_defaults`
- `cleanup_numeric_columns`
- `run_pcap_pipeline`
- `_collect_job_export_artifacts`
- `_build_job_evidence_bundle`
- `_job_history_item`
- `analyze_pcap`
- `list_jobs`
- `get_job`
- `export_job_artifact`
- `analyze_local`
- `_resolve_pcap_request_context`

Who calls it:

- Flask routes call the request-entry functions.
- `jobs.submit()` calls `run_pcap_pipeline()`.
- `run_pcap_pipeline()` calls the lower-level `pcap_engine` modules.

Expected data:

- CIC flow frames with `EXPECTED_CIC65`
- evidence frames shaped like summarized conn/dns/http/ssl rows
- job state objects from `JobRegistry`

Returns:

- API responses
- report dicts
- merged/scored DataFrames

What can break if changed carelessly:

- route contracts used by the frontend
- evidence merge keys
- comparison determinism
- pipeline meta fields
- job ownership semantics
- dedup behavior
- cleanup protections

### `Backend/pcap_engine/tshark_runner.py`

Purpose:

- Export packet-level rows from PCAP into a flat CSV suitable for CIC-style aggregation.

Main public function:

- `run_tshark_export(pcap_path, out_csv_path)`

Who calls it:

- `run_pcap_pipeline()`

Expected data:

- existing PCAP file path

Returns:

- CSV path string

High-risk changes:

- changing `TSHARK_FIELD_ARGS` without updating CIC extraction
- changing timeout or fallback behavior without understanding large-PCAP runtime impact

### `Backend/pcap_engine/cic_stream_features.py`

Purpose:

- Convert packet CSV rows into a fixed CIC-like flow schema.

Main public function:

- `build_cic_features_from_tshark_csv(csv_path)`

Who calls it:

- `run_pcap_pipeline()`

Expected data:

- packet CSV columns in the exact tshark export order

Returns:

- DataFrame with `EXPECTED_CIC65`

High-risk changes:

- changing flow key semantics
- changing forward/backward direction semantics
- renaming or deleting expected CIC columns

### `Backend/pcap_engine/ml_infer.py`

Purpose:

- Load model bundle, align inference schema, encode categoricals, and predict per-flow labels/confidences.

Main public functions:

- `load_model_bundle`
- `prepare_inference_frame`
- `predict_flows`
- `encode_categorical_series`
- `FeatureSchemaError`

Who calls it:

- `run_ml_inference()`
- training and test routes also reuse parts of it

Expected data:

- DataFrame containing model-trained columns plus metadata columns

Returns:

- `predict_flows()` returns a DataFrame containing:
  - `src_ip`
  - `dst_ip`
  - `src_port`
  - `dst_port`
  - `ts`
  - `ml_label`
  - `ml_confidence`

High-risk changes:

- changing safe categorical defaults
- silently allowing more missing features
- altering bundle tuple format

### `Backend/pcap_engine/flow_features.py`

Purpose:

- Derive contextual traffic statistics over time buckets for scoring and heuristics.

Main public functions:

- `build_flow_context_features`
- `build_flow_features` compatibility wrapper

Who calls it:

- `build_base_detection_frame()`
- `load_zeek_evidence()` for conn evidence

Expected data:

- rows with timestamp, bytes, ports, endpoints, and optionally conn_state or flag counts

Returns:

- same DataFrame plus context columns such as `src_conn_count`, `src_unique_ports`, `is_failed`, `src_dst_conn_share`

High-risk changes:

- changing bucket semantics
- changing `is_failed` approximation rules
- renaming context columns consumed by heuristics and security logic

### `Backend/pcap_engine/heuristics.py`

Purpose:

- Add conservative heuristic signals that support scoring but do not replace ML classification.

Main public function:

- `apply_heuristics(df)`

Who calls it:

- `build_base_detection_frame()`

Expected data:

- DataFrame containing context columns

Returns:

- same DataFrame plus:
  - `heuristic_score`
  - `heuristic_type`
  - `heuristic_reason`

High-risk changes:

- increasing heuristic aggressiveness can destabilize validation and evidence support logic

### `Backend/pcap_engine/security_logic.py`

Purpose:

- Canonical home for severity mapping, suppression rules, validation rules, support rules, verdict logic, caps/floors, and human-readable explanation generation.

Main public functions:

- `label_to_severity`
- `severity_to_score`
- `severity_to_risk`
- `confidence_tier`
- `verdict_rank`
- `base_verdict_from_signal`
- `validation_fail_reason`
- `should_suppress`
- `context_support_level`
- `support_level_to_multiplier`
- `verdict_score_cap`
- `verdict_score_floor`
- `verdict_from_context`
- `build_reason`

Who calls it:

- `pcap_engine/scorer.py`

Expected data:

- row-like mapping with ML fields, context fields, heuristic fields, and optionally Zeek evidence fields

Returns:

- scalar values driving final scoring and reasons

High-risk changes:

- this file defines the actual detection semantics
- any careless change affects verdict inflation/demotion, suppression rates, risk levels, and explanation text

### `Backend/pcap_engine/scorer.py`

Purpose:

- Fuse ML output, heuristics, validation, support, and verdict logic into the final scored flow frame.

Main public function:

- `fuse_scores(df)`

Who calls it:

- `run_pcap_pipeline()`

Expected data:

- DataFrame with:
  - `ml_label`
  - `ml_confidence`
  - `src_ip`
  - `dst_ip`
  - `dst_port`
  - heuristic/context/evidence columns as available

Returns:

- DataFrame with final scoring, verdict, reason, and confidence fields

High-risk changes:

- raw score formula
- cap/floor ordering
- suppression/validation precedence
- final `confidence` meaning

### `Backend/pcap_engine/zeek_runner.py`

Purpose:

- Launch Zeek under WSL and store JSON logs in a per-run folder.

Main public functions:

- `prepare_zeek_run_folder`
- `run_zeek`

Who calls it:

- `run_pcap_pipeline()` in a background future

Expected data:

- Windows absolute paths

Returns:

- run folder path

High-risk changes:

- path conversion
- Zeek command line
- timeout policy

### `Backend/pcap_engine/zeek_loader.py`

Purpose:

- Load JSON Zeek logs into DataFrames with guaranteed required columns.

Main public functions:

- `load_conn`
- `load_dns`
- `load_http`
- `load_ssl`

Who calls it:

- `load_zeek_evidence()`

Expected data:

- Zeek log files in JSON-per-line format

Returns:

- DataFrames, empty if logs are missing or empty

High-risk changes:

- required column names
- log filename expectations

### `Backend/pcap_engine/reporter.py`

Purpose:

- Convert the final scored DataFrame into the report JSON shape consumed by the PCAP frontend.

Main public functions:

- `cluster_alerts`
- `build_report`

Who calls it:

- `run_pcap_pipeline()`

Expected data:

- fully scored DataFrame, preferably after evidence defaults and numeric cleanup

Returns:

- report dict containing `meta`, `summary`, `clusters`, `alerts`, `timeline`

High-risk changes:

- field names consumed by `PcapAnalyzerPage.tsx`
- JSON-safe sanitization
- alert filtering and dedup semantics

### `Backend/pcap_engine/jobs.py`

Purpose:

- Persist and manage background analysis jobs.

Main public functions and classes:

- `JobState`
- `JobRegistry`
- `create`
- `create_or_reuse_active`
- `get`
- `update`
- `list_recent`
- `submit`

Who calls it:

- `app.py` routes and cleanup scheduler

Expected data:

- owner IDs
- upload path
- analysis key

Returns:

- job state objects

High-risk changes:

- status transitions
- persistence format
- dedup matching behavior

### `Backend/pcap_engine/cleanup.py`

Purpose:

- Remove stale job folders, stale exported bundles, and stale run artifacts while protecting active work.

Main public functions:

- `run_cleanup_pass`
- `start_cleanup_scheduler`

Who calls it:

- scheduler bootstrap in `app.py`

Expected data:

- base run folder
- jobs folder
- retention windows

Returns:

- summary dict for cleanup passes

High-risk changes:

- active job protection logic
- retention time semantics
- forgetting jobs still needed by the frontend

## 4. Data contracts between stages

### 4.1 Packet export CSV contract

This is the raw tshark output consumed by `build_cic_features_from_tshark_csv()`.

Required exported fields in order:

```text
frame.time_epoch
ip.src
ip.dst
ipv6.src
ipv6.dst
tcp.srcport
tcp.dstport
udp.srcport
udp.dstport
ip.proto
frame.len
tcp.flags
```

Required:

- all positions must exist in the emitted CSV row order
- empty values are allowed for non-applicable IP version or transport

Derived:

- source/destination IP selection prefers IPv4, then IPv6
- source/destination ports choose TCP if present, otherwise UDP

Display-only:

- none at this stage

### 4.2 CIC feature frame contract

The pipeline validates exact membership against `EXPECTED_CIC65`.

Required columns:

```text
src_ip
dst_ip
src_port
dst_port
ip_prot
ts
flow_duration
fwd_pkts_tot
bwd_pkts_tot
fwd_bytes_tot
bwd_bytes_tot
flow_pkts_per_sec
bytes_per_s
down_up_ratio
fwd_pkts_payload.min
fwd_pkts_payload.max
fwd_pkts_payload.tot
fwd_pkts_payload.avg
fwd_pkts_payload.std
bwd_pkts_payload.min
bwd_pkts_payload.max
bwd_pkts_payload.tot
bwd_pkts_payload.avg
bwd_pkts_payload.std
flow_pkts_payload.min
flow_pkts_payload.max
flow_pkts_payload.tot
flow_pkts_payload.avg
flow_pkts_payload.std
fwd_iat.min
fwd_iat.max
fwd_iat.tot
fwd_iat.avg
fwd_iat.std
bwd_iat.min
bwd_iat.max
bwd_iat.tot
bwd_iat.avg
bwd_iat.std
flow_iat.min
flow_iat.max
flow_iat.tot
flow_iat.avg
flow_iat.std
flow_FIN_flag_count
flow_SYN_flag_count
flow_RST_flag_count
fwd_PSH_flag_count
bwd_PSH_flag_count
flow_ACK_flag_count
fwd_URG_flag_count
bwd_URG_flag_count
flow_ECE_flag_count
flow_CWR_flag_count
active.min
active.max
active.tot
active.avg
active.std
idle.min
idle.max
idle.tot
idle.avg
idle.std
service
```

Important required columns for downstream logic:

- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `ip_prot`
- `ts`
- `flow_duration`
- `flow_pkts_per_sec`
- `bytes_per_s`
- `flow_SYN_flag_count`, `flow_ACK_flag_count`, `flow_RST_flag_count`
- `bwd_pkts_tot`
- `service`

Optional at this stage:

- none by contract, because the schema is fixed

Derived:

- all fields come from packet aggregation
- `service` is hardcoded to `unknown` in the extractor

Display-only:

- none yet

### 4.3 ML inference frame contract

Model feature requirements are dynamic because `trained_columns` comes from the saved model bundle.

Hard rules enforced by code:

- only `ip_prot` and `service` may be auto-filled safely as `unknown`
- any other missing trained feature triggers `FeatureSchemaError`
- metadata columns may be present and remain outside the model matrix

Metadata columns explicitly preserved by `predict_flows()`:

```text
src_ip
dst_ip
src_port
dst_port
ts
```

New ML output fields:

```text
ml_label
ml_confidence
```

Important distinction:

- `ml_confidence` is the model probability-like output
- later `confidence` becomes the post-validation `final_score`

### 4.4 Base context and security fields

`build_flow_context_features()` derives the base context columns:

```text
time_bucket
bytes_total
bytes_ratio
is_short
is_long
is_failed
src_conn_count
src_unique_ports
src_unique_targets
src_failed_ratio
src_short_ratio
src_dst_conn_count
src_dst_failed_ratio
src_dst_short_ratio
src_dst_port_conn_count
src_dst_port_failed_ratio
src_dst_port_short_ratio
src_dst_conn_share
src_dst_port_conn_share
```

`apply_heuristics()` adds:

```text
heuristic_score
heuristic_type
heuristic_reason
```

`add_flow_merge_keys()` adds:

```text
flow_dir_key
flow_pair_key
```

Required for scoring:

- `ml_label`
- `ml_confidence`
- endpoint fields
- `dst_port`

Strongly influential context fields:

- `src_conn_count`
- `src_unique_ports`
- `src_unique_targets`
- `src_failed_ratio`
- `src_short_ratio`
- `src_dst_conn_count`
- `src_dst_port_conn_count`
- `flow_pkts_per_sec`
- `bytes_per_s`
- `heuristic_score`
- `conn_state` if evidence later supplies it

### 4.5 Zeek evidence frame contracts

#### Conn evidence

Loaded columns:

```text
ts
uid
id.orig_h
id.orig_p
id.resp_h
id.resp_p
proto
service
duration
orig_bytes
resp_bytes
conn_state
```

Merged columns kept for final frame:

```text
proto
service
conn_state
duration
orig_bytes
resp_bytes
```

#### DNS evidence

Loaded columns:

```text
ts
uid
id.orig_h
id.orig_p
id.resp_h
id.resp_p
query
qtype_name
answers
rcode_name
```

Summarized merged columns:

```text
dns_query_count
dns_nx_count
dns_unique_queries
dns_top_query
```

#### HTTP evidence

Loaded columns:

```text
ts
uid
id.orig_h
id.orig_p
id.resp_h
id.resp_p
method
host
uri
status_code
user_agent
```

Summarized merged columns:

```text
http_request_count
http_unique_hosts
http_top_host
http_top_uri
http_status_4xx_5xx_count
```

#### SSL evidence

Loaded columns:

```text
ts
uid
id.orig_h
id.orig_p
id.resp_h
id.resp_p
server_name
ja3
version
cipher
```

Summarized merged columns:

```text
ssl_event_count
ssl_unique_sni
ssl_top_sni
ssl_unique_ja3
ssl_top_cipher
```

Evidence-presence marker fields created during merge:

```text
has_conn_evidence
has_dns_evidence
has_http_evidence
has_ssl_evidence
```

### 4.6 Final scored frame contract

After `fuse_scores()` the important fields include:

```text
severity
ml_score
confidence_tier
suppressed
suppressed_reason
validation_failed
validation_reason
support_level
support_multiplier
signal_verdict
verdict
support_promoted
support_demoted
final_score
confidence
reason
```

Important distinction:

- `severity` is the label-derived severity family
- `signal_verdict` is the preliminary verdict before full context resolution
- `verdict` is the final surfaced verdict
- `final_score` is the bounded final risk score
- `confidence` is set equal to `final_score`

### 4.7 Report contract

Produced by `build_report()`:

- `meta`
- `summary`
- `clusters`
- `alerts`
- `timeline`

Frontend currently depends on:

- `summary.total_flows`
- `summary.alerts_count` or `summary.alerts`
- `summary.suspicious`
- `summary.overall_risk`
- `summary.risk_level`
- `clusters[*].attack_type`
- `clusters[*].src_ip`
- `clusters[*].dst_ip`
- `clusters[*].count_flows`
- `clusters[*].max_threat_confidence`
- `clusters[*].max_ml_confidence`
- `clusters[*].severity`
- `clusters[*].top_dst_ports`
- `alerts[*].ts`
- `alerts[*].src_ip`
- `alerts[*].dst_ip`
- `alerts[*].dst_port`
- `alerts[*].ml_label`
- `alerts[*].confidence`
- `alerts[*].severity`
- `alerts[*].reason`
- `timeline[*].ts`
- `timeline[*].src_ip`
- `timeline[*].dst_ip`
- `timeline[*].dst_port`
- `timeline[*].ml_label`
- `timeline[*].confidence`
- `timeline[*].verdict`

Frontend currently does not read `meta`, including `meta.comparison`, even though the backend emits it.

## 5. Scoring and verdict logic

This is the core decision logic. It lives in `security_logic.py` and is executed by `scorer.py`.

### 5.1 Step order in `fuse_scores()`

The scoring order matters:

1. Ensure required columns exist.
2. Compute initial suppression result with `should_suppress()`.
3. Map `ml_label` to `severity` via `label_to_severity()`.
4. Compute raw ML risk-like score via `severity_to_score()`.
5. Compute `confidence_tier()` from label-specific thresholds.
6. Compute `validation_reason` and `validation_failed`.
7. Compute `support_level` and `support_multiplier`.
8. Compute `signal_verdict` via `base_verdict_from_signal()`.
9. Force suppression if validation failed or confidence tier is `ignore`.
10. Compute final `verdict` via `verdict_from_context()`.
11. Mark `support_promoted` and `support_demoted`.
12. Blend and bound the final score.
13. Build `reason`.
14. Copy `final_score` into `confidence`.

### 5.2 Severity mapping

`label_to_severity()` maps normalized labels into:

- `Low`
- `Medium`
- `High`
- `Critical`
- `Unknown`

Important cases:

- `benign` maps to `Low` at this stage, not directly to `Normal`
- final `Normal` is produced later by suppression, confidence tier, or context logic
- `arp_poisioning` or `arp_poisoning` can become `Critical` if `ml_confidence >= 0.95`

### 5.3 Confidence tiers

`confidence_tier()` returns:

- `ignore`
- `suspicious`
- `confirmed`

Thresholds are label-family sensitive:

- generic suspicious floor starts at `0.70`
- generic confirm floor starts at `0.88`
- rare labels require at least `0.95` to confirm
- HTTP DoS, DDoS, generic DoS, and non-alert suspicious labels raise thresholds further

This prevents the model from surfacing weak-confidence traffic too aggressively.

### 5.4 Suppression and validation

There are two separate concepts:

#### `should_suppress()`

Purpose:

- remove obvious network noise and impossible label/context pairs early

Examples:

- mDNS on `5353`
- LLMNR on `5355`
- SSDP on `1900`
- DHCP-like/broadcast traffic
- ARP-poison label on DNS port 53
- HTTP DoS label with no HTTP context and only a few target connections
- isolated DoS or DDoS label without burst characteristics

Output:

- `SuppressionResult(suppressed: bool, reason: str)`

#### `validation_fail_reason()`

Purpose:

- enforce family-specific semantic checks
- reject model labels that do not fit observed protocol behavior

Examples:

- SSH brute-force labels require destination port 22
- FTP brute-force labels require port 21
- ARP poisoning is suppressed because the current pipeline lacks true layer-2 ARP evidence
- HTTP DoS labels require reliable HTTP context
- SYN flood labels require SYN-heavy context
- generic DDoS or DoS labels require clear burst evidence
- scan-like fanout can suppress DoS labels

If validation returns any text:

- `validation_failed = True`
- row is forced to `suppressed = True`
- final reason becomes the validation reason

### 5.5 Context support levels

`context_support_level()` returns:

- `none`
- `weak`
- `moderate`
- `strong`

It is label-family aware. Some examples:

- DoS and DDoS labels rely on:
  - target connection count
  - burst score
  - HTTP context
  - SYN context
- scan labels rely on:
  - `src_conn_count`
  - `src_unique_ports`
  - `src_short_ratio`
- brute-force labels rely on:
  - failed ratios
  - target/source connection counts
- heartbleed relies on:
  - SSL event evidence
  - TLS-like service or port

`support_level_to_multiplier()` then maps support to numeric scaling:

- `none -> 0.35`
- `weak -> 0.60`
- `moderate -> 0.80`
- `strong -> 1.00`

### 5.6 Signal verdict vs final verdict

#### `base_verdict_from_signal()`

Purpose:

- derive a preliminary verdict from:
  - label
  - severity
  - confidence tier
  - base context signal level

This is the "what the model plus base context suggests" verdict before full support resolution.

Important behavior:

- `benign` becomes `Normal`
- `Low` or `Unknown` severity becomes `Normal`
- `ignore` confidence becomes `Normal`
- `suspicious` only becomes `Medium` when base signal is `strong`
- confirmed `Critical` does not automatically become `Critical`
  - `strong` base signal -> `Critical`
  - `moderate` -> `High`
  - `weak` -> `Medium`
  - `none` -> `Medium`

#### `verdict_from_context()`

Purpose:

- convert severity plus full support context into the final surfaced verdict

Important behavior:

- if `suppressed` is true, final verdict is always `Normal`
- `benign` is always `Normal`
- `Low` severity is always `Normal`
- `ignore` confidence is always `Normal`
- `suspicious`:
  - non-alert suspicious labels remain `Normal`
  - otherwise only `strong` support becomes `Medium`
- `confirmed`:
  - `none` support -> `Normal`
  - `weak` support -> `Medium`
  - `moderate` support:
    - `Critical` severity is reduced to `High`
    - `Medium` or `High` stays at severity
  - `strong` support:
    - returns severity

This is why unsupported evidence should not over-promote results.

### 5.7 Promotion and demotion logic

`support_promoted` and `support_demoted` are computed by comparing:

- `verdict_rank(verdict)`
- `verdict_rank(signal_verdict)`

`verdict_rank()` is the canonical ordering:

- `Normal = 0`
- `Low = 1`
- `Medium = 2`
- `High = 3`
- `Critical = 4`

Promotion is possible, but only when strong support justifies it. Example:

- a confirmed `Critical` label may have `signal_verdict = High`
- if full support resolves to `Critical`, that counts as a support-driven promotion

Demotion is common when:

- validation fails
- support is weak or absent
- context points away from the label family

### 5.8 Score construction, floor, and cap

Raw score path in `fuse_scores()`:

```text
ml_score = severity_to_score(severity, ml_confidence)
raw_score = 0.90 * ml_score + 0.10 * heuristic_score
context_scaled = raw_score * support_multiplier
final_score = clip(context_scaled, 0, 1)
final_score = min(final_score, verdict_score_cap(verdict))
if verdict != Normal:
    final_score = max(final_score, verdict_score_floor(verdict))
if verdict == Normal:
    final_score = 0.0
```

#### `verdict_score_cap()`

Current caps:

- `Normal -> 0.00`
- `Low -> 0.30`
- `Medium -> 0.60`
- `High -> 0.82`
- `Critical -> 0.97`

Purpose:

- prevent a modestly supported verdict from carrying an out-of-band risk score
- keep report `overall_risk` aligned with the surfaced verdict band

#### `verdict_score_floor()`

Current floors:

- `Normal -> 0.00`
- `Low -> 0.20`
- `Medium -> 0.40`
- `High -> 0.65`
- `Critical -> 0.85`

Purpose:

- prevent non-Normal verdicts from carrying misleadingly tiny `final_score`
- align report risk thresholds to verdict bands

This is why:

- `Normal` ends with zero score
- `Medium`, `High`, and `Critical` do not keep tiny scores that contradict their surfaced verdict

### 5.9 Reason generation

`build_reason()` uses this precedence:

1. `validation_reason`
2. `suppressed_reason`
3. low-confidence ignore reason
4. label-family-specific explanation built from evidence fragments
5. generic fallback reason

`summarize_evidence_for_reason()` draws concise snippets from:

- heuristic reason
- connection counts
- unique ports
- failed and short ratios
- conn state
- service or proto
- duration
- packet and byte rates
- SYN counts
- Zeek byte totals
- DNS top query
- HTTP host and URI
- SSL SNI

The final reason is intended for operator readability, not machine re-parsing.

### 5.10 Risk level mapping in reports

The report summary maps `overall_risk` to:

- `Critical` if `>= 0.85`
- `High` if `>= 0.65`
- `Medium` if `>= 0.40`
- `Low` if `>= 0.20`
- `Normal` otherwise

This matches the non-Normal score floors, which is intentional.

### Why verdict inflation is prevented

The code prevents unjustified escalation in several layers:

- low-confidence labels become `ignore`
- validation failures force suppression
- suspicious tiers only surface with strong support
- `context_support_level()` is family-specific, not generic
- `verdict_from_context()` demotes unsupported results
- `verdict_score_cap()` keeps score bands aligned with verdict

### Why unsupported evidence should not over-promote results

Evidence does not directly set a verdict. Evidence only populates row fields such as:

- `service`
- `conn_state`
- `duration`
- `orig_bytes`
- `dns_query_count`
- `http_request_count`
- `ssl_event_count`

Those fields then affect:

- `validation_fail_reason()`
- `context_support_level()`
- `build_reason()`

This indirection is what keeps enrichment explainable and bounded.

## 6. Evidence enrichment logic

Zeek enrichment is additive. It never bypasses the scorer.

### 6.1 Shared merge mechanics

The generic merge path is `_merge_frame_with_fallback()`.

It performs:

1. Direct merge on `flow_dir_key + time_bucket`
2. Fallback merge on `flow_pair_key + time_bucket`
3. Fallback eligibility checks:
   - evidence pair must be unique
   - base pair row count must be `<= fallback_base_row_limit`
   - protocol-specific fallback guard must pass
4. Evidence presence flags are computed
5. Coverage metrics are logged

Important:

- conn evidence direct keys include protocol because `proto_col="ip_prot"` or `proto_col="proto"` is used.
- summarized DNS, HTTP, and SSL evidence keys do not include protocol. Safety comes from exact endpoint, port, and time matching plus fallback guards.

### 6.2 Conn evidence

Matching strategy:

- direct:
  - `flow_dir_key`
  - `time_bucket`
- fallback:
  - `flow_pair_key`
  - `time_bucket`
  - only if there is one unique candidate pair and one base pair row

Merged fields:

- `proto`
- `service`
- `conn_state`
- `duration`
- `orig_bytes`
- `resp_bytes`

How it helps scoring:

- provides accurate service and protocol context
- gives conn state for failed-connection logic
- provides byte counts and duration for reasons and context

When it should not change verdict:

- if it only adds ordinary service metadata without increasing support or clearing validation constraints

### 6.3 DNS evidence

Matching strategy:

- exact and fallback use endpoint, port, and time bucket keys
- fallback guard requires:
  - fallback DNS query count present
  - DNS port context (`53` or `5353`) or service `dns`

Summaries:

- `dns_query_count`
- `dns_nx_count`
- `dns_unique_queries`
- `dns_top_query`

Leakage prevention:

- fallback cannot apply unless DNS fallback evidence exists
- fallback also requires DNS-like port or service context

When it can raise support:

- DNS-heavy behavior can provide contextual evidence for certain suspicious labels
- it can improve reason text even if verdict remains unchanged

### 6.4 HTTP evidence

Matching strategy:

- exact and fallback use endpoint, port, and time bucket keys
- fallback guard requires:
  - actual HTTP fallback evidence:
    - `http_request_count__fallback > 0`, or
    - `http_top_host__fallback` non-empty, or
    - `http_top_uri__fallback` non-empty
  - web port context or HTTP service
  - `https` is allowed only when both:
    - web-port context exists
    - HTTP evidence is present

Summaries:

- `http_request_count`
- `http_unique_hosts`
- `http_top_host`
- `http_top_uri`
- `http_status_4xx_5xx_count`

Leakage prevention:

- fallback cannot occur on an arbitrary TLS flow just because the service says `https`
- the guard requires actual HTTP fallback evidence

How it can raise verdict:

- HTTP DoS and web-attack families depend heavily on reliable HTTP context
- HTTP evidence may move a row from suppressed or weakly supported into a validated Medium or High

When it should not change verdict:

- if there is no HTTP evidence
- if there is only a web port but no HTTP-specific summarized fields

### 6.5 SSL evidence

Matching strategy:

- exact and fallback use endpoint, port, and time bucket keys
- fallback guard requires:
  - actual SSL fallback evidence:
    - `ssl_event_count__fallback > 0`, or
    - `ssl_top_sni__fallback` non-empty, or
    - `ssl_top_cipher__fallback` non-empty
  - TLS port context or service in `ssl` or `tls`
  - `https` is allowed only when both:
    - TLS-port context exists
    - SSL evidence exists

Summaries:

- `ssl_event_count`
- `ssl_unique_sni`
- `ssl_top_sni`
- `ssl_unique_ja3`
- `ssl_top_cipher`

Leakage prevention:

- fallback cannot apply to unrelated web traffic without actual TLS evidence

How it can raise verdict:

- heartbleed or TLS-oriented reasoning can gain stronger support
- SSL presence can improve support and reasons for encrypted service flows

### 6.6 Meaning of evidence merge logs

Current log shape:

```text
Merged <frame> evidence | exact_match_rows=... | fallback_match_rows=... | rows_with_evidence=... | coverage_pct=...
```

Definitions:

- `exact_match_rows`
  - rows that gained evidence from direct `flow_dir_key + time_bucket` matching
- `fallback_match_rows`
  - rows that gained evidence only after the pair-key fallback path and guard checks
- `rows_with_evidence`
  - rows where the merged evidence columns are actually considered present
- `coverage_pct`
  - `rows_with_evidence / total_rows * 100`

Interpretation:

- high conn coverage is normal because Zeek `conn.log` closely corresponds to flows
- DNS, HTTP, and SSL coverage should be lower because only flows with those protocol behaviors can carry that evidence
- non-zero fallback counts are not automatically suspicious
- unexpectedly large fallback counts suggest merge-key ambiguity

## 7. Comparison logic

The comparison logic exists to answer: "What changed because Zeek evidence was added?"

### Base snapshot

`base_scored` is the scored frame before evidence merges.

### Enriched snapshot

`final_df` is the rescored frame after evidence merges and defaults cleanup.

### Stable row matching assumptions

Rows are matched by a deterministic comparison key built from:

1. Stable flow identity:
   - `src_ip`
   - `src_port`
   - `dst_ip`
   - `dst_port`
   - normalized protocol
   - `time_bucket`
2. Stable sort tiebreakers:
   - `ts`
   - `ml_label`
   - `ml_confidence`
   - `flow_duration`
   - `flow_pkts_per_sec`
   - `bytes_per_s`
   - `heuristic_score`
3. Per-identity sequence number:
   - `cumcount()` within the stable flow identity

Final compare key:

```text
<stable_flow_identity>#<sequence>
```

This means row order changes alone should not break comparison.

### Comparison summary fields

- `compared_rows`
  - count of keys present in both frames
- `changed_by_evidence_up`
  - rows whose final verdict rank increased after evidence
- `changed_by_evidence_down`
  - rows whose final verdict rank decreased after evidence
- `base_only_rows`
  - rows seen only in the base snapshot
- `enriched_only_rows`
  - rows seen only in the enriched snapshot

### How to interpret a healthy comparison

Typical healthy Zeek-enriched run:

- `compared_rows` equals total flow rows
- `base_only_rows = 0`
- `enriched_only_rows = 0`
- `changed_by_evidence_up` is small but non-zero for captures where Zeek adds meaningful context
- `changed_by_evidence_down` is often zero or small

Example from current logs:

```text
compared_rows=603
base_only_rows=0
enriched_only_rows=0
changed_by_evidence_up=1
changed_by_evidence_down=0
```

### What abnormal comparison values mean

- `base_only_rows > 0` or `enriched_only_rows > 0`
  - likely row identity drift
  - non-deterministic sort assumptions changed
  - merge step changed row multiplicity
- `changed_by_evidence_up` extremely high
  - evidence may be merging too broadly
  - guards may be too permissive
- `changed_by_evidence_down` extremely high
  - validation or support logic may be over-demoting
  - evidence fields may be missing or defaulting incorrectly

## 8. Report structure

The report is produced by `build_report()` and written to `report.json`.

### Top-level shape

```json
{
  "meta": {},
  "summary": {},
  "clusters": [],
  "alerts": [],
  "timeline": []
}
```

### `meta`

Schema:

```json
{
  "generated_at": "ISO-8601 UTC timestamp",
  "pcap_path": "backend filesystem path",
  "run_folder": "pipeline mode label",
  "zeek_requested": true,
  "zeek_enrichment_succeeded": true,
  "zeek_evidence_available": true,
  "analysis_mode": "base_only or enriched",
  "comparison": {
    "compared_rows": 603,
    "changed_by_evidence_up": 1,
    "changed_by_evidence_down": 0,
    "base_only_rows": 0,
    "enriched_only_rows": 0
  },
  "pipeline": {
    "...": "full pipeline_meta"
  }
}
```

Where values come from:

- `generated_at`
  - current UTC time from reporter
- `pcap_path`
  - original path passed from pipeline
- `run_folder`
  - passed by pipeline as a mode label:
    - `tshark+cic`
    - `tshark+cic+zeek`
- `analysis_mode`
  - derived in `run_pcap_pipeline()`
- `comparison`
  - compact comparison summary inserted into `pipeline_meta`

Frontend reliance:

- current frontend does not read `meta`

JSON safety expectations:

- booleans and ints are JSON-safe
- floats should already be bounded and finite

Important caveat:

- `meta.run_folder` is currently a descriptive mode label, not the actual filesystem Zeek directory

### `summary`

Schema:

```json
{
  "total_flows": 603,
  "alerts_count": 3,
  "suspicious": 3,
  "malicious": 2,
  "overall_risk": 0.6561,
  "risk_level": "High",
  "top_attackers": [
    {
      "src_ip": "10.0.0.1",
      "count_flows": 12
    }
  ]
}
```

Where values come from:

- `total_flows`
  - full DataFrame length
- `alerts_count`
  - number of emitted alert rows
- `suspicious`
  - same count as alert rows because alerts are Medium+
- `malicious`
  - count of High or Critical emitted alerts
- `overall_risk`
  - max `final_score` among Medium, High, or Critical rows
- `risk_level`
  - thresholded from `overall_risk`
- `top_attackers`
  - aggregated from cluster source IP counts

Frontend reliance:

- frontend accepts either `summary.alerts` or `summary.alerts_count`
- current backend emits `alerts_count`

JSON safety expectations:

- numeric values must be finite

Compatibility sensitivity:

- backend does not currently emit explicit `summary.suppressed`
- frontend derives a suppressed count client-side, which does not represent all suppressed flows because backend alerts only include non-suppressed rows

### `clusters`

Schema per row:

```json
{
  "attack_type": "portscan",
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.5",
  "count_flows": 9,
  "top_dst_ports": [{"port": 80, "count": 7}],
  "top_dst_ips": [{"ip": "10.0.0.5", "count": 9}],
  "max_confidence": 0.82,
  "max_threat_confidence": 0.82,
  "max_ml_confidence": 0.94,
  "severity": "High"
}
```

Where values come from:

- grouped from non-suppressed Medium, High, or Critical rows
- grouping key:
  - `src_ip`
  - `dst_ip`
  - `ml_label`

Frontend reliance:

- heavily relied on for the Attack Clusters table

JSON safety expectations:

- confidence fields are sanitized
- counts and ports are ints

### `alerts`

Schema per row:

```json
{
  "type": "ML",
  "ts": 1710635291.0,
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.5",
  "dst_port": 80,
  "ml_label": "dos_hulk",
  "ml_confidence": 0.93,
  "classification_confidence": 0.93,
  "confidence": 0.65,
  "threat_confidence": 0.65,
  "severity": "High",
  "reason": "DoS suspected: ...",
  "zeek_service": "http",
  "zeek_conn_state": "SF",
  "zeek_proto": "tcp",
  "zeek_duration": 4.12,
  "zeek_bytes": {"orig": 1024.0, "resp": 512.0},
  "dns_top_query": "",
  "dns_query_count": 0,
  "http_top_host": "example.local",
  "http_top_uri": "/",
  "http_request_count": 22,
  "ssl_top_sni": "",
  "ssl_event_count": 0,
  "heuristic": {
    "type": "FocusedBurst",
    "score": 0.45,
    "reason": "Repeated focused traffic..."
  }
}
```

Where values come from:

- only from non-suppressed rows with final verdict in `Medium`, `High`, or `Critical`
- deduplicated by:
  - `src_ip`
  - `dst_ip`
  - `dst_port`
  - `ml_label`
  - `verdict`
  - `time_bucket` if present

Frontend reliance:

- main source for the Alerts Drilldown table and detail sheet

Important contract nuance:

- backend does not emit a separate `decision`
- frontend derives decision from severity and verdict
- backend uses final verdict value as `severity` in alert rows

JSON safety expectations:

- `zeek_bytes` are finite floats
- counts are ints
- strings are sanitized against blank and `nan`

### `timeline`

Schema per row:

```json
{
  "ts": 1710635291.0,
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.5",
  "dst_port": 80,
  "ml_label": "dos_hulk",
  "ml_confidence": 0.93,
  "classification_confidence": 0.93,
  "confidence": 0.65,
  "threat_confidence": 0.65,
  "verdict": "High"
}
```

Where values come from:

- all rows in the final frame, not just alerts
- sorted by timestamp

Frontend reliance:

- used for the Activity Timeline table

Important contract nuance:

- timeline rows do not include a separate `severity`
- frontend falls back to `verdict` when normalizing severity

### NaN and inf sanitization expectations

Reporter safety helpers:

- `_safe_float()`
- `_safe_int()`
- `_safe_str()`

They prevent:

- `NaN`
- `Infinity`
- `-Infinity`

from leaking into the report JSON. This matters because the job system serializes with `allow_nan=False` and the browser expects strict JSON.

## 9. Logs-to-stage troubleshooting guide

### `Starting tshark export`

- Stage:
  - packet export start
- Success looks like:
  - appears once per real job start
  - includes correct path, size, mode, timeout
- Suspicious output:
  - repeated lines for the same PCAP and same option set
- Likely causes:
  - duplicate submissions before dedup
  - intentionally distinct jobs by owner or options

### `tshark export completed`

- Stage:
  - packet export finished
- Success looks like:
  - elapsed time roughly scales with PCAP size
  - non-zero `output_size`
- Suspicious output:
  - output size zero or extremely small for a large capture
  - missing matching `Packet export ready`
- Likely causes:
  - bad read filter
  - truncated capture
  - tshark partial failure

### `CIC feature extraction`

- Stage:
  - packet CSV -> CIC flow aggregation
- Success looks like:
  - `missing=[]`
  - `extra=[]`
  - non-zero `flow_count`
  - low `parse_errors`
- Suspicious output:
  - schema mismatch
  - `flow_count=0`
  - high parse errors
- Likely causes:
  - tshark field order drift
  - CSV corruption
  - parser breakage

### `Inference schema check`

- Stage:
  - model input alignment
- Success looks like:
  - no dangerous missing columns
  - only expected metadata in `unexpected`
- Suspicious output:
  - missing trained columns other than `ip_prot` or `service`
  - `order_mismatch=True` with other anomalies
- Likely causes:
  - model bundle drift
  - changed CIC feature names
  - bad preprocessing edits

### `Inference label distribution`

- Stage:
  - raw model output distribution
- Success looks like:
  - plausible mix for the capture
- Suspicious output:
  - almost all rows suddenly map to one strange class
  - repeated impossible labels after a model update
- Likely causes:
  - model mismatch
  - broken categorical encoding
  - feature drift

### `ML inference completed`

- Stage:
  - model inference finished and attached to the flow frame
- Success looks like:
  - `flow_count` matches CIC `flow_count`
- Suspicious output:
  - missing log after schema check
- Likely causes:
  - prediction count mismatch
  - thrown `FeatureSchemaError`

### `Zeek run completed`

- Stage:
  - Zeek background analysis finished
- Success looks like:
  - non-zero `log_files`
- Suspicious output:
  - very few logs for a capture expected to contain multiple protocols
- Likely causes:
  - Zeek failure
  - path conversion problem
  - empty or unusual capture

### `Zeek evidence loaded`

- Stage:
  - Zeek JSON logs loaded and summarized
- Success looks like:
  - conn count close to flow scale
  - dns, http, and ssl counts plausible for protocol mix
- Suspicious output:
  - all zeros after successful Zeek run
- Likely causes:
  - loader filename mismatch
  - malformed log JSON
  - wrong run folder

### `Merged conn evidence`

- Stage:
  - conn evidence merge
- Success looks like:
  - high `coverage_pct`
  - low but non-zero fallback sometimes acceptable
- Suspicious output:
  - very low coverage
  - huge fallback
- Likely causes:
  - protocol normalization drift
  - time bucket mismatch
  - flow key mismatch

### `Merged dns evidence`

- Stage:
  - DNS summary merge
- Success looks like:
  - coverage only on DNS-looking traffic
- Suspicious output:
  - unexpectedly high fallback or wide coverage on non-DNS capture
- Likely causes:
  - fallback guard loosened
  - wrong ports or service normalization

### `Merged http evidence`

- Stage:
  - HTTP summary merge
- Success looks like:
  - modest coverage on web traffic
  - fallback often zero
- Suspicious output:
  - HTTP evidence appearing broadly on non-HTTP traffic
- Likely causes:
  - fallback guard broken
  - bad host or URI summarization

### `Merged ssl evidence`

- Stage:
  - SSL summary merge
- Success looks like:
  - TLS-related coverage only
- Suspicious output:
  - SSL evidence on unrelated flows
- Likely causes:
  - TLS guard broken
  - pair-key collisions

### `Detection scoring | stage=base_pre_evidence`

- Stage:
  - scoring before evidence
- Success looks like:
  - all `conn_rows`, `dns_rows`, `http_rows`, `ssl_rows` zero
  - verdicts plausible but conservative
- Suspicious output:
  - evidence rows already non-zero
- Likely causes:
  - stale columns left in base frame

### `Detection scoring | stage=post_evidence`

- Stage:
  - scoring after evidence
- Success looks like:
  - evidence row counts reflect merge coverage
  - `changed_by_evidence_up/down` plausible
- Suspicious output:
  - huge jump in alerts from tiny evidence coverage
- Likely causes:
  - support logic or merge guard regression

### `Detection scoring | stage=final_no_zeek`

- Stage:
  - final scoring when Zeek is disabled
- Success looks like:
  - evidence counts all zero
  - no comparison changes
- Suspicious output:
  - repeated identical lines for the same user action
- Likely causes:
  - duplicate submissions
  - concurrent intentional jobs on the same file before dedup

### `Detection comparison`

- Stage:
  - base vs enriched verdict comparison
- Success looks like:
  - row counts match
  - only some verdicts change
- Suspicious output:
  - non-zero base-only or enriched-only rows
- Likely causes:
  - non-deterministic ordering
  - row count drift
  - merge multiplicity changes

### `cleanup started` and `cleanup completed`

- Stage:
  - artifact retention
- Success looks like:
  - active jobs skipped
  - no unexpected deletions
- Suspicious output:
  - errors deleting active job folders
  - active jobs not listed as skipped
- Likely causes:
  - status persistence bug
  - cleanup protection regression

## 10. Current Runtime Risks / Caveats

These are grounded in the current implementation and current logs.

### Localhost auth fallback still exists by design

- PCAP routes intentionally allow localhost fallback ownership when auth is missing or invalid.
- This is useful in development, but it can mask frontend auth propagation problems for PCAP routes while `/api/auth/*` still correctly returns `401`.
- Current code throttles the warning logs, but the behavior remains.

### Large PCAPs are expensive in time, disk, and memory

- The subsystem writes a full packet CSV before feature aggregation.
- Large captures observed in current logs:
  - `8.23 GB` PCAP
  - approximately `858 MB` packet CSV
  - approximately `397,538` flow rows
  - several minutes just for tshark export
- Pandas then holds large flow frames in memory and may hold both base and enriched variants during scoring and comparison.

### Concurrency pressure is real

- `JobRegistry` uses `max_workers=3`.
- Each Zeek-enabled job can also spin its own one-thread Zeek executor.
- Concurrent large jobs can pressure:
  - CPU
  - disk I/O
  - RAM
  - WSL Zeek runtime

### Polling is lighter, but still polling

- The backend now throttles successful poll access logs and adds `Retry-After`.
- Polling does not recompute analysis.
- Even so, repeated polling still hits Flask and state loading paths.

### Schema drift remains a hard failure point

- CIC output must match `EXPECTED_CIC65`.
- Model input must match bundle `trained_columns`.
- Safe defaults only exist for `ip_prot` and `service`.
- This is correct for integrity, but it means any feature rename or bundle mismatch fails hard.

### Evidence merge safety depends on guards staying strict

- conn evidence is protocol-aware in merge keys.
- DNS, HTTP, and SSL summary merges are not protocol-aware at the key level.
- Safety comes from:
  - exact endpoint, port, and time matching
  - unique pair fallback restriction
  - `_summary_fallback_guard()`
- If those guards are loosened, evidence leakage across protocol types becomes much more likely.

### Duplicate jobs are reduced, not universally impossible

- Equivalent active jobs are deduplicated per owner and option set using `analysis_key`.
- Different owners, different `include_zeek`, different limits, or non-equivalent source keys still run independently.
- Upload dedup uses a sampled file fingerprint, not a full-file cryptographic hash over the entire payload.

### Report and frontend compatibility is sensitive in a few places

- Frontend relies heavily on `summary`, `clusters`, `alerts`, and `timeline`.
- Frontend currently ignores `meta`.
- Backend does not emit `summary.suppressed`, but frontend can show a suppressed badge derived client-side.
- `meta.run_folder` is a mode label, not a filesystem folder path.

## 11. Safe modification guide

### If you want to modify this subsystem safely

#### Safest files to touch

- `Backend/pcap_engine/reporter.py`
  - only if you preserve field names and JSON-safety
- `Backend/pcap_engine/heuristics.py`
  - only for threshold tuning, not contract changes
- `Backend/pcap_engine/zeek_loader.py`
  - only if Zeek log formats change and you keep required output columns stable

#### Medium-risk files

- `Backend/pcap_engine/flow_features.py`
- `Backend/pcap_engine/tshark_runner.py`
- `Backend/pcap_engine/cleanup.py`
- frontend `PcapAnalyzerPage.tsx` normalization code

#### High-risk files

- `Backend/app.py`
- `Backend/pcap_engine/security_logic.py`
- `Backend/pcap_engine/scorer.py`
- `Backend/pcap_engine/cic_stream_features.py`
- `Backend/pcap_engine/ml_infer.py`
- `Backend/pcap_engine/jobs.py`

### Invariants that must not be broken

- Architecture must remain:
  - `tshark -> CIC -> ML -> base context -> heuristics -> optional Zeek -> fuse_scores -> comparison -> report`
- `EXPECTED_CIC65` must stay aligned with the extractor output.
- `security_logic.py` must remain the canonical source for scorer imports.
- `Normal` verdict must end with `final_score = 0.0`.
- non-Normal verdicts must respect floor and cap semantics.
- HTTP and SSL fallback guards must remain evidence-dependent.
- `build_detection_comparison_summary()` must stay deterministic under row reordering.
- report `summary`, `clusters`, `alerts`, and `timeline` shapes must remain frontend-compatible.

### How to test a change safely

Run at least these scenarios:

1. Small PCAP with Zeek disabled
   - expect `final_no_zeek`
   - no evidence rows
2. Small PCAP with Zeek enabled
   - expect `base_pre_evidence`, merge logs, `Detection comparison`, `post_evidence`
3. Local analyze path if you touched local-path handling
4. Repeated Analyze clicks if you touched dedup
   - second click should reuse active job
5. Job polling and exports
   - `/job/<id>`
   - report export
   - evidence export when Zeek is present

### How to validate base vs enriched consistency

For Zeek-enabled runs check:

- `compared_rows` equals the final flow count
- `base_only_rows = 0`
- `enriched_only_rows = 0`
- `changed_by_evidence_up/down` are plausible
- evidence coverage aligns with protocol mix

If those checks fail, inspect:

- merge keys
- time bucket logic
- summary fallback guards
- stable comparison sorting fields

### How to check report compatibility with the frontend

Frontend normalization lives in:

- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`

At minimum preserve:

- `summary.total_flows`
- `summary.alerts_count`
- `summary.suspicious`
- `summary.overall_risk`
- `summary.risk_level`
- cluster fields
- alert fields
- timeline fields

Also verify:

- no `NaN` or `Infinity` in exported JSON
- alert severities still map cleanly into frontend badges
- timeline still sorts and displays time, IPs, port, label, confidence, and verdict

## 12. Fast review cheat sheet

### Pipeline in 10 steps

1. Accept upload or local path request.
2. Resolve PCAP ownership context.
3. Deduplicate equivalent active jobs.
4. Export packet CSV with tshark.
5. Aggregate packets into CIC-like flows.
6. Run ML inference and attach `ml_label` and `ml_confidence`.
7. Build context features, heuristics, and merge keys.
8. Optionally run or load Zeek and merge conn, dns, http, and ssl evidence.
9. Score with suppression, validation, support, verdict, cap, and floor rules.
10. Compare base vs enriched outputs and emit report plus exports.

### Critical functions to remember

- `run_tshark_export()`
- `build_cic_features_from_tshark_csv()`
- `predict_flows()`
- `build_base_detection_frame()`
- `load_zeek_evidence()`
- `merge_conn_evidence()`
- `merge_summary_evidence()`
- `fuse_scores()`
- `build_detection_comparison_summary()`
- `build_report()`

### Critical fields to remember

- ML:
  - `ml_label`
  - `ml_confidence`
- Context:
  - `src_conn_count`
  - `src_unique_ports`
  - `src_failed_ratio`
  - `src_dst_conn_count`
  - `src_dst_port_conn_count`
  - `flow_pkts_per_sec`
  - `bytes_per_s`
- Evidence:
  - `service`
  - `conn_state`
  - `dns_query_count`
  - `http_request_count`
  - `ssl_event_count`
- Scoring:
  - `confidence_tier`
  - `support_level`
  - `signal_verdict`
  - `verdict`
  - `final_score`
  - `reason`

### Critical logs to watch

- `Starting tshark export`
- `tshark export completed`
- `CIC feature extraction`
- `Inference schema check`
- `Inference label distribution`
- `ML inference completed`
- `Zeek run completed`
- `Zeek evidence loaded`
- `Merged conn evidence`
- `Merged dns evidence`
- `Merged http evidence`
- `Merged ssl evidence`
- `Detection scoring | stage=base_pre_evidence`
- `Detection scoring | stage=post_evidence`
- `Detection scoring | stage=final_no_zeek`
- `Detection comparison`

### Most likely bug locations by symptom

- CIC schema mismatch:
  - `tshark_runner.py`
  - `cic_stream_features.py`
- model schema mismatch:
  - `ml_infer.py`
  - saved model bundle
- HTTP or SSL evidence appears on wrong rows:
  - `_summary_fallback_guard()`
  - `_merge_frame_with_fallback()`
- scores look too high or too low:
  - `security_logic.py`
  - `scorer.py`
- base vs enriched comparison row drift:
  - `_stable_comparison_frame()`
  - merge-key generation
- report breaks frontend:
  - `reporter.py`
  - frontend normalizer in `PcapAnalyzerPage.tsx`
- duplicate heavy runs:
  - `jobs.py`
  - `_build_analysis_key()`
  - request entry routes

## Open Questions / Verify Later

- Is `meta.run_folder` intended to remain a pipeline mode label, or should it eventually represent the actual filesystem evidence directory?
- Should the backend explicitly emit `summary.suppressed` instead of leaving the frontend to derive a limited value?
- Should the frontend eventually surface `meta.comparison` for analyst visibility, or is it intended to remain backend-only diagnostics?
- Should additional Zeek logs such as `weird.log` or protocol-specific logs be incorporated into exports or scoring later, or is the current `conn`, `dns`, `http`, and `ssl` scope the intended long-term boundary?
- Should model bundle version, training timestamp, or schema fingerprint be surfaced in the report meta for easier maintenance and incident review?
