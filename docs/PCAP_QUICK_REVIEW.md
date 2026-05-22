# PCAP Quick Review

This is the short reviewer guide for the current PCAP analysis subsystem.

## Pipeline Overview

1. `/analyze-pcap` or `/analyze-local` accepts a PCAP request.
2. Backend resolves PCAP ownership context:
   - authenticated user, or
   - localhost fallback client for local development PCAP routes.
3. Backend computes an `analysis_key` and reuses an equivalent active job if one already exists.
4. Background job starts and writes persistent `state.json`.
5. `tshark` exports packet rows to CSV.
6. `build_cic_features_from_tshark_csv()` aggregates packets into the fixed CIC-like flow schema.
7. `predict_flows()` adds `ml_label` and `ml_confidence`.
8. `build_flow_context_features()` and `apply_heuristics()` add context and heuristic fields.
9. If enabled, Zeek runs in parallel and later loads `conn`, `dns`, `http`, and `ssl` evidence.
10. `fuse_scores()` computes suppression, validation, support, verdict, final score, and reason.
11. If Zeek ran, base vs enriched outputs are compared with deterministic stable keys.
12. `build_report()` emits `meta`, `summary`, `clusters`, `alerts`, and `timeline`.

Pipeline architecture must remain:

`tshark -> CIC -> ML -> base context -> heuristics -> optional Zeek -> fuse_scores -> comparison -> report`

## Most Important Files and Functions

### Orchestration

- `Backend/app.py`
  - `analyze_pcap()`
  - `analyze_local()`
  - `run_pcap_pipeline()`
  - `build_detection_comparison_summary()`
  - `merge_conn_evidence()`
  - `merge_summary_evidence()`
  - `get_job()`
  - `export_job_artifact()`

### Extraction and inference

- `Backend/pcap_engine/tshark_runner.py`
  - `run_tshark_export()`
- `Backend/pcap_engine/cic_stream_features.py`
  - `build_cic_features_from_tshark_csv()`
- `Backend/pcap_engine/ml_infer.py`
  - `prepare_inference_frame()`
  - `predict_flows()`

### Detection logic

- `Backend/pcap_engine/flow_features.py`
  - `build_flow_context_features()`
- `Backend/pcap_engine/heuristics.py`
  - `apply_heuristics()`
- `Backend/pcap_engine/security_logic.py`
  - `base_verdict_from_signal()`
  - `verdict_from_context()`
  - `context_support_level()`
  - `validation_fail_reason()`
  - `verdict_score_cap()`
  - `verdict_score_floor()`
  - `build_reason()`
- `Backend/pcap_engine/scorer.py`
  - `fuse_scores()`

### Zeek enrichment

- `Backend/pcap_engine/zeek_runner.py`
  - `run_zeek()`
- `Backend/pcap_engine/zeek_loader.py`
  - `load_conn()`
  - `load_dns()`
  - `load_http()`
  - `load_ssl()`

### Reporting and jobs

- `Backend/pcap_engine/reporter.py`
  - `build_report()`
  - `cluster_alerts()`
- `Backend/pcap_engine/jobs.py`
  - `create_or_reuse_active()`
  - `submit()`
  - `update()`

## Most Important Scoring Rules

- `ml_label -> severity` is not the same as final verdict.
- `confidence_tier()` returns `ignore`, `suspicious`, or `confirmed`.
- `should_suppress()` removes obvious noise and impossible label-context combinations early.
- `validation_fail_reason()` can force suppression even after a label looks severe.
- `context_support_level()` is family-specific and drives how far a label can surface.
- `signal_verdict` is the preliminary result from ML + base context.
- `verdict` is the final surfaced result after suppression and support checks.
- `support_promoted` and `support_demoted` compare final verdict to `signal_verdict`.
- `final_score` is not raw ML confidence.
- `confidence` is set equal to `final_score`.
- `Normal` always ends with `final_score = 0.0`.
- Non-Normal verdicts are bounded by:
  - floor:
    - Low `0.20`
    - Medium `0.40`
    - High `0.65`
    - Critical `0.85`
  - cap:
    - Low `0.30`
    - Medium `0.60`
    - High `0.82`
    - Critical `0.97`

## Most Important Evidence Rules

- Conn evidence is the strongest merge source and is protocol-aware in the merge key.
- DNS, HTTP, and SSL summaries merge on endpoint, port, and time bucket keys.
- Fallback matching is only allowed when:
  - the pair key is unique,
  - the base pair row count is small,
  - the protocol-specific fallback guard passes.
- HTTP fallback only applies when actual HTTP fallback evidence exists.
- SSL fallback only applies when actual SSL fallback evidence exists.
- `https` handling is intentionally narrow and evidence-dependent.
- Evidence can influence verdict only indirectly through:
  - `validation_fail_reason()`
  - `context_support_level()`
  - `build_reason()`

## Most Important Report Fields

### Backend emits

- `meta`
  - includes `analysis_mode` and compact `comparison`
- `summary`
  - `total_flows`
  - `alerts_count`
  - `suspicious`
  - `malicious`
  - `overall_risk`
  - `risk_level`
  - `top_attackers`
- `clusters`
- `alerts`
- `timeline`

### Frontend currently relies on

- `summary.total_flows`
- `summary.alerts_count` or `summary.alerts`
- `summary.suspicious`
- `summary.overall_risk`
- `summary.risk_level`
- cluster rows
- alert rows
- timeline rows

### Important contract notes

- Frontend currently ignores `meta`.
- Backend does not emit explicit `summary.suppressed`.
- `meta.run_folder` is currently a mode label, not a filesystem folder path.
- `confidence` in alert and timeline rows is the post-validation final score, not raw model confidence.

## Most Important Logs to Inspect

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
- `cleanup started`
- `cleanup completed`

## Top Runtime Risks

- Localhost PCAP auth fallback can hide frontend auth propagation issues during development.
- Large PCAPs are expensive in disk, time, and memory because tshark writes a large intermediate CSV and pandas holds large frames.
- Concurrency can pressure RAM, disk I/O, CPU, and WSL Zeek runtime.
- Schema drift between:
  - tshark export,
  - CIC output,
  - trained model columns,
  - evidence merge fields
  causes hard failures.
- Evidence merge safety depends on keeping fallback guards strict.
- Equivalent active jobs are deduplicated, but different owners or different option sets still run separately.
- Frontend is sensitive to report shape changes in `summary`, `clusters`, `alerts`, and `timeline`.

## Safe Change Checklist

- Keep the pipeline order unchanged.
- Do not rename `EXPECTED_CIC65` columns without updating the model contract.
- Do not loosen `_summary_fallback_guard()`.
- Do not move canonical scorer API functions out of `security_logic.py`.
- Preserve `Normal -> final_score 0.0`.
- Preserve verdict floors and caps unless intentionally recalibrating the scoring model.
- Keep comparison keys deterministic.
- Keep report JSON finite and strict-JSON-safe.
- Test both:
  - no-Zeek mode
  - Zeek-enriched mode
- Validate:
  - `base_only_rows = 0`
  - `enriched_only_rows = 0`
  - report renders in `PcapAnalyzerPage.tsx`
