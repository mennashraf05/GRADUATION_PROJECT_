# PCAP Summary for ChatGPT

Scope: Sentinel AI PCAP / AI Threat Detection evidence only. This file is a technical evidence summary, not graduation-book prose.

## What the PCAP Module Is

The PCAP module lets an authenticated user upload a `.pcap` or `.pcapng` network capture, queues a background analysis job, extracts packet/flow features, runs ML inference, applies heuristic/context validation, and returns a JSON report with summary, alerts, clusters, timeline, and per-IP risk.

Evidence:
- `Backend/app.py`: routes `/pcap/analyze`, `/analyze-pcap`, `/job/<job_id>`, `/pcap/report/<job_id>`, `/job/<job_id>/export`, `/pcap/jobs`, `/api/pcap/cancel/<job_id>`.
- `Backend/app.py`: `run_pcap_pipeline`.
- `Backend/pcap_engine/jobs.py`: `JobRegistry`, `JobState`.
- `Backend/pcap_engine/reporter.py`: `build_report`.
- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`: upload, options, progress, results, exports.

## Problem Solved

Code-supported wording: the module analyzes uploaded network capture files and produces structured threat-analysis outputs for review. It supports detection triage by combining ML predictions, heuristics, contextual validation, and optional Zeek evidence.

Do not claim that the module detects every attack, provides real-time IDS protection, or is enterprise-grade. Those claims are not supported by code.

## Users

- Authenticated end users: upload/analyze PCAP files, monitor job progress, view report data, download report/evidence, cancel running jobs, view PCAP-derived dashboard alerts.
- Admin users: monitor PCAP job overview, queue health, latest files, suspicious files, engine status, timelines, and export report/evidence artifacts.

Evidence:
- User auth context: `Backend/app.py` `_resolve_authenticated_pcap_request_context`, `_get_authorized_job_for_context`, `_pcap_job_matches_context`.
- Admin auth: `Backend/app.py` `@admin_auth_required` on `/api/admin/pcap/overview` and `/api/admin/pcap/jobs/<job_id>/export`.
- Frontend user page: `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`.
- Frontend admin page: `Cybersecurity Dashboard Design/src/components/admin/PcapAnalysisAdminControl.tsx`.

## User-Side Features Confirmed by Code

- Upload `.pcap` / `.pcapng` files up to 15 GB.
- Select confidence mode: Strict, Balanced, Relaxed.
- Select maximum alerts and maximum clusters.
- Include or skip Zeek evidence.
- Background job progress polling through `/job/<job_id>`.
- Job history through `/jobs` or `/pcap/jobs`.
- Cancel queued/running analysis.
- Download report JSON.
- Download evidence ZIP when Zeek artifacts exist.
- View summary, security score, severity breakdown, top attacks, risk per IP, clusters, alerts, timeline, and raw details in the frontend.
- Persist recent PCAP alert snapshots in local storage for dashboard widgets.

Evidence:
- `Backend/app.py` `analyze_pcap`, `get_job`, `cancel_pcap_job`, `export_job_artifact`, `list_jobs`.
- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`.
- `Cybersecurity Dashboard Design/src/utils/recentPcapAlerts.ts`.

## Admin-Side Features Confirmed by Code

- PCAP overview endpoint with total jobs, queue health, latest attack families, latest files, top suspicious files, performance, engine status, and timeline.
- Admin export of PCAP report JSON and evidence ZIP.
- Admin UI preview of report JSON and export buttons.
- PCAP signals feed into high-risk users and security incidents admin calculations.

Evidence:
- `Backend/app.py` `admin_pcap_overview`, `admin_export_pcap_job_artifact`, `_pcap_admin_job_row`, `_pcap_admin_timeline_for_job`.
- `Cybersecurity Dashboard Design/src/services/adminPcapOverview.ts`.
- `Cybersecurity Dashboard Design/src/components/admin/PcapAnalysisAdminControl.tsx`.

## Fully Implemented

- Upload validation by extension and size.
- Background job registry with JSON state persistence.
- Active-job reuse/deduplication for matching owner/source/options.
- `tshark` packet export with Windows-native lookup and WSL fallback.
- CIC-like flow feature extraction from exported packet CSV.
- ML inference using a joblib model bundle.
- Heuristic feature scoring.
- Context validation and suppression.
- Report JSON creation and storage.
- User report/evidence export.
- Job cancellation with subprocess termination best effort.
- Alert persistence to `pcap_alert`.
- Admin overview and admin export.
- Cleanup scheduler for stale run artifacts/jobs.

Evidence:
- `Backend/app.py`, `Backend/pcap_engine/*.py`.

## Partially Implemented

- Zeek enrichment: implemented but optional and environment-dependent. `run_zeek` assumes WSL and `/usr/local/zeek/bin/zeek`; if Zeek fails, the pipeline continues without Zeek evidence.
- Artifact encryption: implemented only when `PCAP_PROTECT_ARTIFACTS` and `PCAP_ARTIFACT_ENCRYPTION_KEY` are configured. Otherwise skipped.
- Gamification integration: upload/download calls exist, but `reporter.py` module contract says `gamification_available: false` and `gamification_status: not_implemented`.
- Report generation center: admin report service includes PCAP report-generation/demo code, but a backend endpoint `/api/admin/reports/pcap/generate` is not confirmed in inspected PCAP route evidence.
- Network Security Score dashboard: implemented in frontend as a derived score from recent PCAP reports, separate from backend `summary.security_score`.

## Mentioned but Not Confirmed

- Suricata usage: no confirmed code usage found.
- Live/real-time network capture: no confirmed code usage. The module analyzes uploaded or local files, not live traffic.
- Raw payload inspection: no confirmed raw payload extraction. Report exposes flow metadata, Zeek metadata, DNS queries, HTTP host/URI, TLS SNI/cipher, but not full packet payloads.
- Model generalization quality beyond metrics files: cannot confirm from code.

## What ChatGPT Can Safely Write in the Graduation Book

- Sentinel AI includes a PCAP analysis module that accepts `.pcap` and `.pcapng` files and processes them asynchronously.
- The pipeline exports packet fields using `tshark`, aggregates CIC-style flow features, runs a saved ML model, applies heuristic/context validation, and creates a structured JSON report.
- The report includes summary metrics, alerts, clusters, timeline rows, risk per IP, and a module contract used by dashboards.
- Optional Zeek enrichment can add connection, DNS, HTTP, and SSL/TLS evidence when Zeek is available.
- Users can view progress, cancel active jobs, view results, and export report/evidence artifacts.
- Admins can monitor PCAP jobs and export artifacts from an admin overview.

## What ChatGPT Must Verify With External Sources

- General cybersecurity value of PCAP for network forensics.
- Why flow-based IDS reduces processing complexity.
- ML-based IDS strengths and limitations.
- False-positive challenges in IDS.
- Any academic claims about CIC-style features, XGBoost, Zeek, tshark, or IDS evaluation.

## What ChatGPT Must Ask the Project Owner

- Which dataset(s) were finally used for the trained PCAP65 model.
- Whether `metrics_pcap65.json` is the official final evaluation.
- Whether the reported accuracy and macro-F1 can be included in the book.
- Whether Zeek and Wireshark/tshark were installed and demonstrated during testing.
- Whether PCAP artifact encryption was enabled in the submitted deployment.
- Whether screenshots should show real captures or sanitized/demo captures.

## What ChatGPT Must Avoid Claiming

- Do not claim real-time detection.
- Do not claim complete protection from all network threats.
- Do not claim Suricata usage.
- Do not claim model quality beyond values explicitly present in metrics files.
- Do not claim raw payloads are never stored unless the owner confirms captures and Zeek logs are sanitized.
- Do not claim enterprise-grade scalability.
