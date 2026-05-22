# PCAP API Contract Evidence

## `POST /analyze-pcap` and `POST /pcap/analyze`

- Auth: required user PCAP context.
- Request type: `multipart/form-data`.
- Required: `file`.
- Optional form fields: `include_zeek`, `confidence_mode`, `max_alerts`, `max_clusters`.
- Safe request structure:

```text
file=<capture.pcap>
include_zeek=true
confidence_mode=Balanced
max_alerts=200
max_clusters=100
```

- Success: `202`, fields `job_id`, `status`, `poll`; may include `reused`.
- Errors: `400` no file, invalid type; `413` too large; `500` generic exception.
- Backend function: `analyze_pcap`.
- Frontend: `PcapAnalyzerPage.tsx` `startAnalysis`.

## `POST /analyze-local` and `POST /pcap/analyze-local`

- Auth: required user PCAP context.
- Request type: JSON.
- Required: `pcap_path`.
- Optional: `include_zeek`, `confidence_mode`, `max_alerts`, `max_clusters`.
- Safe request:

```json
{
  "pcap_path": "path-inside-allowed-root/example.pcap",
  "include_zeek": true,
  "confidence_mode": "Balanced"
}
```

- Success: `202`, fields `job_id`, `status`, `poll`.
- Errors: `400` missing/path not found/invalid path; `403` outside allowed root; `500`.
- Backend function: `analyze_local`.
- Frontend: no confirmed main UI call.

## `GET /job/<job_id>`, `/pcap/status/<job_id>`, `/pcap/result/<job_id>`

- Auth: job owner required.
- Request type: path param.
- Success fields: `job_id`, `status`, `created_at`, `started_at`, `finished_at`, `progress`, `message`, `error`, `upload_path`, `upload_name`, `report_path`, `report_available`, `evidence_available`, `artifact_protection`; `report` inline when done; `poll_after_ms` for active jobs.
- Errors: `404` job not found; `403` forbidden.
- Backend function: `get_job`.
- Frontend: `PcapAnalyzerPage.tsx` polling; `networkSecurityScore.ts`.

## `GET /jobs` and `/pcap/jobs`

- Auth: owner context.
- Query: `limit` optional.
- Success: `{ "jobs": [...], "count": n }`.
- Job item fields include `job_id`, `status`, timestamps, `progress`, `message`, `upload_name`, `upload_path`, `report_path`, `report_available`, `evidence_available`, `artifact_protection`, `error`.
- Backend: `list_jobs`.
- Frontend: `PcapAnalyzerPage.tsx` history; `networkSecurityScore.ts`.

## `POST /api/pcap/cancel/<job_id>` and `/pcap/cancel/<job_id>`

- Auth: job owner required.
- Request type: no body required.
- Success: `ok`, `status`, `message`, `process_terminated`.
- Possible non-error statuses: already done/failed/cancelled returns explanatory payload.
- Errors: `404`, `403`, `500`.
- Backend: `cancel_pcap_job`.
- Frontend: `PcapAnalyzerPage.tsx` `cancelPcapAnalysis`.

## `GET /pcap/report/<job_id>` and `/job/<job_id>/export`

- Auth: job owner required.
- Query for `/job/<id>/export`: `type=report|evidence|bundle`.
- Success:
  - report: JSON attachment `pcap_report_<job_id>.json`.
  - evidence/bundle: ZIP attachment `pcap_evidence_<job_id>.zip`.
- Errors: `400` invalid export type; `409` job not completed; `404` missing report/evidence.
- Backend: `export_job_artifact`.
- Frontend: `PcapAnalyzerPage.tsx` `downloadJobArtifact`.

## `GET /api/pcap/alerts` and `/pcap/alerts`

- Auth: user context.
- Query: `limit` optional, `include_dismissed` optional.
- Success: `alerts`, `count`, `limit`, `source`, `user_id`, `scope`, `include_dismissed`.
- Backend: `list_pcap_alerts`.
- Frontend: `RecentSecurityAlertsPanel.tsx`.

## `POST /api/pcap/alerts/clear`, `/api/pcap/alerts/dismiss-visible`, `/pcap/alerts/clear`, `/pcap/alerts/dismiss-visible`

- Auth: user context.
- Request type: JSON.
- Required: either `alert_ids` list or `dismiss_all_visible: true`.
- Success: `ok`, `dismissed_count`, `skipped_count`, `skipped_reasons`, `message`.
- Errors: `400` invalid body/no IDs; ownership violations are counted as skipped/unavailable.
- Backend: `dismiss_visible_pcap_alerts`.
- Frontend: `RecentSecurityAlertsPanel.tsx`.

## `GET /api/admin/pcap/overview`

- Auth: admin only.
- Query: `limit` optional, normalized to 20-250 range.
- Success fields: `success`, `summary`, `queue_health`, `latest_attack_families`, `top_suspicious_files`, `latest_files`, `performance`, `engine_status`, `timeline`, `generated_at`.
- Backend: `admin_pcap_overview`.
- Frontend: `adminPcapOverview.ts`, `PcapAnalysisAdminControl.tsx`.

## `GET /api/admin/pcap/jobs/<job_id>/export`

- Auth: admin only.
- Query: `type=report|evidence|bundle`.
- Success: report JSON or evidence ZIP.
- Errors: `404`, `400`, `409`.
- Backend: `admin_export_pcap_job_artifact`.
- Frontend: `PcapAnalysisAdminControl.tsx`.
