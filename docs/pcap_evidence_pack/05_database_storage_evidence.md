# Database and Storage Evidence

## PCAP-Related Database Models / Tables

### `PcapAlertRecord`

Evidence: `Backend/app.py` class `PcapAlertRecord`, `__tablename__ = "pcap_alert"`.

Fields:
- `id`
- `user_id` foreign key to `user.id`, indexed
- `job_id`
- `alert_key`, unique
- `source_type`
- `type`
- `title`
- `message`
- `severity`
- `status`
- `risk_label`
- `threats_count`
- `flows_analyzed`
- `top_pattern`
- `filename`
- `attack_type`
- `protocol`
- `src_ip`
- `dst_ip`
- `event_at`
- `metadata_json`
- `dismissed_at`
- `created_at`

What it proves:
- PCAP alerts are persisted in DB and scoped to `user_id`.
- Dismissal state is persisted through `dismissed_at`.
- Job linkage exists through `job_id`.

### `UserActivityLog`

Evidence: `Backend/app.py` references `_log_pcap_analysis_activity`, `log_user_event`, `MODULE_PCAP`.

PCAP actions include:
- `pcap_uploaded`
- `pcap_analysis_started`
- `pcap_reanalysis_started`
- `pcap_analysis_completed`
- `pcap_analysis_failed`
- `pcap_analysis_cancel_requested`
- `pcap_analysis_cancelled`
- `pcap_report_downloaded`
- `pcap_evidence_downloaded`
- `security_alert_dismissed`
- `security_alerts_cleared`

What it proves:
- PCAP user activity/audit-style logging exists.

### `UserNotification`

Evidence: `Backend/app.py` `UserNotification` model; PCAP job notification helper calls such as `_create_job_started_notification`, `_notify_job_success`, `_notify_job_failure`.

What it proves:
- PCAP job events can generate user notifications.

## Job Storage

Evidence:
- `Backend/pcap_engine/jobs.py` `JobRegistry`.
- `Backend/app.py` `JOBS_FOLDER = os.path.join(BASE_RUN_FOLDER, "_jobs")`.

Stored on disk:
- Each job folder contains `state.json`.
- Completed jobs write `report.json`.
- `JobState` includes `upload_path`, `packet_csv_path`, `report_path`, `evidence_dir`, `file_hash`, `artifact_protection`, cancellation fields.

## File Storage Paths

Evidence:
- `Backend/app.py` `BASE_RUN_FOLDER = os.getenv("PCAP_RUN_FOLDER", str(BASE_DIR / "pcap_runs"))`.
- Uploads saved as UUID filenames in `BASE_RUN_FOLDER`.
- Packet CSV saved as UUID `_packets.csv` in `BASE_RUN_FOLDER`.
- Job state/report saved in `BASE_RUN_FOLDER/_jobs/<job_id>/`.
- Zeek run folders created under `BASE_RUN_FOLDER`.

## Report Storage

Reports are stored as JSON files, not as a dedicated PCAP report DB table.

Evidence:
- `Backend/pcap_engine/jobs.py` writes `report.json`.
- `Backend/app.py` `_collect_job_export_artifacts` finds report file.
- `Backend/app.py` `get_job` reads report JSON inline when job is done.

PCAP alert summaries/details are also persisted to DB as `PcapAlertRecord`.

## Uploaded PCAP Persistence

Uploaded PCAPs are initially stored under `BASE_RUN_FOLDER` with UUID names. They are not immediately deleted after successful analysis unless artifact protection or cleanup later removes/encrypts them.

Evidence:
- `Backend/app.py` `analyze_pcap` saves `upload_path`.
- `Backend/pcap_engine/cleanup.py` deletes stale artifacts after retention.
- `Backend/app.py` `_protect_pcap_artifacts_after_terminal_state` can encrypt/delete original PCAP when enabled.

## Cleanup / Deletion Behavior

Evidence:
- `Backend/pcap_engine/cleanup.py`.
- `Backend/app.py` starts cleanup scheduler with `ARTIFACT_RETENTION_HOURS`, `JOB_RETENTION_HOURS`, `CLEANUP_INTERVAL_MINUTES`.

Behavior:
- Protects queued/running jobs.
- Deletes stale `.pcap`, `.pcapng`, `.csv`, `.zip`, temp files under base run folder.
- Deletes stale evidence bundles.
- Deletes stale terminal job folders with status `done` or `error`.

Limitation:
- Cleanup terminal statuses in `cleanup.py` are `done` and `error`; cleanup of `cancelled` job folders is not clearly confirmed.

## Admin Access

Admin endpoints read all recent jobs through `jobs.list_recent(limit=0)`.

Evidence:
- `Backend/app.py` `admin_pcap_overview`.
- `Backend/app.py` `admin_export_pcap_job_artifact`.

## Ownership

Evidence:
- `Backend/app.py` `_pcap_job_matches_context`.
- Authenticated users must match both `owner_user_id` and `owner_user_scope`.
- Unauthenticated/local-style context uses `owner_client_id`.

Safe wording:
- User PCAP jobs and alerts are owner-scoped in backend route checks.
