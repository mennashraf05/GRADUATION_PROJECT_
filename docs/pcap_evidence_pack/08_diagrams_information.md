# PCAP Diagram Information

Do not draw final diagrams here. Use these elements later.

## PCAP Architecture Diagram

Actors:
- Authenticated user
- Admin user

Components:
- React `PcapAnalyzerPage`
- React dashboard widgets: Network Security Score, Recent Alerts
- React admin `PcapAnalysisAdminControl`
- Flask `app.py` PCAP routes
- `JobRegistry`
- `pcap_runs` storage
- `tshark_runner`
- `cic_stream_features`
- `ml_infer`
- `heuristics` / `security_logic` / `scorer`
- optional `zeek_runner` / `zeek_loader`
- `reporter`
- SQLite/SQLAlchemy `pcap_alert`, activity logs, notifications

Data flows:
- User uploads PCAP to Flask.
- Flask stores file and creates job.
- Background job exports packets, extracts features, predicts labels, scores, builds report.
- Job state/report stored as JSON.
- Alert records stored in DB.
- Frontend polls job and displays report.
- Admin overview reads jobs/reports and exports artifacts.

## PCAP Sequence Diagram

Lifelines:
- User browser
- Flask `/analyze-pcap`
- `JobRegistry`
- Background worker
- `tshark`
- ML model bundle
- optional Zeek
- Report storage
- Alert DB

Sequence:
1. User selects file/options and posts multipart upload.
2. Backend validates and saves UUID PCAP.
3. Backend creates or reuses active job.
4. Backend returns `202 job_id`.
5. Worker starts, updates status.
6. Worker runs `tshark` to CSV.
7. Worker builds CIC features.
8. Worker runs ML inference.
9. Worker applies heuristics/context scoring.
10. Optional Zeek evidence is merged if available.
11. Worker builds report and writes `report.json`.
12. Worker updates job status done.
13. Backend persists alert records.
14. Frontend polls `/job/<id>` and receives inline report.
15. User exports report/evidence.

## PCAP DFD Level 0

External entities:
- User
- Admin

Process:
- PCAP Analysis System

Data stores:
- PCAP run artifacts
- Job state/report JSON files
- PCAP alerts table
- Activity/admin audit logs

Flows:
- PCAP upload/options from user.
- Report/status/export to user.
- Job overview/export to admin.
- Alerts to dashboard.

## PCAP DFD Level 1

Processes:
- Validate upload/local path
- Create/reuse job
- Export packet fields
- Build flow features
- Predict ML labels
- Apply heuristics and validation
- Optional Zeek enrichment
- Generate report
- Persist alerts/logs
- Export artifacts
- Cleanup stale files

Stores:
- `BASE_RUN_FOLDER`
- `_jobs/<job_id>/state.json`
- `_jobs/<job_id>/report.json`
- `pcap_alert`
- activity/admin logs

## PCAP State Diagram

States:
- Idle/no job
- Queued
- Running
- Done
- Error
- Cancelled

Transitions:
- Upload accepted -> Queued
- Worker starts -> Running
- Pipeline succeeds -> Done
- Pipeline exception -> Error
- Cancel requested from Queued/Running -> Cancelled
- Export allowed only from Done
- Polling occurs during Queued/Running

Evidence: `JobState.status`, `JobRegistry.submit`, `request_cancel`, `get_job`.

## PCAP Use Case Diagram

User use cases:
- Upload PCAP
- Configure analysis options
- Start analysis
- Monitor progress
- Cancel analysis
- View results
- Inspect alerts/clusters/timeline/risk per IP
- Download report
- Download evidence bundle
- View dashboard alerts
- Clear/dismiss alerts

Admin use cases:
- View PCAP overview
- Monitor queue health
- Inspect latest files/suspicious files
- Preview report
- Export report
- Export evidence bundle
- Review PCAP in audit/high-risk/security incident context

## PCAP ERD Entities

Entities:
- `User`
- `PcapAlertRecord`
- `UserActivityLog`
- `UserNotification`
- `AdminNotificationRead`
- `MonthlySecurityReport` indirectly includes PCAP monthly summaries

Relationships:
- `User.id` -> `PcapAlertRecord.user_id`
- `PcapAlertRecord.job_id` links DB alerts to filesystem job state/report
- `User.id` -> user activity and notifications

Note: `JobState` is not a DB table; it is JSON persisted on disk.
