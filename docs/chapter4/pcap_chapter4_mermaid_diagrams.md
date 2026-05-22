# Chapter 4: System Design — PCAP Analysis Module

## Code Evidence Summary

### Backend files analyzed
- `Backend/app.py`
- `Backend/activity_logs.py`
- `Backend/pcap_engine/jobs.py`
- `Backend/pcap_engine/tshark_runner.py`
- `Backend/pcap_engine/cic_stream_features.py`
- `Backend/pcap_engine/ml_infer.py`
- `Backend/pcap_engine/heuristics.py`
- `Backend/pcap_engine/scorer.py`
- `Backend/pcap_engine/reporter.py`
- `Backend/pcap_engine/zeek_runner.py`
- `Backend/pcap_engine/zeek_loader.py`
- `Backend/pcap_engine/flow_features.py`
- `Backend/pcap_engine/security_logic.py`
- `Backend/pcap_engine/cleanup.py`
- `Backend/gamification/models.py`
- `Backend/reports/monthly_security_report_service.py`
- `Backend/reports/monthly_security_report_renderer.py`

### Frontend files analyzed
- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`
- `Cybersecurity Dashboard Design/src/components/pages/ChatbotWorkspacePage.tsx`
- `Cybersecurity Dashboard Design/src/components/admin/PcapAnalysisAdminControl.tsx`
- `Cybersecurity Dashboard Design/src/components/admin/ReportsExportCenterPage.tsx`
- `Cybersecurity Dashboard Design/src/services/adminPcapOverview.ts`
- `Cybersecurity Dashboard Design/src/services/adminReportsService.ts`
- `Cybersecurity Dashboard Design/src/utils/recentPcapAlerts.ts`
- `Cybersecurity Dashboard Design/src/utils/pcapChartSelectors.ts`
- `Cybersecurity Dashboard Design/src/utils/activityLogs.ts`
- `Cybersecurity Dashboard Design/src/utils/gamification.ts`

### Database/model files analyzed
- `Backend/app.py` SQLAlchemy models: `User`, `UserNotification`, `AdminNotificationRead`, `PcapAlertRecord`, `MonthlySecurityReport`, `AdminAuditLog`, `SecurityAuditLog`, `RefreshToken`.
- `Backend/activity_logs.py` SQLAlchemy model: `UserActivityLog`.
- `Backend/gamification/models.py` SQLAlchemy models: `GamificationEvent`, `UserGamificationProfile`, `UserBadge`, `UserChallenge`, `GamificationDailyStat`, `UserAlertReviewState`, `InvestigationNote`.
- `Backend/pcap_engine/jobs.py` disk-persisted job state: `JobState` stored as `state.json`; not a relational database table.

### Confirmed PCAP endpoints
- `POST /pcap/analyze` and `POST /analyze-pcap`: upload `.pcap` or `.pcapng`, create/reuse job, submit background pipeline.
- `POST /pcap/analyze-local` and `POST /analyze-local`: analyze server-local PCAP path after path validation.
- `GET /pcap/jobs` and `GET /jobs`: list authorized recent jobs.
- `GET /pcap/result/<job_id>`, `GET /pcap/status/<job_id>`, and `GET /job/<job_id>`: poll job status and inline `report` when done.
- `GET /pcap/report/<job_id>` and `GET /job/<job_id>/export?type=report|evidence|bundle`: export `report.json` or Zeek evidence bundle ZIP.
- `GET /api/pcap/alerts` and `GET /pcap/alerts`: list persisted user-visible PCAP alert records.
- `POST /api/chatbot/pcap`: rule/context-based PCAP chatbot response using latest or selected authorized job.

### Confirmed admin endpoints
- `POST /api/admin/auth/login`, `POST /api/admin/auth/verify-2fa`, `GET /api/admin/auth/me`: admin authentication.
- `GET /api/admin/pcap/overview`: admin PCAP overview from disk-backed job registry and report artifacts.
- `GET /api/admin/pcap/jobs/<job_id>/export?type=report|evidence`: admin export of PCAP report JSON or evidence ZIP.
- `GET /api/admin/audit-logs` and `GET /api/admin/audit-logs/export`: admin audit log and CSV export.
- `GET /api/admin/reports/pcap/...` endpoints referenced by `adminReportsService.ts` are not confirmed in backend code; the frontend falls back to local generated PDF/CSV blobs.

### Confirmed database tables/models
- `user`: authentication, profile, notification preferences, 2FA/admin fields.
- `pcap_alert`: persisted PCAP alert/summary records linked to `user.id`.
- `user_activity_logs`: PCAP activity events such as upload, analysis start/completion/failure, report download, evidence download, chatbot question.
- `user_notification`: PCAP job started/completed/failed/report/evidence/suspicious/critical notifications.
- `admin_audit_log`: admin actions including PCAP export.
- `admin_notification_read`: read-state for admin notifications.
- `monthly_security_report`: monthly report payloads that can include PCAP section data.
- `gamification_event`, `user_gamification_profile`, `user_badge`, `user_challenge`, `gamification_daily_stat`, `user_alert_review_state`, `investigation_note`: gamification and investigation records used by PCAP UI/actions.
- PCAP job records are not a SQL table; they are `JobState` JSON files under `Backend/pcap_runs/_jobs/<job_id>/state.json`, with `report.json` in the same job folder.

### Confirmed frontend pages/components
- `PcapAnalyzerPage`: upload, poll, report normalization, report/evidence export, history, charts, alert/cluster/timeline views.
- `ChatbotWorkspacePage`: PCAP mode posts to `/api/chatbot/pcap` with optional `analysis_id`.
- `PcapAnalysisAdminControl`: admin PCAP operations dashboard, overview loading, JSON summary export, report/evidence artifact export.
- `ReportsExportCenterPage`: admin reports UI for PCAP and Identity reports; PCAP report generation/export uses partially connected backend URLs and local fallback PDF/CSV generation.

### Confirmed job statuses
- `queued`
- `running`
- `done`
- `error`
- `failed` is normalized to `error` in `Backend/pcap_engine/jobs.py`; the React page maps `error` to UI status `failed`.

### Confirmed report/export features
- Report artifact: `report.json`, returned/downloaded as `application/json`.
- Evidence artifact: `evidence_bundle.zip`, available only when Zeek evidence files exist.
- Report fields from `Backend/pcap_engine/reporter.py`: `meta`, `summary`, `module_contract`, `risk_per_ip`, `clusters`, `alerts`, `timeline`.
- Alert fields include flow-level `type`, `ts`, `src_ip`, `dst_ip`, `dst_port`, `ml_label`, `ml_confidence`, `classification_confidence`, `confidence`, `threat_confidence`, `severity`, `reason`, Zeek evidence fields, DNS/HTTP/SSL summary fields, and heuristic details.
- Admin backend exports only report JSON and evidence ZIP for PCAP jobs. Admin PDF/CSV report exports in `adminReportsService.ts` are frontend fallback behavior, not confirmed backend PCAP report endpoints.

### Confirmed chatbot features
- `POST /api/chatbot/pcap` is implemented.
- Chatbot context is built from authorized user-owned jobs and `report.json`.
- Responses are rule/intent based via `_pcap_chatbot_intent()` and `_pcap_chatbot_answer()`.
- Context fields include selected/latest job, summary, threat items, attack counts, severity counts, top IPs, protocols, ports, recommendations, and total user jobs.
- Chatbot activity is recorded as `pcap_chatbot_question` in `user_activity_logs` when a user is authenticated.

### Missing or uncertain parts
- A relational `pcap_jobs` table is not confirmed from code; PCAP jobs are file-backed JSON state.
- Backend PDF export for PCAP job reports is not confirmed from code.
- Backend CSV export for PCAP job reports is not confirmed from code.
- Frontend `/api/admin/reports/pcap/generate`, `/api/admin/reports/pcap/<id>/export`, and `/api/admin/reports/pcap/<id>/regenerate` are planned / not confirmed from backend code.
- Raw packet payload storage inside reports is not confirmed from code; reports use derived flow, alert, cluster, timeline, and evidence summary fields.
- Zeek is optional and controlled by `include_zeek`; evidence ZIP is unavailable when Zeek files are absent.

## 4.1 Sequence Diagrams

### User PCAP Upload and Analysis Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as PcapAnalyzerPage.tsx
    participant API as POST /analyze-pcap or /pcap/analyze
    participant Auth as require_full_auth_user + JWT/cookies
    participant Jobs as JobRegistry (state.json)
    participant Pipeline as run_pcap_pipeline()
    participant Tshark as run_tshark_export()
    participant CIC as build_cic_features_from_tshark_csv()
    participant ML as run_ml_inference()
    participant Heuristics as apply_heuristics / fuse_scores
    participant Zeek as optional run_zeek + load_conn/dns/http/ssl
    participant Reporter as build_report()
    participant DB as SQLAlchemy activity/notification/alert tables

    User->>UI: Select .pcap/.pcapng and click analyze
    UI->>API: multipart file, include_zeek, confidence_mode, max_alerts, max_clusters
    API->>Auth: Resolve authenticated PCAP request context
    Auth-->>API: User id and owner scope or 401
    API->>API: Validate extension and size, save file under pcap_runs
    API->>Jobs: create_or_reuse_active(upload_path, owner_user_id, owner_user_scope, dedupe analysis key)
    Jobs-->>API: JobState status queued
    API->>DB: Log pcap_uploaded and pcap_analysis_started
    API->>DB: Record gamification upload and job started notification
    API->>Jobs: submit background pipeline
    API-->>UI: 202 {job_id, status: queued, poll: /job/{job_id}}
    Jobs->>Pipeline: Run background job and set status running
    Pipeline->>Tshark: Export packets to *_packets.csv
    Pipeline->>CIC: Build CIC flow features
    Pipeline->>ML: Predict labels/confidence with threat_model_pcap65
    Pipeline->>Heuristics: Build base detection frame and score/validate
    alt include_zeek true
        Pipeline->>Zeek: Run Zeek in parallel and load conn/dns/http/ssl evidence
        Zeek-->>Pipeline: Evidence dataframes or empty evidence
        Pipeline->>Heuristics: Merge evidence and re-fuse scores
    else include_zeek false
        Pipeline->>Heuristics: Continue base-only scoring
    end
    Pipeline->>Reporter: Build report meta, summary, module_contract, risk_per_ip, clusters, alerts, timeline
    Reporter-->>Jobs: report dict
    Jobs->>Jobs: Write report.json and update status done
    Jobs->>DB: Success callback persists PCAP alerts/summary and notifications
```

### User Viewing PCAP Report Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as PcapAnalyzerPage.tsx
    participant API as GET /job/{job_id}
    participant Auth as require_full_auth_user + owner scope check
    participant Jobs as JobRegistry
    participant FS as state.json/report.json/evidence files
    participant UIState as React report/charts/details state

    User->>UI: Open active job or history item
    UI->>API: GET /job/{job_id} with Authorization/cookies
    API->>Auth: Resolve authenticated PCAP context
    Auth-->>API: User context
    API->>Jobs: jobs.get(job_id)
    Jobs->>FS: Load state.json if not in memory
    Jobs-->>API: JobState
    API->>API: _pcap_job_matches_context(owner_user_id + owner_user_scope)
    alt job not owned by user
        API-->>UI: 403 Forbidden
    else queued or running
        API-->>UI: status, progress, message, poll_after_ms, Retry-After
        UI->>UI: Continue polling and update progress step
    else done with report_path
        API->>FS: Read report.json
        API-->>UI: status done, report_available, evidence_available, report object
        UI->>UIState: normalizeReport(meta, summary, alerts, clusters, risk_per_ip, timeline)
        UI->>UIState: Render summary cards, security score, severity charts, alerts, clusters, timeline
        UI->>UIState: Persist recent alert/report snapshot for dashboard utilities
    else error
        API-->>UI: status error, summarized error
        UI->>UIState: Show failure state
    end
```

### User Report and Evidence Export Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as PcapAnalyzerPage.tsx
    participant API as GET /job/{job_id}/export
    participant Auth as require_full_auth_user + owner check
    participant Jobs as JobRegistry
    participant FS as report.json / evidence_bundle.zip
    participant DB as user_activity_logs + gamification

    User->>UI: Click Report JSON or Evidence ZIP
    UI->>API: GET /job/{job_id}/export?type=report or evidence
    API->>Auth: Resolve authenticated PCAP context
    API->>Jobs: Load authorized JobState
    API->>API: Require status == done
    alt type report
        API->>FS: Locate report.json
        API->>DB: Log pcap_report_downloaded and report_accessed gamification
        API-->>UI: application/json attachment pcap_report_{job_id}.json
    else type evidence or bundle
        API->>FS: Build evidence_bundle.zip from report.json, state.json, Zeek logs
        API->>DB: Log pcap_evidence_downloaded and evidence_accessed gamification
        API-->>UI: application/zip attachment pcap_evidence_{job_id}.zip
    else unavailable
        API-->>UI: 404 or 409 error
    end
    UI->>User: Browser downloads artifact
```

### Admin PCAP Overview and Artifact Export Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant AdminUI as PcapAnalysisAdminControl / ReportsExportCenterPage
    participant AuthAPI as /api/admin/auth/login or verify-2fa
    participant AdminAPI as GET /api/admin/pcap/overview
    participant ExportAPI as GET /api/admin/pcap/jobs/{job_id}/export
    participant Auth as admin_auth_required
    participant Jobs as JobRegistry
    participant FS as state.json/report.json/evidence_bundle.zip
    participant Audit as admin_audit_log

    Admin->>AuthAPI: Sign in with admin credentials and optional 2FA
    AuthAPI-->>AdminUI: Admin token
    AdminUI->>AdminAPI: GET overview with Authorization Bearer token
    AdminAPI->>Auth: Validate admin token/scope
    AdminAPI->>Jobs: list_recent()
    Jobs->>FS: Load state.json and report.json for recent jobs
    AdminAPI-->>AdminUI: summary, queue_health, latest_attack_families, top_suspicious_files, latest_files, performance, engine_status, timeline
    Admin->>AdminUI: Export selected job report or evidence
    AdminUI->>ExportAPI: GET /api/admin/pcap/jobs/{job_id}/export?type=report|evidence
    ExportAPI->>Auth: admin_auth_required
    ExportAPI->>Jobs: jobs.get(job_id)
    alt report export
        ExportAPI->>FS: Send report.json
        ExportAPI->>Audit: log_admin_action report_exported
        ExportAPI-->>AdminUI: application/json attachment
    else evidence export
        ExportAPI->>FS: Build/send evidence_bundle.zip
        ExportAPI->>Audit: log_admin_action report_exported
        ExportAPI-->>AdminUI: application/zip attachment
    end
    Note over AdminUI: Backend PDF/CSV export for PCAP reports is not confirmed from code. ReportsExportCenterPage has local fallback PDF/CSV generation.
```

### PCAP Chatbot Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant ChatUI as ChatbotWorkspacePage.tsx
    participant API as POST /api/chatbot/pcap
    participant Auth as optional get_current_user()
    participant Jobs as JobRegistry
    participant FS as report.json
    participant Bot as _pcap_chatbot_context + _pcap_chatbot_answer
    participant DB as user_activity_logs

    User->>ChatUI: Ask a PCAP question
    ChatUI->>API: JSON {message, analysis_id?, include_latest_analysis:true}
    API->>Auth: Try to resolve authenticated user
    Auth-->>API: User or None
    API->>Bot: Build context
    alt authenticated user and analysis_id supplied
        Bot->>Jobs: jobs.get(analysis_id)
        Jobs->>FS: Load state/report if needed
        Bot->>Bot: Require owner_user_id + owner_user_scope match
    else authenticated user and no analysis_id
        Bot->>Jobs: list_recent()
        Bot->>FS: Load latest owned completed report if available
    else no authenticated user
        Bot->>Bot: Empty context
    end
    Bot->>Bot: Detect intent and answer from stored summary/threat context or generic PCAP knowledge
    alt user authenticated
        API->>DB: Log pcap_chatbot_question
    end
    API-->>ChatUI: {answer, mode:"pcap", analysis_id, context_used, context}
    ChatUI-->>User: Render assistant answer
```

## 4.2 Entity Relationship Diagram ERD

```mermaid
erDiagram
    USER {
        int id PK
        string email UK
        string full_name
        string phone
        string job_title
        string company
        boolean is_email_verified
        boolean email_notifications_enabled
        boolean telegram_notifications_enabled
        boolean is_two_factor_enabled
        string admin_role
        string admin_status
        datetime created_at
        datetime last_login_at
    }

    PCAP_ALERT {
        int id PK
        int user_id FK
        string job_id
        string alert_key UK
        string source_type
        string type
        string title
        text message
        string severity
        string status
        string risk_label
        int threats_count
        int flows_analyzed
        string filename
        string attack_type
        string protocol
        string src_ip
        string dst_ip
        datetime event_at
        text metadata_json
        datetime created_at
    }

    USER_ACTIVITY_LOGS {
        int id PK
        string event_id UK
        int user_id FK
        string module
        string action_type
        string title
        text description
        string status
        string severity
        int risk_score
        string target_type
        string target_id
        string target_label
        string ip_address
        boolean is_sensitive
        boolean is_suspicious
        datetime created_at
        text metadata_json
    }

    USER_NOTIFICATION {
        int id PK
        int user_id FK
        string type
        string severity
        string title
        text body
        string job_id
        boolean is_read
        datetime created_at
    }

    MONTHLY_SECURITY_REPORT {
        int id PK
        int user_id FK
        string report_month
        int report_year
        text report_payload_json
        string pdf_path
        string status
        datetime created_at
    }

    ADMIN_AUDIT_LOG {
        int id PK
        int actor_user_id
        string actor_name
        string actor_email
        string actor_role
        string action_type
        string action_label
        string module
        string target_type
        string target_id
        string target_label
        string status
        string severity
        datetime created_at
    }

    ADMIN_NOTIFICATION_READ {
        int id PK
        string admin_email
        string notification_key
        datetime read_at
    }

    GAMIFICATION_EVENT {
        int id PK
        int user_id FK
        string event_type
        string event_key UK
        string job_id
        string alert_id
        int points_awarded
        datetime created_at
    }

    USER_GAMIFICATION_PROFILE {
        int user_id PK
        int total_points
        int current_level
        string current_level_name
        int current_streak
        int total_scans
        int total_reviewed_alerts
        int total_badges
        datetime updated_at
    }

    USER_ALERT_REVIEW_STATE {
        int id PK
        int user_id FK
        string job_id
        string alert_id
        string review_status
        string disposition
        datetime first_viewed_at
        datetime reviewed_at
        datetime updated_at
    }

    INVESTIGATION_NOTE {
        int id PK
        int user_id FK
        string job_id
        string alert_id
        text note_body
        datetime created_at
    }

    PCAP_JOB_STATE {
        string job_id PK
        string status
        string created_at
        string started_at
        string finished_at
        int progress
        string message
        int owner_user_id
        string owner_user_scope
        string upload_path
        string packet_csv_path
        string report_path
        string evidence_dir
        string error
    }

    USER ||--o{ PCAP_ALERT : owns
    USER ||--o{ USER_ACTIVITY_LOGS : records
    USER ||--o{ USER_NOTIFICATION : receives
    USER ||--o{ MONTHLY_SECURITY_REPORT : has
    USER ||--o{ GAMIFICATION_EVENT : earns
    USER ||--|| USER_GAMIFICATION_PROFILE : has
    USER ||--o{ USER_ALERT_REVIEW_STATE : reviews
    USER ||--o{ INVESTIGATION_NOTE : writes
    PCAP_JOB_STATE ||--o{ PCAP_ALERT : "linked by job_id file backed not FK"
    PCAP_JOB_STATE ||--o{ USER_NOTIFICATION : "linked by job_id (not FK)"
    PCAP_JOB_STATE ||--o{ GAMIFICATION_EVENT : "linked by job_id (not FK)"
    PCAP_JOB_STATE ||--o{ USER_ALERT_REVIEW_STATE : "linked by job_id (not FK)"
    PCAP_JOB_STATE ||--o{ INVESTIGATION_NOTE : "linked by job_id (not FK)"
```

Notes:
- PCAP jobs are file-backed `JobState` JSON records, not a relational table.
- `PCAP_JOB_STATE` is inferred from `Backend/pcap_engine/jobs.py` dataclass and disk JSON access code, not from an ORM model.
- `pcap_alert.job_id`, `user_notification.job_id`, gamification/review/note `job_id` fields are string links to file-backed job IDs, not declared foreign keys.

## 4.3 Data Flow Diagrams

### DFD Level 0: PCAP Analysis Module Context

```mermaid
flowchart LR
    User["User"]
    Admin["Admin"]
    PCAP["PCAP Analysis Module"]
    Auth["Auth/JWT and User/Admin Context"]
    Store["SQLAlchemy DB Tables"]
    Files["pcap_runs files: PCAP, packet CSV, state.json, report.json, evidence ZIP"]
    Tools["tshark, optional Zeek, ML model, heuristics/scorer"]
    Chat["PCAP Chatbot"]
    UI["React PCAP/Admin/Chatbot UI"]

    User -->|"Upload PCAP, poll job, view/export report"| UI
    Admin -->|"Monitor jobs, export artifacts"| UI
    UI -->|"Authenticated HTTP requests"| PCAP
    PCAP --> Auth
    Auth --> PCAP
    PCAP -->|"Persist activities, alerts, notifications, audit, gamification"| Store
    PCAP -->|"Save/load job and artifacts"| Files
    PCAP -->|"Run analysis pipeline"| Tools
    Tools -->|"Packet CSV, features, predictions, evidence, scores"| PCAP
    PCAP -->|"Status/report/export payloads"| UI
    UI -->|"PCAP question + optional analysis_id"| Chat
    Chat -->|"POST /api/chatbot/pcap"| PCAP
    PCAP -->|"Contextual answer"| Chat
    Chat --> User
```

### DFD Level 1: Implemented PCAP Processing

```mermaid
flowchart TD
    U["User / PcapAnalyzerPage"]
    A1["1. Authenticate PCAP request<br/>require_full_auth_user()"]
    A2["2. Validate and store PCAP<br/>/analyze-pcap or /pcap/analyze"]
    A3["3. Create/reuse JobState<br/>JobRegistry"]
    A4["4. Background pipeline<br/>run_pcap_pipeline()"]
    A5["5. tshark packet export<br/>*_packets.csv"]
    A6["6. CIC feature extraction<br/>build_cic_features_from_tshark_csv()"]
    A7["7. ML inference<br/>run_ml_inference()"]
    A8["8. Heuristic/scoring fusion<br/>base frame + fuse_scores()"]
    A9["9. Optional Zeek enrichment<br/>conn,dns,http,ssl evidence"]
    A10["10. Report generation<br/>build_report()"]
    A11["11. Persist results<br/>report.json, state.json, pcap_alert, notifications"]
    A12["12. Poll/report/export responses<br/>/job/&lt;id&gt;, /job/&lt;id&gt;/export"]
    DB[("SQLAlchemy DB")]
    FS[("pcap_runs folder")]
    Model[("threat_model_pcap65.pkl and metrics")]

    U --> A1
    A1 --> A2
    A2 --> FS
    A2 --> A3
    A3 --> FS
    A3 --> DB
    A3 --> A4
    A4 --> A5
    A5 --> FS
    A5 --> A6
    A6 --> A7
    A7 --> Model
    A7 --> A8
    A8 --> A9
    A9 --> FS
    A9 --> A10
    A8 --> A10
    A10 --> A11
    A11 --> FS
    A11 --> DB
    A12 --> FS
    A12 --> DB
    U --> A12
    A12 --> U
```

## 4.4 State Diagram

```mermaid
stateDiagram-v2
    [*] --> queued: JobRegistry.create_or_reuse_active()
    queued --> running: jobs.submit() runner starts
    running --> running: progress/message updates; export, features, ML, Zeek, scoring, report
    running --> done: pipeline returns report and report.json is written
    running --> error: exception during pipeline
    done --> [*]: report/evidence available for polling/export
    error --> [*]: summarized error returned

    note right of queued
      Persisted in state.json.
      Status values confirmed:
      queued, running, done, error.
    end note

    note right of error
      "failed" is normalized to "error"
      in JobRegistry; frontend maps error
      to failed for display.
    end note
```

## 4.5 Use Case Diagrams

### User PCAP Use Cases

```mermaid
flowchart LR
    User((User))
    Auth((Authenticated Session))

    UC1["Upload PCAP file"]
    UC2["Start local-path analysis"]
    UC3["Poll job status"]
    UC4["View report dashboard"]
    UC5["Download report JSON"]
    UC6["Download evidence ZIP"]
    UC7["View recent jobs"]
    UC8["View recent PCAP alerts"]
    UC9["Ask PCAP chatbot question"]
    UC10["Trigger gamification/activity tracking"]

    User --> UC1
    User --> UC2
    User --> UC3
    User --> UC4
    User --> UC5
    User --> UC6
    User --> UC7
    User --> UC8
    User --> UC9

    UC1 -. requires .-> Auth
    UC2 -. requires .-> Auth
    UC3 -. requires owner match .-> Auth
    UC4 -. includes .-> UC3
    UC5 -. requires completed job .-> UC3
    UC6 -. requires completed job and Zeek evidence .-> UC3
    UC9 -. uses latest/selected owned job when authenticated .-> Auth
    UC1 -. records .-> UC10
    UC4 -. records .-> UC10
    UC5 -. records .-> UC10
    UC6 -. records .-> UC10
```

### Admin PCAP Use Cases

```mermaid
flowchart LR
    Admin((Admin))
    AdminAuth((Admin JWT Scope))

    A1["Login to Admin Console"]
    A2["Verify admin 2FA when required"]
    A3["View PCAP admin overview"]
    A4["Monitor queue health"]
    A5["Review latest files"]
    A6["Review top suspicious files"]
    A7["Review attack families"]
    A8["Export PCAP report JSON"]
    A9["Export PCAP evidence ZIP"]
    A10["Export admin summary JSON from UI"]
    A11["View/export admin audit logs"]

    Admin --> A1
    A1 --> A2
    A2 --> AdminAuth
    A1 --> AdminAuth
    Admin --> A3
    A3 -. requires .-> AdminAuth
    A3 --> A4
    A3 --> A5
    A3 --> A6
    A3 --> A7
    Admin --> A8
    Admin --> A9
    Admin --> A10
    Admin --> A11
    A8 -. requires .-> AdminAuth
    A9 -. requires .-> AdminAuth
    A11 -. requires .-> AdminAuth

    Note["Backend PCAP PDF/CSV report export not confirmed.<br/>ReportsExportCenterPage has local fallback PDF/CSV blobs."]
    Admin -.-> Note
```

## 4.6 User Interface Design Flow

### PCAP Analyzer User Interface Flow

```mermaid
flowchart TD
    Start["PcapAnalyzerPage"]
    Upload["Upload panel<br/>file input, confidence_mode, max_alerts, max_clusters, include_zeek"]
    Validate["Client validation<br/>.pcap/.pcapng and selected file"]
    StartJob["POST /analyze-pcap"]
    Poll["Polling loop<br/>GET /job/&lt;job_id&gt;"]
    Running["Running state<br/>progress, message, normalized step"]
    Done["Done state<br/>inline report object"]
    Error["Error state"]
    Normalize["normalizeReport()"]
    Dashboard["Summary and score cards"]
    Charts["Severity, threat activity, risk per IP charts"]
    Tables["Clusters, alerts, timeline tables"]
    Details["Alert/cluster detail panel"]
    History["History drawer<br/>GET /jobs?limit=50"]
    Export["Report JSON / Evidence ZIP<br/>GET /job/&lt;id&gt;/export"]
    Cache["Recent alert/report snapshot utilities"]

    Start --> Upload
    Upload --> Validate
    Validate --> StartJob
    StartJob --> Poll
    Poll --> Running
    Running --> Poll
    Poll --> Done
    Poll --> Error
    Done --> Normalize
    Normalize --> Dashboard
    Normalize --> Charts
    Normalize --> Tables
    Tables --> Details
    Done --> Cache
    Start --> History
    History --> Poll
    Done --> Export
    History --> Export
```

### Admin PCAP Interface Flow

```mermaid
flowchart TD
    AdminLogin["AdminLoginPage"]
    AdminConsole["AdminConsolePage"]
    PcapAdmin["PcapAnalysisAdminControl"]
    ReportsCenter["ReportsExportCenterPage"]
    OverviewAPI["GET /api/admin/pcap/overview"]
    OverviewUI["KPI cards, queue health, performance, engine status"]
    Latest["Latest 5 PCAP Analysis Results"]
    Suspicious["Ranked Recent PCAP Files"]
    Timeline["Admin PCAP timeline"]
    ExportAPI["GET /api/admin/pcap/jobs/&lt;job_id&gt;/export"]
    SummaryExport["Client-side admin overview JSON export"]
    ReportsFallback["Reports Center local fallback PDF/CSV<br/>Planned / not confirmed backend PCAP report endpoints"]

    AdminLogin --> AdminConsole
    AdminConsole --> PcapAdmin
    AdminConsole --> ReportsCenter
    PcapAdmin --> OverviewAPI
    OverviewAPI --> OverviewUI
    OverviewUI --> Latest
    OverviewUI --> Suspicious
    OverviewUI --> Timeline
    Latest --> ExportAPI
    Suspicious --> ExportAPI
    PcapAdmin --> SummaryExport
    ReportsCenter --> OverviewAPI
    ReportsCenter --> ReportsFallback
    ReportsCenter --> ExportAPI
```

### PCAP Chatbot UI Flow

```mermaid
flowchart TD
    ChatPage["ChatbotWorkspacePage"]
    Mode["Select PCAP Analyzer mode"]
    ContextId["Read analysis_id from current URL/search params when available"]
    Message["User enters message or quick action"]
    API["POST /api/chatbot/pcap"]
    BackendContext["Backend loads selected/latest owned JobState and report.json"]
    Intent["Rule-based intent detection"]
    Answer["Contextual answer with context summary"]
    Empty["No analysis found answer"]
    Log["pcap_chatbot_question activity log when authenticated"]

    ChatPage --> Mode
    Mode --> ContextId
    ContextId --> Message
    Message --> API
    API --> BackendContext
    BackendContext --> Intent
    Intent --> Answer
    BackendContext --> Empty
    API --> Log
    Answer --> ChatPage
    Empty --> ChatPage
```

## Manual Verification Checklist

- Confirm Mermaid renders without syntax errors in the Chapter 4 document renderer.
- Verify endpoint names against `Backend/app.py` before final submission.
- Verify job statuses remain `queued`, `running`, `done`, and `error` in `Backend/pcap_engine/jobs.py`.
- Verify `PcapAlertRecord` and `UserActivityLog` fields against current SQLAlchemy models if migrations are added later.
- Verify whether backend PCAP PDF/CSV admin report endpoints are later implemented; currently they are not confirmed from code.
- Verify Zeek evidence export availability by checking completed jobs that have `evidence_dir` with Zeek log files.
- Verify no secrets, environment values, API keys, passwords, or tokens were copied into this documentation.
