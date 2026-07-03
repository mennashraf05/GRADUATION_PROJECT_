# Phishing Scanner Documentation Pack

Inspection date: 2026-06-29

Scope: Phishing Scanner module only, including integrations with Sentinel AI. This document describes the current implemented behavior in the inspected worktree. It does not expose secrets, API keys, SMTP passwords, cookies, tokens, or raw sensitive data.

Important current-state note: the Phishing Scanner admin email integration is partially present but not correctly implemented at runtime in the phishing alert function. `send_admin_alert_email_best_effort(...)` exists in `Backend/app.py`, but `create_phishing_scanner_security_alert(...)` currently contains a misplaced Password Checker admin-email block that references undefined variables such as `severity`, `title`, `password_check_id`, `breached`, `strength_label`, and `breach_count`. The phishing alert row is committed before that block, then the exception is caught and the function returns `None`. Therefore, as currently implemented, phishing admin email sending should be considered not working/bugged, even though the shared helper exists.

## 1. Module Overview

The Phishing Scanner lets an authenticated user submit an HTTP or HTTPS URL and receive a phishing-risk result. It combines lexical URL feature extraction, a Random Forest phishing model when available, trusted-domain shortcut logic, deterministic risk scoring, and optional VirusTotal domain reputation enrichment.

It exists in Sentinel AI to reduce the chance that users open suspicious links, submit credentials to phishing pages, or ignore known malicious domains. The module gives users an immediate score, category, guidance message, scan history, and visible security ecosystem integrations.

Main users:

- Normal User: scans URLs, views results, history, and notifications.
- Admin: reviews phishing incidents through threat management, reports, recent alerts, and user activity.
- System: performs ML prediction, reputation lookup, persistence, notifications, reports, scoring, and gamification.

High-level workflow:

1. User enters a URL in `PhishingScannerPage.tsx`.
2. Frontend normalizes URLs without a scheme by prepending `https://`.
3. Frontend rejects malformed URLs before calling the backend.
4. Backend validates that the URL has scheme and network location and that scheme is `http` or `https`.
5. Backend calls `predict_url(url)`.
6. Backend converts ML probability into `risk_score` and `category`.
7. Backend calls VirusTotal domain reputation lookup.
8. Backend combines ML and VirusTotal into `final_risk_score` and `final_category`.
9. Backend saves the scan to SQLite `Backend/data/scans.db`.
10. Backend records gamification and user activity logs.
11. Backend creates an in-app notification and, for risky scans, user email where configured.
12. Backend attempts to create a reused `PcapAlertRecord` recent security alert.
13. Backend returns JSON to the frontend.
14. Frontend displays the final score, category, ML details, VirusTotal section, and refreshes history.

## 2. Implemented Features

| Feature | Implemented | Backend files/functions | Frontend files/components | API | Data stored | Important notes |
|---|---:|---|---|---|---|---|
| URL input | Yes | `scan_url()` consumes `url` | `PhishingScannerPage.tsx` input field | `POST /api/v1/scan-url` | Saved only after backend validation | User can enter `github.com` in frontend. |
| URL validation | Yes | `scan_url()` uses `urlparse`; requires scheme, netloc, `http/https` | `normalizeUrlInput()` uses `new URL()` and requires hostname with `.` | `POST /api/v1/scan-url` | Invalid URLs are not stored | Backend and frontend validation differ slightly. |
| URL normalization | Partially | Backend does not add scheme | Frontend prepends `https://` if missing | Frontend only | Normalized URL is sent/stored | Direct API callers must include scheme. |
| ML prediction | Yes | `predict_url()` in `ml.py` | Result displayed in ML panel | `POST /api/v1/scan-url` | Probability returned, but base scans table stores only final risk/result | Current model path is `Backend/data/models/rf_model.pkl`. |
| Risk score calculation | Yes | `calculate_risk()`, `category_from_score()`, `combine_ml_and_virustotal()` | Displays final score and ML score | `POST /api/v1/scan-url` | `risk` column stores final score | 0-39 safe, 40-69 suspicious, 70-100 dangerous. |
| Safe/Suspicious/Dangerous classification | Yes | `risk.py`, `scan.py` | Badges, result card, history | `POST /api/v1/scan-url`, `GET /api/v1/scans` | `result` stores final category | Notification severity differs from alert severity. |
| VirusTotal enrichment | Yes | `virustotal.py` | VirusTotal reputation panel | `POST /api/v1/scan-url` | Not in `scans` table; metadata passed to notifications/alerts | Cache is in-memory only. |
| Scan history | Yes | `get_user_scans(user_id)` | `fetchScanHistory()` and table | `GET /api/v1/scans` | SQLite `scans` | User-scoped. |
| Delete scan history | Yes | `delete_scan(scan_id, user_id)` | `handleClearHistory()` deletes each item | `DELETE /api/v1/scan/<scan_id>` | Deletes from `scans` | Frontend only implements clear-all by looping deletes; no single row UI delete. |
| Notification Center | Yes | `create_phishing_scan_notification()` and `create_user_notification()` | `NotificationCenter.tsx` | `/notifications` endpoints | `user_notification` | Created for safe, suspicious, and dangerous scans. |
| User email notification | Yes | `send_phishing_scan_email_alert()` fallback and generic notification email path | No direct UI; response includes status | `POST /api/v1/scan-url` | No separate table; side effect | Sent only for suspicious/dangerous or score >= 50 when mail/user settings allow. |
| Admin email alerts | Bugged / not working for phishing | `send_admin_alert_email_best_effort()` exists; phishing call block is wrong | Response fields exist | `POST /api/v1/scan-url` | None | Current phishing path references undefined password variables and returns `recent_alert_created=false`. |
| Recent Security Alerts | Partially yes | `create_phishing_scanner_security_alert()`, `_backfill_phishing_alert_records_for_user()` | `RecentSecurityAlertsPanel.tsx`, `recentPcapAlerts.ts` | `GET /api/pcap/alerts` | `pcap_alert` reused | Live creation commits the row, then bug causes function to return `None`; list/backfill can still surface phishing rows. |
| Threat Management | Yes, via admin feed | `_serialize_admin_pcap_threat()`, `_build_admin_threat_feed()` | `AdminConsolePage.tsx` | Admin threat endpoints | Derived from `pcap_alert`/notifications | Phishing module label and dedupe keys are supported. |
| Admin Audit Trail | Partially | Report view/export logs admin action; scan itself logs user activity | `AdminAuditTrailPage.tsx`, `UserActivityLogsPage.tsx` | Admin audit/user activity endpoints | `admin_audit_log`, `user_activity_log` | Direct user scan is not an admin audit event. |
| Reports & Export Center | Yes | `admin_phishing_incidents_report_summary()`, `admin_phishing_incidents_report_export()` | `ReportsExportCenterPage.tsx` | `/api/admin/reports/phishing-incidents` and `/export` | Reads `scans` SQLite | Backend CSV only; frontend can generate a simple PDF locally. |
| Monthly Reports | Yes | `reports.py` `_build_phishing_section()`, `build_monthly_security_report_data()` | `MonthlyReportsPage.tsx` | `/api/reports/monthly*` | `monthly_security_report` JSON/PDF | Phishing section included when monthly scans exist. |
| Security Score | Yes | `_score_phishing_module()`, `_build_security_score_payload()` | Security score UI utility consumes payload | Security score endpoints | Reads latest scan | Phishing has 25% component weight with password/vault/identity. |
| Gamification/Rewards | Yes | `_record_phishing_gamification()`, `record_phishing_scan_completion()` | Gamification components/reward history | Triggered through scan | Gamification event tables | Base scan + safe/risky event. |
| Chatbot integration | Yes | `_safe_phishing_llm_context()`, `_fallback_phishing_answer()` | `ChatbotWorkspacePage.tsx` phishing mode | `/api/chatbot/llm` | Reads scans and alert metadata | Uses safe context only. |
| User Activity Logs | Yes | `_record_phishing_activity()` | `UserActivityLogsPage.tsx` | User activity endpoints | `user_activity_log` | Module key is `phishing`. |
| Docker/environment | Yes | `docker-compose.yml`, `Dockerfile.frontend`, `.env.example` | N/A | N/A | Env vars | Docker passes `VIRUSTOTAL_API_KEY`; frontend build passes `VITE_API_BASE_URL`. |

## 3. Actors

- Normal User: submits URLs, receives result, views history, clears history, receives in-app/user email notifications.
- Admin: reviews phishing incidents in Reports & Export Center, Threat Management, Recent Security Alerts, user activity, and monthly reports.
- System: validates, predicts, enriches, stores, logs, notifies, scores, and reports.
- ML Model: Random Forest classifier loaded from `Backend/data/models/rf_model.pkl`; produces phishing probability.
- VirusTotal API: external domain reputation provider at `https://www.virustotal.com/api/v3/domains/{domain}`.
- Notification Center: displays phishing scan notifications from `user_notification`.
- Email Service: existing `MAIL_*` SMTP path sends user phishing email; admin helper exists but phishing call is bugged.
- Reports System: aggregates scan rows into admin and monthly report payloads.
- Security Dashboard / Score System: reads latest scan and converts phishing risk into security posture score.
- Admin Threat Management: receives normalized phishing alert records via reused `PcapAlertRecord`.
- Audit Trail: logs admin report view/export actions; user scan events go to user activity logs.
- Gamification System: awards points, challenges, and badges based on phishing scan events.
- Chatbot: explains latest/history/risk logic from safe stored metadata.

## 4. Backend API Endpoints

### POST `/api/v1/scan-url`

- Auth required: Yes. Uses `current_app.extensions["get_current_user"]`.
- Handler: `scan_url()` in `Backend/phishing_scanner/scan.py`.
- Request body: `{"url": "<http-or-https-url>"}`.
- Success response fields: `url`, `domain`, `ml_result`, `risk_score`, `category`, `guidance`, `virustotal`, `final_category`, `final_risk_score`, `final_guidance`, `notification_created`, `recent_alert_created`, `admin_email_alert_sent`, `admin_email_alert_reason`, `email_alert_sent`, `email_alert_reason`, `activity_logged`, `activity_log_reason`, `gamification`.
- Error responses:
  - 401: `{"success": false, "message": "Not authenticated"}`
  - 400: `{"success": false, "message": "Please enter a valid URL, for example https://github.com"}`
- Called by: `PhishingScannerPage.tsx` `handleScan()`.
- Notes: invalid URL does not call ML, VirusTotal, save, notifications, email, alert, gamification, or activity logging.

### GET `/api/v1/scans`

- Auth required: Yes.
- Handler: `get_scans()` in `scan.py`.
- Request body: none.
- Success response: array of rows with `scan_id`, `url`, `category`, `risk_score`, `timestamp`.
- Error response: 401 if not authenticated.
- Called by: `PhishingScannerPage.tsx` `fetchScanHistory()`.
- Notes: user-scoped by `user.id`.

### DELETE `/api/v1/scan/<scan_id>`

- Auth required: Yes.
- Handler: `delete_scan_route(scan_id)` in `scan.py`.
- Request body: none.
- Success response: `{"message": "Scan <scan_id> deleted"}`.
- Error response: 401 if not authenticated.
- Called by: `PhishingScannerPage.tsx` `handleClearHistory()` once per history row.
- Notes: deletion is scoped by both scan id and user id.

### GET `/api/admin/reports/phishing-incidents`

- Auth required: Yes, `@admin_auth_required`.
- Handler: `_admin_phishing_incidents_report_summary_early()` -> `admin_phishing_incidents_report_summary()`.
- Query filters: `date_from`/`dateFrom`, `date_to`/`dateTo`, `date_range`/`period`, `risk_level`/`riskLevel`, `category`/`status`.
- Success response: `{"success": true, "report": ...}`.
- Called by: `ReportsExportCenterPage.tsx` `loadPhishingReport()`.

### GET `/api/admin/reports/phishing-incidents/export`

- Auth required: Yes, `@admin_auth_required`.
- Handler: `_admin_phishing_incidents_report_export_early()` -> `admin_phishing_incidents_report_export()`.
- Query filters: same as summary plus `format`.
- Successful backend format: CSV.
- Error: non-CSV returns 400 with message that PDF export is generated in Reports & Export Center.

### Monthly and shared endpoints including phishing data

- `/api/reports/monthly` and related monthly report generate/download/upload endpoints include phishing when `phishing_scan_query` returns rows.
- `/api/pcap/alerts` includes phishing alert records because `PcapAlertRecord` is reused and serialized with source `phishing`.
- Security score endpoints include phishing through `_build_security_score_payload()`.
- Chatbot `/api/chatbot/llm` supports module `phishing`.

## 5. Frontend Flow

`PhishingScannerPage.tsx`:

1. Stores input in `url`.
2. `normalizeUrlInput(value)` trims input.
3. If input starts with malformed `http/` or `https/`, it rejects it.
4. If no scheme exists, it prepends `https://`.
5. `new URL(candidate)` validates protocol and hostname.
6. It requires protocol `http:` or `https:` and hostname containing `.`.
7. `handleScan()` sets loading, clears previous result/error, and POSTs to `${VITE_API_BASE_URL}/api/v1/scan-url`.
8. Auth behavior: first tries cookie credentials; on 401/403 retries with `localStorage.sentinel_auth_token` unless token is `cookie_based`.
9. On success, `buildScanResult()` maps backend fields into frontend result.
10. It displays final status, final score, guidance, ML probability, ML risk category, trusted domain, original ML score, VirusTotal status, domain, malicious count, suspicious count, and VirusTotal message.
11. It refreshes history and dispatches `sentinel:notifications-updated` if `notification_created` is true.
12. History table displays URL, status, risk score, ML Category (actually the final category from stored history), and scan time.
13. Clear history loops over all history rows and calls DELETE for each.
14. Download PDF creates a simple client-side PDF from history; this is not a backend export.
15. Error handling: validation error, 400 backend invalid URL, 401 session expired/not logged in, 5xx server error, network error.

## 6. URL Validation & Normalization

Frontend accepted examples:

- `github.com`: accepted by frontend, normalized to `https://github.com/`.
- `https://github.com/`: accepted.
- `http://github.com`: accepted and normalized by `URL` to include trailing slash.

Frontend rejected examples:

- `http/github.com`: rejected by regex because it starts like HTTP without `://`.
- `https:/github.com/`: rejected by `new URL()`/protocol-hostname checks.
- Empty string: rejected.
- Hostname without dot: rejected by frontend because `hostname.includes(".")` must be true.

Backend accepted examples:

- `https://github.com/`: accepted.
- `http://github.com`: accepted.

Backend rejected examples:

- `github.com`: rejected if sent directly to backend because no scheme/netloc.
- `http/github.com`: rejected.
- `https:/github.com/`: rejected.
- Non-HTTP schemes: rejected.

Validation message: `Please enter a valid URL, for example https://github.com`.

Invalid URL behavior: no scan record, no ML, no VirusTotal call, no notification, no user email, no admin alert, no gamification, no activity log.

## 7. ML Model Details

- Algorithm: `RandomForestClassifier`.
- Training file: `Backend/phishing_scanner/train.py`.
- Runtime prediction file: `Backend/phishing_scanner/ml.py`.
- Model path: `Backend/data/models/rf_model.pkl`.
- Scaler path: `Backend/data/models/scaler.pkl`.
- Dataset path: `Backend/data/final_phishing_dataset.csv`.
- Target column: `phishing`.
- Feature columns: `url_length`, `n_dots`, `n_hypens`, `n_underline`, `n_slash`, `n_questionmark`, `n_equal`, `n_at`, `n_and`, `n_exclamation`, `n_space`, `n_tilde`, `n_comma`, `n_plus`, `n_asterisk`, `n_hastag`, `n_dollar`, `n_percent`, `n_redirection`.
- Training split: `test_size=0.25`, `random_state=42`, `stratify=y`.
- Scaler: `StandardScaler`.
- Random Forest parameters: `n_estimators=300`, `max_depth=20`, `min_samples_split=5`, `min_samples_leaf=2`, `class_weight="balanced"`, `random_state=42`, `n_jobs=-1`.
- Prediction output: `prediction`, `probability`, `risk`, `trusted_domain`, optionally `model_fallback`.
- `predict_proba`: uses `model.predict_proba(df_scaled)[0, 1]`.
- Trusted domain shortcut: if any trusted domain substring appears in the normalized domain, returns `prediction=0`, `probability=0.0`, `risk="safe"`, `trusted_domain=True`.
- Trusted domains: google.com, youtube.com, facebook.com, twitter.com, wikipedia.org, microsoft.com, github.com, linkedin.com, apple.com, amazon.com, stackoverflow.com, reddit.com.
- Fallback if model/scaler missing: intended fallback exists, but currently appears broken because `extract_features(url)` returns a list while fallback code indexes it as a dict by feature name. Therefore no-model fallback is not reliable as implemented.
- Do not invent accuracy: training prints accuracy and classification report, but no fixed stored accuracy is documented in the inspected code.

## 8. Risk Scoring Logic

Base risk:

- If `trusted_domain=True`: `risk_score=0`, `category=safe`.
- Otherwise: `risk_score = round(probability * 100)`, clamped 0-100.
- `category_from_score()`:
  - 0-39: `safe`
  - 40-69: `suspicious`
  - 70-100: `dangerous`

VirusTotal combination:

- Starts with ML score.
- If VirusTotal unavailable, final score remains ML score.
- If VirusTotal malicious count > 0:
  - `vt_boost = min(15, 5 + malicious * 2 + suspicious)`
  - `final_score = min(100, max(ml_score + vt_boost, 85))`
  - `final_category = dangerous`
- If no malicious but suspicious count > 0:
  - `vt_boost = min(10, suspicious * 3)`
  - `final_score = min(100, max(ml_score + vt_boost, 50))`
  - if score category was safe, category becomes suspicious.
- VirusTotal never reduces ML risk: `final_score = min(max(final_score, ml_score), 100)`.

Examples based on implemented logic:

- `github.com` from frontend becomes `https://github.com/`; trusted domain shortcut makes ML score 0. If VirusTotal is clean/unavailable, final remains safe.
- `example-login-security-check.com`: no hardcoded example exists; result depends on extracted features, model, and VirusTotal.
- `http://malware.wicar.org/`: no hardcoded example exists; final depends on ML and VirusTotal. If VirusTotal malicious > 0, final becomes dangerous with minimum score 85.

## 9. VirusTotal Integration

- File: `Backend/phishing_scanner/virustotal.py`.
- Endpoint: `https://www.virustotal.com/api/v3/domains/{domain}`.
- Header: `x-apikey`, read from `VIRUSTOTAL_API_KEY`.
- Domain extraction: `urlparse(url).hostname`, lowercased and stripped.
- Timeout: 5 seconds.
- Cache: in-memory `_CACHE`, keyed by domain, TTL 6 hours.
- Main functions:
  - `extract_domain_from_url(url)`
  - `get_virustotal_domain_report(domain)`
  - `parse_virustotal_reputation(response_json)`
  - `get_domain_reputation(url)`
- Returned fields when available: `available`, `domain`, `source`, `malicious`, `suspicious`, `harmless`, `undetected`, `reputation`, `message`.
- Missing API key: returns `available=False`, `reputation="unavailable"`, message `VirusTotal API key is not configured`.
- Rate limit: 429 returns `available=False`, `reputation="rate_limited"`.
- Request/timeout/non-OK/JSON parse failure: returns `available=False`, `reputation="unavailable"`.
- Security: API key is read server-side only and is not returned in responses.

## 10. Database Design

Primary phishing scan storage:

- DB type: SQLite.
- File: `Backend/data/scans.db`.
- Table: `scans`.
- Created by: import-time initialization in `Backend/phishing_scanner/database.py`.
- Columns:
  - `id INTEGER PRIMARY KEY AUTOINCREMENT`
  - `user_id INTEGER`
  - `url TEXT`
  - `risk INTEGER`
  - `result TEXT`
  - `timestamp DATETIME DEFAULT CURRENT_TIMESTAMP`
- Insert: `save_scan(user_id, url, risk, result)`.
- Read: `get_user_scans(user_id)`.
- Delete: `delete_scan(scan_id, user_id)`.
- User scoping: reads/deletes filter by `user_id`.
- Foreign key to `user`: not enforced in SQLite table; logical relationship only.

Related records outside `scans`:

- `user_notification`: created by `create_user_notification()` via `create_phishing_scan_notification()`.
- `pcap_alert`: reused as Recent Security Alert and admin threat feed record. Phishing rows use `source_type="phishing_scanner"`, `job_id="phishing-scan-<scan_id>"`, `risk_label="phishing"`, metadata with URL/domain/final category/final score/VT counts.
- `user_activity_log`: created by `_record_phishing_activity()`.
- Gamification tables: record events from `record_phishing_scan_completion()`.
- `monthly_security_report`: stores JSON/PDF monthly report payload that may include phishing section.
- `admin_audit_log`: report view/export actions are logged when admin accesses phishing report.
- Reports data: admin reports read `scans.db`; monthly reports receive scan rows through `_query_user_phishing_scan_records()`.

## 11. ERD Diagram Content

Entities:

- User: `id` PK, `email`, `email_notifications_enabled`, auth/profile fields.
- PhishingScan: `id` PK, `user_id` logical FK to User, `url`, `risk`, `result`, `timestamp`.
- Notification: `id` PK, `user_id` FK, `type`, `severity`, `title`, `body`, `job_id`, `metadata_json`, `is_read`, `created_at`.
- SecurityAlert / RecentSecurityAlert: `PcapAlertRecord` `id` PK, `user_id` FK, `job_id`, `alert_key` unique, `source_type`, `type`, `title`, `message`, `severity`, `risk_label`, `metadata_json`, `event_at`.
- AdminAuditEvent: `AdminAuditLog` `id` PK, actor fields, action fields, `module`, `severity`, `metadata_json`, `created_at`.
- UserActivityLog: `id` PK, `user_id`, `module`, `action_type`, `title`, `description`, `severity`, `risk_score`, `target_type`, `target_id`, `metadata_json`, `event_id`.
- RewardEvent: gamification event record, logical link to User and phishing scan id in metadata.
- MonthlyReport: `MonthlySecurityReport` `id` PK, `user_id` FK, `report_month`, `report_payload_json`, `pdf_path`, `status`, timestamps.

Relationships:

- User 1-to-many PhishingScan: logical relationship only, not enforced in `scans` SQLite.
- User 1-to-many Notification: enforced by SQLAlchemy FK.
- User 1-to-many SecurityAlert: enforced by SQLAlchemy FK.
- User 1-to-many UserActivityLog: logical/SQLAlchemy model relationship depending table definition.
- PhishingScan 1-to-0/1 SecurityAlert: logical via `alert_key="phishing-scanner:{user_id}:{scan_id}"`.
- PhishingScan 1-to-many Notification/UserActivity/Gamification events: logical through `scan_id` metadata/event ids.
- User 1-to-many MonthlyReport: enforced by SQLAlchemy FK.

## 12. Use Case Diagram Content

Use cases:

- Submit URL for scan: User triggers Scan button; precondition authenticated; postcondition scan pipeline starts or validation error displayed.
- Validate URL: System checks frontend/backend format; alternative invalid path returns error and stores nothing.
- Normalize URL: Frontend prepends `https://` when missing; backend does not normalize.
- Extract URL features: System calls `extract_features(url)`; output feature vector.
- Predict phishing risk with ML: ML Model returns probability/risk; trusted-domain alternative returns safe without model.
- Check domain reputation using VirusTotal: System calls VirusTotal unless API unavailable; alternative returns unavailable object.
- Calculate final risk score: System combines ML score and VirusTotal boosts; output final score/category.
- Display scan result: Frontend renders result card, ML panel, VirusTotal panel.
- Save scan history: System inserts row into SQLite.
- View scan history: User opens page; frontend GETs history.
- Delete scan history: User clicks Clear History; frontend DELETEs each scan id.
- Receive user notification: Notification Center receives scan notification.
- Receive user email for risky URL: Email Service sends to user if trigger/config/settings pass.
- Send admin email for high/critical event: Intended System/Admin email; current phishing implementation is bugged/not working.
- Create admin threat alert: System creates/reuses `PcapAlertRecord`; current live function commits row then returns `None` because of bug.
- Log audit/activity event: User activity always attempted after scan; admin audit for report view/export.
- Generate phishing report: Admin triggers report load.
- Export phishing report: Admin exports CSV via backend or simple PDF via frontend.
- Update security score: System reads latest scan when security score is requested.
- Award gamification points: Gamification service processes scan events.
- Ask chatbot about phishing scan: User selects phishing mode and asks; chatbot uses safe context.

## 13. Sequence Diagram Content

### A) Safe URL scan: `https://github.com/`

Participants: User, Frontend, Backend `scan_url`, ML, VirusTotal, SQLite, Gamification, UserActivityLog, NotificationCenter, EmailService, RecentSecurityAlerts.

1. User enters URL and clicks Scan.
2. Frontend validates and sends POST.
3. Backend authenticates user.
4. Backend validates URL.
5. `predict_url()` detects trusted domain `github.com`, returns probability 0, safe.
6. `calculate_risk()` returns score 0, category safe.
7. `get_domain_reputation()` checks VirusTotal or cache; unavailable/clean does not reduce/increase risk.
8. `combine_ml_and_virustotal()` returns final safe score unless VT suspicious/malicious says otherwise.
9. `save_scan()` inserts row.
10. Gamification records base scan and safe scan events.
11. User activity logs `phishing_scan_completed`.
12. Notification is created with info/job-completed type.
13. User email not sent because safe score/category.
14. Recent security alert is attempted; safe alert severity low.
15. Response returned to frontend; frontend displays safe result and refreshes history.

### B) Dangerous URL scan: `http://malware.wicar.org/`

1. User submits URL.
2. Frontend sends POST.
3. Backend validates/authenticates.
4. ML predicts based on features unless model unavailable.
5. VirusTotal domain report is fetched/cached.
6. If VT malicious > 0, final score becomes at least 85 and category dangerous.
7. Scan saved with final score/category.
8. Gamification records base scan and risky URL event.
9. User activity logs `phishing_dangerous_url_detected`.
10. Notification created with critical severity/type.
11. User email attempted if mail and user settings allow.
12. Recent security alert row is created and committed.
13. Current bug: admin email block references undefined variables; exception is caught and function returns `None`, so response may show `recent_alert_created=false` and admin email not sent.

### C) Invalid URL: `https:/github.com/`

1. User enters invalid URL.
2. Frontend validation rejects it and displays validation message.
3. If sent directly to backend, backend rejects with 400.
4. No database write, ML, VirusTotal, notification, email, alert, gamification, report, or activity log occurs.

### D) Admin report/export phishing incidents

1. Admin opens Reports & Export Center and selects Phishing Incidents Summary.
2. Frontend calls `GET /api/admin/reports/phishing-incidents` with filters.
3. Backend admin auth validates token/session.
4. Backend reads SQLite `scans` table.
5. Backend normalizes fields into latest scans and summary metrics.
6. Backend logs report view action.
7. Frontend displays KPIs, filters, latest scans, recommendations.
8. CSV export calls `/export?format=csv`; backend returns CSV and logs export.
9. Frontend PDF export is generated client-side from current summary; backend non-CSV export returns 400.

### E) Admin email alert for dangerous phishing

Current intended participants: Backend phishing alert function, admin email helper, MAIL service.

Current actual behavior:

1. Dangerous scan reaches `create_phishing_scanner_security_alert()`.
2. `PcapAlertRecord` is added and committed.
3. Function enters a misplaced block intended for Password Checker admin email.
4. Undefined variables cause an exception.
5. Exception is caught; database rollback is called after commit; function logs failure and returns `None`.
6. Admin phishing email is not sent from the live phishing path.

## 14. Data Flow Diagram Content

DFD Level 0:

- External entities: User, Admin, VirusTotal API, Email Service, ML Model, Admin Dashboard/Reports.
- System: Phishing Scanner System.
- Data stores: `scans.db`, app database tables (`user_notification`, `pcap_alert`, `user_activity_log`, gamification, monthly reports).
- User sends URL and receives result/history.
- Admin requests reports/alerts and receives summaries/exports.
- System sends domain to VirusTotal and receives reputation.
- System sends features to ML model and receives probability.
- System sends email content to Email Service when triggered.

DFD Level 1:

1. Receive URL Input: input URL, user session; output candidate URL.
2. Validate and Normalize URL: input candidate URL; output normalized frontend URL or validation error.
3. Extract URL Features: input backend URL; output 19 lexical features.
4. Run ML Prediction: input feature vector/domain; output probability, risk, trusted flag.
5. Fetch VirusTotal Reputation: input domain; output reputation counts/status/message.
6. Calculate Final Risk: input ML score/category and VT counts; output final score/category/guidance.
7. Store Scan Result: input user id, URL, final risk, final category; output scan id.
8. Notify User/Admin: input scan metadata; output notification, optional user email, bugged admin email.
9. Update Reports/Security Score/Alerts: input scan/metadata; output `pcap_alert`, report aggregates, score component.
10. Return Result to Frontend: input full result; output JSON response.

## 15. State Diagram / Data State Diagram

States and transitions:

- URL Entered -> URL Validating: user clicks Scan.
- URL Validating -> Invalid URL: frontend/backend validation fails.
- URL Validating -> URL Normalized: frontend accepts and normalizes.
- URL Normalized -> Features Extracted: backend calls ML path.
- Features Extracted -> ML Prediction Running: model/scaler path starts.
- ML Prediction Running -> VirusTotal Lookup Running: ML result produced.
- VirusTotal Lookup Running -> Risk Calculated: reputation object returned or unavailable.
- Risk Calculated -> Scan Saved: `save_scan()` inserts row.
- Scan Saved -> Safe Result: final score 0-39.
- Scan Saved -> Suspicious Result: final score 40-69.
- Scan Saved -> Dangerous Result: final score 70-100 or VT malicious.
- Safe/Suspicious/Dangerous -> User Notified: in-app notification attempted.
- Suspicious/Dangerous -> User Email: user email attempted.
- Dangerous -> Admin Alert Created: `PcapAlertRecord` commit attempted/currently row can be committed.
- Dangerous -> Admin Email Sent: Not implemented correctly for phishing; current path is bugged.
- Any saved result -> Reportable: rows available to reports/monthly/security score.
- Saved result -> Deleted: DELETE endpoint removes scan row.

## 16. Admin Integrations

- Admin Threat Management: Implemented. Uses `PcapAlertRecord` and notification feed serialization. Source label `Phishing Scanner`; IDs may be `phishing-scanner:{user_id}:{scan_id}`; severity dangerous->critical, suspicious->medium, safe->low.
- Admin Audit Trail: Partially implemented. Scan itself logs user activity, not admin audit. Admin report view/export logs admin actions with Phishing Incidents Summary.
- Admin Overview / Analytics Dashboard: Implemented indirectly where threat feed/reports consume phishing alerts/scans; exact dashboard widgets depend on admin console sections.
- Reports & Export Center: Implemented. Shows total URL scans, safe/suspicious/dangerous/risky counts, average risk, latest scan, VT totals, highest risk scan, latest scans, recommendations. Filters: date from/to, risk level, category, export format.
- Monthly Security Report: Implemented. Includes phishing section if scans exist in report month.
- Security Incidents Report: Not directly phishing-specific from `scans`; phishing can appear indirectly through `PcapAlertRecord` as a pcap/security alert source, but Security Incidents report code is primarily pcap/identity/password/notification/activity/audit.
- High-Risk Users Report: Implemented indirectly via `PcapAlertRecord`, notifications, and user activity signals; phishing user activity can contribute when severe/suspicious.
- User Activity Logs: Implemented. Module `phishing`, actions `phishing_scan_completed`, `phishing_suspicious_url_detected`, `phishing_dangerous_url_detected`.
- Notification Center: Implemented. Created per scan; action URL `/phishing-scanner`.
- Recent Security Alerts: Partially implemented; phishing rows are supported, but live function currently returns `None` after committing due to bug.

## 17. Email Notification Behavior

### A) User email

- Sent when: final category is `suspicious` or `dangerous`, or score >= 50.
- Not sent when: safe scan, missing user/email, user disabled email notifications, mail not configured, or delivery failure.
- Recipient: `user.email`.
- Helper: `send_phishing_scan_email_alert()` and/or generic `send_notification_email_best_effort()` via notification side effect.
- Subject: `[Sentinel AI] Phishing scan alert: <category>`.
- Content summary: module, scanned URL, domain, final category, final score, ML probability, VT status/counts, recommended action.
- Best effort: failures return reason and do not break scan.

### B) Admin email

- Shared helper exists: `send_admin_alert_email_best_effort(...)`.
- Recipient env: `ADMIN_ALERT_EMAIL_TO`.
- Missing recipient reason: `admin_alert_email_skipped_no_recipient`.
- Dedupe: in-memory `_admin_alert_email_dedupe_keys`.
- Safe metadata only: helper filters sensitive key names and text patterns.
- Current phishing behavior: Not implemented correctly / bugged. The live phishing path does not correctly call the helper with phishing metadata.
- Why safe scans do not email admin: helper only sends for severity `high` or `critical`; phishing should only trigger admin email for dangerous/high-risk conditions, but current call is broken.

### C) In-app notifications only

- Safe scan: in-app notification created, no user email.
- Suspicious/dangerous: in-app notification created; user email may be attempted.
- Admin sees system-wide/admin notifications depending admin endpoints; user sees own notification center.

## 18. Reports Documentation

Reports & Export Center Phishing Incidents Summary:

- Backend data source: SQLite `scans`.
- Summary fields: `total_url_scans`, `safe_urls`, `suspicious_urls`, `dangerous_urls`, `risky_urls`, `average_risk_score`, `latest_scan_time`, `virustotal_malicious_total`, `virustotal_suspicious_total`.
- Highest risk: `highest_risk_scan`.
- Latest scans: up to 50 backend records.
- Empty state: message `No phishing scanner activity is available for this reporting period.`
- CSV export: backend implemented.
- PDF export: backend says PDF is generated in frontend; frontend builds a simple PDF blob from current summary.

Monthly Reports:

- Builder: `Backend/reports.py`.
- Section key: `sections.phishing`.
- Metrics: total phishing scans, safe URLs, suspicious URLs, dangerous URLs, risky URLs, highest risk URL, average phishing risk score, VT malicious/suspicious totals, latest scans, analyst summary, recommendations.
- PDF: backend monthly PDF rendering includes phishing section when present.

## 19. Gamification / Rewards

Implemented.

- Function: `GamificationService.record_phishing_scan_completion()`.
- Events:
  - `phishing_scan_completed`: 5 points.
  - `phishing_safe_scan_completed`: 5 points.
  - `phishing_risky_url_detected`: 8 default points, but service overrides to 10 for dangerous or score >= 70.
- Badges:
  - `phishing_first_url_scan`
  - `phishing_safe_link_checker`
  - `phishing_hunter`
  - `weekly_phishing_analyst`
- Challenges:
  - `phishing_check_one_url`
  - `phishing_identify_one_risky_url`
  - `phishing_complete_three_scans`
  - `phishing_detect_two_risky_urls`
- Deduplication uses scan id context: `phishing_scan_id`.
- Reward history text includes phrases such as “Phishing: Safe URL scan completed” and “Phishing: Dangerous URL detected.”

## 20. Chatbot Integration

Implemented.

- Frontend mode: `ChatbotWorkspacePage.tsx` has `phishing` tab/mode and quick prompts.
- Backend safe context: `_safe_phishing_llm_context(user_id)`.
- Reads latest scan rows from `scans.db` and related phishing `PcapAlertRecord` metadata.
- Context includes latest scan, recent scans, counts, recommendations, score weight, and VirusTotal fields if available in alert metadata.
- Fallback answer function: `_fallback_phishing_answer(intent, safe_context)`.
- Supported intents include latest scan, history, scoring, VirusTotal explanation, safe reason, dangerous reason, next steps, and security score effect.
- Security score explanation distinguishes phishing `final_risk_score` from security score posture.
- Does not expose keys, tokens, cookies, or hidden config.

## 21. Security & Privacy

- Secrets not exposed: VirusTotal API key is read from env and never returned.
- Raw passwords not relevant to phishing and are not included.
- SMTP/MAIL secrets not included in email templates or logs.
- User-scoped history: GET and DELETE filter by `user.id`.
- Admin-safe metadata: helper sanitizes sensitive metadata, but phishing helper call is currently bugged.
- Email safe content: user email includes scan metadata, not secrets.
- Invalid URL: no scan record, no notification, no email, no admin alert.
- Best-effort behavior: notification/email/activity/gamification failures are caught and should not intentionally break the original scan. Current phishing alert bug can cause `recent_alert_created=false` after row commit, but scan response still completes.

## 22. Testing Documentation

| Test ID | Scenario | Input | Expected result | Actual implemented behavior if known | Related function/file |
|---|---|---|---|---|---|
| PH-001 | Valid safe URL | `https://github.com/` | Safe score/category, saved history | Trusted shortcut returns ML safe; VT can only boost if risky | `predict_url`, `scan_url` |
| PH-002 | Valid dangerous URL | `http://malware.wicar.org/` | Dangerous if ML/VT indicates risk | VT malicious forces dangerous >=85 | `combine_ml_and_virustotal` |
| PH-003 | Suspicious URL | Long/symbol-heavy URL | Suspicious 40-69 | Depends on model probability and VT | `calculate_risk` |
| PH-004 | Invalid URL | `https:/github.com/` | Validation error | No record/notification/email | frontend `normalizeUrlInput`, backend `scan_url` |
| PH-005 | VirusTotal unavailable | API timeout | ML-only result | Returns unavailable object; scan continues | `virustotal.py` |
| PH-006 | Missing VT key | no env key | ML-only result + message | Returns “API key is not configured” | `get_virustotal_domain_report` |
| PH-007 | Missing admin recipient | no `ADMIN_ALERT_EMAIL_TO` | Admin email skipped | Helper returns skip, but phishing call bug prevents correct live use | `send_admin_alert_email_best_effort` |
| PH-008 | User email risky URL | suspicious/dangerous | User email sent if configured | Best effort; response reason set | `send_phishing_scan_email_alert` |
| PH-009 | Admin email dangerous URL | dangerous | Admin email sent | Not working in current phishing path due undefined variables | `create_phishing_scanner_security_alert` |
| PH-010 | Safe URL no admin email | safe URL | No admin email | Helper would skip; live path bug not relevant for safe | `send_admin_alert_email_best_effort` |
| PH-011 | History saved | valid URL | Row in scans table | Implemented | `save_scan` |
| PH-012 | History deleted | scan id | Row deleted for user | Implemented | `delete_scan` |
| PH-013 | Dashboard alert created | risky URL | `pcap_alert` row | Row can be committed; function returns `None` due bug | `create_phishing_scanner_security_alert` |
| PH-014 | Reports export | admin CSV | CSV file | Implemented for CSV | `admin_phishing_incidents_report_export` |
| PH-015 | Security score update | latest scan | Phishing component reflects latest risk | Implemented | `_score_phishing_module` |
| PH-016 | Activity logging | scan | User activity row | Implemented | `_record_phishing_activity` |
| PH-017 | Gamification points | scan | Points/events | Implemented | `record_phishing_scan_completion` |
| PH-018 | Chatbot response | ask latest scan | Uses real context or says none | Implemented | `_safe_phishing_llm_context` |

## 23. Book Chapter Material

### A) Introduction

The Phishing Scanner module is a user-facing security feature within Sentinel AI that evaluates URLs before users interact with them. It combines machine learning, URL feature analysis, and VirusTotal domain reputation to classify a submitted URL as safe, suspicious, or dangerous. The module is integrated with scan history, notifications, reporting, security score calculation, gamification, and admin monitoring.

### B) Problem Statement

Phishing attacks remain one of the most common ways users lose credentials or access malicious pages. Users often receive unfamiliar links through email, messages, or web content and need a fast method to assess the risk before opening them. Sentinel AI addresses this problem by providing a centralized URL scanning workflow with automated risk analysis and administrative visibility.

### C) Module Objectives

- Validate submitted URLs.
- Extract URL-based features.
- Predict phishing probability with an ML model.
- Enrich results with VirusTotal reputation.
- Calculate an understandable final risk score.
- Preserve user-specific scan history.
- Notify users about risky URLs.
- Surface risky scan data to admin reports and dashboards.
- Feed user security score, gamification, and chatbot explanations.

### D) Functional Requirements

- The system shall allow authenticated users to submit HTTP/HTTPS URLs.
- The system shall reject invalid URLs.
- The system shall classify URLs into safe, suspicious, or dangerous.
- The system shall save successful scans per user.
- The system shall display scan history.
- The system shall allow deletion of scan history.
- The system shall create notifications.
- The system shall generate report summaries for admins.
- The system shall include phishing data in monthly reports and security score.

### E) Non-Functional Requirements

- Best-effort external integrations must not break the scan.
- Secrets must remain server-side.
- User history must be scoped to the authenticated user.
- Reports must use safe metadata.
- The UI should provide clear feedback for loading, errors, and final result.

### F) System Design Explanation

The module is split into backend scanner logic, model inference, reputation enrichment, SQLite history storage, and frontend presentation. Backend routes are exposed through a Flask blueprint with prefix `/api/v1`. The frontend page manages user input, authentication-aware API calls, and visual result panels.

### G) Implementation Explanation

The backend validates URLs, runs `predict_url()`, calculates ML risk, obtains VirusTotal reputation, combines results, saves the scan, and triggers integrations. The frontend normalizes input before sending and displays both ML and VirusTotal evidence.

### H) Database Design Explanation

The main scan table is `scans` in `Backend/data/scans.db`. It stores a user id, URL, final risk score, final category, and timestamp. Related application tables store notifications, activity logs, alert records, gamification events, and monthly reports.

### I) ML and VirusTotal Explanation

The ML layer uses a trained Random Forest classifier over lexical URL features. VirusTotal adds independent domain reputation. The final logic preserves ML risk and only boosts when VirusTotal reports suspicious or malicious detections.

### J) Admin Monitoring Explanation

Admins can review phishing incidents in Reports & Export Center, monthly reports, threat feed/recent alerts, and user activity logs. Current admin email behavior for phishing is not correctly implemented due a runtime bug in the phishing alert function.

### K) Testing and Validation Explanation

Testing should cover safe, suspicious, dangerous, invalid, VirusTotal unavailable, missing API key, email paths, history, deletion, reports, score, gamification, and chatbot behavior. The current implementation should specifically test the phishing admin alert bug.

### L) Limitations

- Backend does not normalize missing URL schemes.
- Main `scans` table does not store VirusTotal fields or ML probability.
- No-model ML fallback appears broken because of feature list/dict mismatch.
- Admin phishing email path is bugged.
- Backend admin phishing report export supports CSV only; PDF is frontend-generated.

### M) Future Enhancements

Future enhancements may include backend URL normalization, storing full safe scan metadata in `scans`, fixing the no-model fallback, fixing admin phishing email, adding backend PDF export for phishing reports, and adding dedicated phishing tables with enforced foreign keys. These are future possibilities, not current implementation.

## 24. Final Summary

Files involved:

- `Backend/phishing_scanner/scan.py`
- `Backend/phishing_scanner/ml.py`
- `Backend/phishing_scanner/risk.py`
- `Backend/phishing_scanner/url_features.py`
- `Backend/phishing_scanner/database.py`
- `Backend/phishing_scanner/train.py`
- `Backend/phishing_scanner/virustotal.py`
- `Backend/app.py`
- `Backend/reports.py`
- `Backend/activity_logs.py`
- `Backend/gamification/definitions.py`
- `Backend/gamification/service.py`
- `Cybersecurity Dashboard Design/src/components/pages/PhishingScannerPage.tsx`
- `Cybersecurity Dashboard Design/src/components/NotificationCenter.tsx`
- `Cybersecurity Dashboard Design/src/components/security/RecentSecurityAlertsPanel.tsx`
- `Cybersecurity Dashboard Design/src/utils/recentPcapAlerts.ts`
- `Cybersecurity Dashboard Design/src/components/admin/AdminAuditTrailPage.tsx`
- `Cybersecurity Dashboard Design/src/components/admin/ReportsExportCenterPage.tsx`
- `Cybersecurity Dashboard Design/src/components/pages/AdminConsolePage.tsx`
- `Cybersecurity Dashboard Design/src/components/pages/MonthlyReportsPage.tsx`
- `Cybersecurity Dashboard Design/src/components/pages/ChatbotWorkspacePage.tsx`
- `Cybersecurity Dashboard Design/src/components/pages/UserActivityLogsPage.tsx`
- `docker-compose.yml`
- `Dockerfile.frontend`
- `Cybersecurity Dashboard Design/.env.example`

APIs involved:

- `POST /api/v1/scan-url`
- `GET /api/v1/scans`
- `DELETE /api/v1/scan/<scan_id>`
- `GET /api/admin/reports/phishing-incidents`
- `GET /api/admin/reports/phishing-incidents/export`
- Monthly report APIs under `/api/reports/monthly...`
- Notification APIs under `/notifications...` and admin notification variants
- Recent alert APIs under `/api/pcap/alerts`
- Chatbot LLM API `/api/chatbot/llm`
- Security score APIs that call `_build_security_score_payload()`

Database tables involved:

- `scans`
- `user`
- `user_notification`
- `pcap_alert`
- `user_activity_log`
- `admin_audit_log`
- gamification event/badge/challenge tables
- `monthly_security_report`

Frontend components involved:

- `PhishingScannerPage.tsx`
- `NotificationCenter.tsx`
- `RecentSecurityAlertsPanel.tsx`
- `ReportsExportCenterPage.tsx`
- `MonthlyReportsPage.tsx`
- `ChatbotWorkspacePage.tsx`
- `UserActivityLogsPage.tsx`
- `AdminConsolePage.tsx`
- `AdminAuditTrailPage.tsx`

External services involved:

- VirusTotal Domain API
- SMTP/MAIL email service
- Browser localStorage/session cookies for frontend auth fallback
- Optional Docker/WAF environment around the app

Diagrams to create:

- ERD: User, PhishingScan, Notification, SecurityAlert, UserActivityLog, AdminAuditEvent, RewardEvent, MonthlyReport.
- Use Case Diagram: User/Admin/System/ML/VirusTotal/Email interactions.
- Sequence Diagrams: safe scan, dangerous scan, invalid URL, admin report/export, admin email alert current-state bug.
- DFD Level 0: Phishing Scanner system boundary.
- DFD Level 1: validation, ML, VirusTotal, scoring, storage, notifications, reports.
- State/Data State Diagram: URL entered through deleted/reportable states.

Missing or uncertain parts requiring manual confirmation:

- Actual trained model files and dataset may or may not exist in the runtime environment; code paths are documented, but file presence should be checked in deployment.
- Model accuracy is not fixed in source code and should not be claimed unless training output is captured.
- Phishing admin email is present as intended infrastructure but bugged in the current live phishing path.
- Backend phishing report PDF export is not implemented; frontend simple PDF export is implemented.
