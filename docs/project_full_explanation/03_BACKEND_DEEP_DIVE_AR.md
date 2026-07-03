# 03 - Backend Deep Dive

## Main backend entry point

`Backend/app.py` هو entry point الرئيسي. يبدأ بتحميل `.env` من root/backend/frontend، يضبط Flask config، يسجل blueprints، ويحتوي routes كثيرة. الدليل: `_load_project_env_files`, `app.register_blueprint(scan_bp)`, `app.register_blueprint(gamification_bp)`, `app.register_blueprint(password_checker_bp)`, `init_vault(app)`.

## Configuration and environment variables

أهم env vars المرئية في الكود:

- `SECRET_KEY`, `JWT_SECRET_KEY`: auth/session secrets في `Backend/app.py`.
- `DATABASE_URL`: SQLAlchemy database URI.
- `SMTP_*`, `MAIL_*`: email notifications/password reset.
- `VIRUSTOTAL_API_KEY`: phishing reputation.
- `PCAP_RUN_FOLDER`, `LOCAL_PCAP_ALLOWED_ROOT`, `UPLOAD_SAVE_BUFFER_SIZE`: PCAP storage/upload.
- `PCAP_ARTIFACT_ENCRYPTION_KEY`, `PCAP_ARTIFACT_ENCRYPTION_MODE`: artifact protection.
- `GOOGLE_DRIVE_UPLOADS_ENABLED`, `GOOGLE_DRIVE_SERVICE_ACCOUNT_FILE`, `GOOGLE_DRIVE_FOLDER_ID`: report upload.
- `OLLAMA_*`, `GEMINI_*`, `LLM_*`: chatbot providers.
- `CORS_ALLOWED_ORIGINS`, `FRONTEND_BASE_URL`: frontend integration.

## Route groups

### Auth/user

- `/api/auth/signup` -> `signup`
- `/api/auth/login` -> `login`
- `/api/auth/refresh` -> `refresh`
- `/api/auth/me` -> `get_me`
- `/api/auth/logout` -> `logout`
- `/api/auth/forgot-password` -> `forgot_password`
- `/api/auth/reset-password` -> `reset_password`
- `/api/auth/verify-email-token` -> `verify_email`
- `/api/auth/2fa/setup` -> `setup_2fa`
- `/api/auth/2fa/verify-setup` -> `verify_2fa_setup`
- `/api/auth/2fa/verify-login` -> `verify_2fa_login`

### Password Checker

- `/api/password/check` -> `check_password` in `Backend/password_checker/routes.py`.
- `/api/password/history` -> `get_user_password_history`, `clear_user_password_history`.

### Phishing Scanner

- `/api/v1/scan-url` -> `scan_url`.
- `/api/v1/scans` -> `get_scans`.
- `/api/v1/scan/<scan_id>` DELETE -> `delete_scan_route`.

### Vault

- `/api/documents/rules` -> `document_rules`.
- `/api/documents` GET/POST -> `list_documents`, `upload_document`.
- `/api/upload` POST -> `upload_alias`.
- `/api/documents/<doc_id>/offline` -> `toggle_offline_access`.
- `/api/documents/<doc_id>/verify` -> `verify_document_integrity`.
- `/api/documents/<doc_id>/download` -> `download_document`.
- `/api/documents/<doc_id>` DELETE -> `delete_document`.

### PCAP

- `/analyze-pcap`, `/pcap/analyze` -> `analyze_pcap`.
- `/jobs`, `/pcap/jobs` -> `list_jobs`.
- `/job/<job_id>`, `/pcap/status/<job_id>`, `/pcap/result/<job_id>` -> `get_job`.
- `/api/pcap/cancel/<job_id>` -> `cancel_pcap_job`.
- `/job/<job_id>/export`, `/pcap/report/<job_id>` -> `export_job_artifact`.
- `/api/pcap/alerts` -> `list_pcap_alerts`.
- `/api/pcap/alerts/clear` -> `dismiss_visible_pcap_alerts`.
- `/analyze-local` -> `analyze_local`.

### Identity

- Legacy: `/api/assets`, `/api/scan/<asset_id>`, `/api/full-scan`, `/api/toggle-auto-scan/<asset_id>`, `/api/protection-rate`, `/api/check`.
- Web identity: `/api/identity/web-scan`, `/api/identity/scans`, `/api/identity/scans/<scan_id>`, `/api/identity/findings/<scan_id>`, `/api/identity/scans/<scan_id>/report.pdf`, `/api/identity/assets`, `/api/identity/full-scan-assets`, `/api/identity/alerts`.

### Reports/activity/notifications

- `/api/reports/monthly*` -> monthly reports.
- `/api/activity-logs/me*`, `/api/activity-logs/track`.
- `/notifications*`, `/api/admin/notifications*`.

### Admin

- `/api/admin/auth/login`, `/verify-2fa`, `/me`, `/logout`.
- `/api/admin/users*`, `/api/admin/roles`, `/api/admin/permissions`.
- `/api/admin/threats*`.
- `/api/admin/audit-logs*`.
- `/api/admin/reports/*`.
- `/api/admin/pcap/overview`, `/api/admin/pcap/jobs/<job_id>/export`.
- `/api/admin/ai-governance/*`.
- `/api/admin/security-simulation/*`.

## Authentication/authorization flow

- User auth: token decoding happens in `get_current_user`, `require_full_auth_user`, `_create_jwt_token` in `Backend/app.py`.
- Admin auth: admin console token includes `scope = "admin_console"` and is checked by admin helpers in `Backend/app.py`.
- Frontend stores `sentinel_auth_token`, `sentinel_refresh_token`, and `sentinel_admin_token` in `localStorage` in pages like `LoginPage.tsx`, `AdminLoginPage.tsx`.

## Background jobs

- PCAP jobs use `JobRegistry` from `Backend/pcap_engine/jobs.py` and ThreadPoolExecutor in `Backend/app.py`.
- Cleanup scheduler is started by `ensure_cleanup_scheduler_started` and `start_cleanup_scheduler`.
- Monthly reports have `run_monthly_security_reports` in `Backend/reports.py`.
- Identity legacy has `autoscan_job` in `Backend/identityleak.py`.

## File upload handling

- PCAP: `validate_pcap_upload` checks extension `.pcap/.pcapng` and magic bytes.
- Vault: `validate_vault_upload` blocks dangerous extensions/MIME/magic and validates common formats.
- Path safety: `_contained_path_or_response`, `ensure_path_within_directory`.

## Backend to database

- SQLAlchemy models use `db.Model` and shared `db` from `Backend/extensions.py`.
- Phishing and identity web use sqlite3 directly in module-specific files.

## Backend to AI/ML

- PCAP: `run_pcap_pipeline` calls tshark/Zeek/feature builders, `predict_flows`, `fuse_scores`, `build_report`.
- Phishing: `scan_url` calls `predict_url`, `calculate_risk`, `get_domain_reputation`.
- Chatbot: `route_chatbot_llm` calls Ollama/Gemini providers or fallback.

## Important backend functions

| Function | File | Does | Input | Output | Called by | Calls | Related frontend |
|---|---|---|---|---|---|---|---|
| `signup` | `Backend/app.py` | creates user + verification flow | signup JSON | user/status | `/api/auth/signup` | `send_email` helpers | `SignUpPage.tsx` |
| `login` | `Backend/app.py` | verifies credentials/session state | email/password | token or 2FA state | `/api/auth/login` | JWT helpers | `LoginPage.tsx` |
| `check_password` | `password_checker/routes.py` | password breach/strength check | password | pwned/count/score | `/api/password/check` | `check_pwned_password` | `PasswordCheckerPage.tsx` |
| `scan_url` | `phishing_scanner/scan.py` | phishing risk scan | url | ML/VT/final risk | `/api/v1/scan-url` | `predict_url`, `get_domain_reputation` | `PhishingScannerPage.tsx` |
| `upload_document` | `encrypted_file_vault/routes.py` | encrypt/store uploaded file | file/password | document metadata | `/api/documents` POST | vault crypto/upload validation | `FileVaultPage.tsx` |
| `download_document` | `encrypted_file_vault/routes.py` | decrypt/download file | doc id/password | file response | `/api/documents/<id>/download` | vault crypto | `FileVaultPage.tsx` |
| `run_pcap_pipeline` | `Backend/app.py` | PCAP analysis pipeline | pcap/job settings | report/state | background job | tshark, Zeek, ML, reporter | `PcapAnalyzerPage.tsx` |
| `analyze_pcap` | `Backend/app.py` | accepts PCAP upload and creates job | multipart file | job id/status | `/analyze-pcap` | `validate_pcap_upload`, job registry | `PcapAnalyzerPage.tsx` |
| `identity_web_scan` | `Backend/app.py` | creates identity scan/findings | identifiers | scan result | `/api/identity/web-scan` | `run_identity_web_scan` | `IdentityLeakMonitorPage.tsx` |
| `build_monthly_security_report_data` | `Backend/reports.py` | aggregates module data | user/month | payload | report endpoints | DB queries | `MonthlyReportsPage.tsx` |
| `admin_pcap_overview` | `Backend/app.py` | admin PCAP dashboard data | query | overview payload | `/api/admin/pcap/overview` | job/report helpers | `AdminConsolePage.tsx` |
| `chatbot_llm` | `Backend/app.py` | assistant answer | message/module | answer/provider info | `/api/chatbot/llm` | context builders/providers | `ChatbotWorkspacePage.tsx` |

## Limitations

- `Backend/app.py` is very large; architecture is functional but tightly coupled.
- Some features are optional by environment variables.
- Tests exist, but this inspection did not execute the full test suite.
