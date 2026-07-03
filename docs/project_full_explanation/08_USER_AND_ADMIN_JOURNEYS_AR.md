# 08 - User and Admin Journeys

## Normal user registration/login

1. Signup -> `SignUpPage.tsx` -> `/api/auth/signup` -> create `User`, send verification if SMTP works -> email sent/verification message.
2. Verify email -> `VerifyEmailPage.tsx` -> `/api/auth/verify-email-token` -> mark email verified, maybe issue pending 2FA token -> setup/login next step.
3. Setup 2FA if required -> `Setup2FAPage.tsx` -> `/api/auth/2fa/setup` then `/api/auth/2fa/verify-setup` -> store enabled 2FA -> login page.
4. Login -> `LoginPage.tsx` -> `/api/auth/login` -> verify password/session state -> token or redirect to `/login-2fa`.
5. 2FA login -> `Login2FAPage.tsx` -> `/api/auth/2fa/verify-login` -> token/refresh token -> dashboard.

## User dashboard journey

Dashboard -> `SimpleDashboard.tsx` -> `/api/auth/me`, `/api/documents`, `/api/security/global-score`, `/api/reports/monthly/latest`, `/api/ai/vault/analyze` -> aggregate module data -> score/cards/recent activity shown.

## Password Checker journey

Enter password -> `PasswordCheckerPage.tsx` -> `/api/password/check` -> `_password_strength` + `check_pwned_password` + save `PasswordCheck` -> strength/breach count/history item shown.  
View history -> same page -> `/api/password/history` -> fetch current user checks -> table/list shown.  
Clear history -> same page -> DELETE `/api/password/history` -> delete current user records -> empty history.

## Phishing Scanner journey

Enter URL -> `PhishingScannerPage.tsx` -> `/api/v1/scan-url` -> validate URL -> `predict_url` -> `calculate_risk` -> optional `get_domain_reputation` -> `combine_ml_and_virustotal` -> final risk/category/guidance shown.  
History -> `/api/v1/scans` -> SQLite scan rows -> previous scans shown.  
Delete -> `/api/v1/scan/<id>` -> user-scoped deletion -> row removed.

## File Vault journey

Upload file + password -> `FileVaultPage.tsx` -> POST `/api/documents` -> `validate_vault_upload` -> encrypt file with password-derived key -> save `VaultDocument` -> file appears in list.  
Download -> same page -> POST `/api/documents/<id>/download` -> password decrypt -> file response.  
Verify -> POST `/api/documents/<id>/verify` -> recompute hash/signature check -> integrity result shown.  
Offline toggle -> PATCH `/api/documents/<id>/offline` -> update flag -> UI status changes.  
Delete -> DELETE `/api/documents/<id>` -> remove file/metadata -> list updates.

## Identity Leak journey

Scan identifier -> `IdentityLeakMonitorPage.tsx` -> `/api/identity/web-scan` -> validate email/username/domain -> create scan -> run identity web scan -> save findings/alerts -> results shown.  
Assets -> `/api/identity/assets` GET/POST/DELETE -> monitored assets list changes.  
Full scan -> `/api/identity/full-scan-assets` -> scan saved assets -> findings/alerts updated.  
PDF -> `/api/identity/scans/<scan_id>/report.pdf` -> generate PDF -> browser downloads report.

## PCAP Analyzer journey

Upload `.pcap/.pcapng` -> `PcapAnalyzerPage.tsx` -> `/analyze-pcap` -> `validate_pcap_upload` -> create job -> returns job id.  
Poll status -> `/job/<id>` -> job registry/report payload -> progress/steps shown.  
Pipeline -> `run_pcap_pipeline` -> tshark/Zeek/features/ML/scoring/report -> final report ready.  
Export -> `/job/<id>/export?type=report|evidence` -> protected artifact -> download.  
Cancel -> `/api/pcap/cancel/<id>` -> terminate/cancel job -> cancelled state.

## Monthly report journey

Open reports -> `MonthlyReportsPage.tsx` -> `/api/reports/monthly` -> existing reports shown.  
Generate -> POST `/api/reports/monthly/generate` -> `generate_and_store_monthly_security_report` -> DB record/PDF -> report card.  
Download -> `/api/reports/monthly/<month>/download` -> PDF file.  
Upload to Drive -> POST `/api/reports/monthly/<month>/upload-drive` -> Google Drive upload if configured -> link/status.

## Activity logs journey

Open activity logs -> `UserActivityLogsPage.tsx` -> `/api/activity-logs/me` -> filtered events shown.  
Open detail -> `/api/activity-logs/me/<event_id>` -> event details shown.  
Export -> `/api/activity-logs/me/export` -> CSV/file response.

## Admin login/overview journey

Admin login -> `AdminLoginPage.tsx` -> `/api/admin/auth/login` -> check admin credentials -> token or 2FA challenge.  
Verify 2FA -> `/api/admin/auth/verify-2fa` -> issue admin token -> `/admin/console`.  
Overview -> `AdminConsolePage.tsx` -> `/api/admin/auth/me`, `/api/admin/users/summary`, `/api/admin/threats/summary`, `/api/admin/pcap/overview`, `/api/admin/audit-logs` -> dashboard sections shown.

## Admin monitoring journey

Users -> `AdminConsolePage.tsx` -> `/api/admin/users` -> list/create/status/role/delete -> user table updates.  
Threats -> `/api/admin/threats`, `/summary`, `/export` -> threat monitoring/export.  
Audit -> `AdminAuditTrailPage.tsx` -> `/api/admin/audit-logs`, `/export` -> audit trail.  
PCAP -> `PcapAnalysisAdminControl.tsx` / service -> `/api/admin/pcap/overview` -> job and attack family overview.  
Reports center -> `ReportsExportCenterPage.tsx` -> `/api/admin/reports/*` -> report summaries/exports.

## Error/edge-case journey

Invalid auth -> any protected page/endpoint -> 401 -> frontend redirects/login or shows error.  
Invalid file type -> upload page -> `validate_pcap_upload` or `validate_vault_upload` -> 400 safe public message.  
Rate limit -> Flask-Limiter -> 429 via `handle_rate_limit_exceeded`.  
Missing optional config -> SMTP/Drive/LLM/VirusTotal -> code returns skipped/unavailable/config message depending endpoint.
