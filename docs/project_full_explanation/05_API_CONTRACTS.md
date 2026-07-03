# 05 - API Contracts

ملاحظة: العقود هنا مبنية من route names وfrontend callers والحقول الظاهرة في الكود. بعض responses كبيرة ومتغيرة، لذلك يتم ذكر الحقول المؤكدة فقط.

## Auth

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/api/auth/signup` | No | Public | user signup JSON | status/message/email info | 400/409/500 | `signup` | `SignUpPage.tsx` | SMTP affects email delivery |
| POST | `/api/auth/login` | No | Public | email/password | token or 2FA pending state | 400/401/423/429 | `login` | `LoginPage.tsx` | may require 2FA |
| POST | `/api/auth/refresh` | refresh | User | refresh token/cookie | new access token | 401 | `refresh` | `FileVaultPage.tsx`, `MonthlyReportsPage.tsx` | used for retry |
| GET | `/api/auth/me` | Yes | User | headers/cookie | `user` | 401 | `get_me` | `Layout.tsx`, `SettingsPage.tsx` | session validation |
| POST | `/api/auth/logout` | Yes | User | none | message | 401 | `logout` | `Layout.tsx` | clears session server side |
| POST | `/api/auth/forgot-password` | No | Public | email | generic message | 400/429/500 | `forgot_password` | `ForgotPasswordPage.tsx` | email optional/config-dependent |
| POST | `/api/auth/reset-password` | No | Public | token/password | message | 400/410 | `reset_password` | `ResetPasswordPage.tsx` | uses `PasswordResetToken` |
| GET | `/api/auth/verify-email-token` | No | Public | query `token` | email/pending token | 400/410 | `verify_email` | `VerifyEmailPage.tsx` | may require 2FA setup |
| GET | `/api/auth/2fa/setup` | pending token | User | email/query | QR/secret/setup info | 401/400 | `setup_2fa` | `Setup2FAPage.tsx` | TOTP |
| POST | `/api/auth/2fa/verify-setup` | pending token | User | code | success | 400/401 | `verify_2fa_setup` | `Setup2FAPage.tsx` | enables 2FA |
| POST | `/api/auth/2fa/verify-login` | pending token | User | code | token/refresh | 400/401 | `verify_2fa_login` | `Login2FAPage.tsx` | completes login |

## Password Checker

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/api/password/check` | Yes | User | `{password}` | `pwned`, `count`, `strength_label`, `score`, `history_item` | 400/401/503/500 | `check_password` | `PasswordCheckerPage.tsx` | raw password not saved |
| GET | `/api/password/history` | Yes | User | none | `{history}` | 401/500 | `get_user_password_history` | `PasswordCheckerPage.tsx` | limit 50 |
| DELETE | `/api/password/history` | Yes | User | none | `{deleted}` | 401/500 | `clear_user_password_history` | `PasswordCheckerPage.tsx` | clears current user |
| POST/DELETE | `/api/password/history/clear` | Yes | User | none | `{deleted}` | 401/500 | `clear_user_password_history` | not primary | alias |

## Phishing

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/api/v1/scan-url` | Yes | User | `{url}` | `ml_result`, `risk_score`, `category`, `virustotal`, `final_category`, `final_risk_score` | 400/401 | `scan_url` | `PhishingScannerPage.tsx` | accepts http/https only |
| GET | `/api/v1/scans` | Yes | User | none | scan list | 401 | `get_scans` | `PhishingScannerPage.tsx` | SQLite `scans` |
| DELETE | `/api/v1/scan/<scan_id>` | Yes | User | path id | message | 401 | `delete_scan_route` | `PhishingScannerPage.tsx` | user-scoped delete |

## Vault

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/documents/rules` | Yes | User | none | allowed/blocked rules | 401 | `document_rules` | `FileVaultPage.tsx` | validates UI guidance |
| GET | `/api/documents` | Yes | User | none | documents list | 401/500 | `list_documents` | `FileVaultPage.tsx`, `DashboardPage.tsx` | user-scoped |
| POST | `/api/documents` | Yes | User | multipart file/password | document metadata | 400/401/413/500 | `upload_document` | `FileVaultPage.tsx` | encrypted storage |
| POST | `/api/upload` | Yes | User | multipart | same as upload | same | `upload_alias` | legacy/alias | alias |
| PATCH | `/api/documents/<doc_id>/offline` | Yes | User | enabled flag/password | updated state | 400/401/404 | `toggle_offline_access` | `FileVaultPage.tsx` | ownership checked |
| POST | `/api/documents/<doc_id>/verify` | Yes | User | password | integrity result | 400/401/404 | `verify_document_integrity` | `FileVaultPage.tsx` | hash/signature |
| POST | `/api/documents/<doc_id>/download` | Yes | User | password | file | 400/401/404 | `download_document` | `FileVaultPage.tsx` | old GET download blocked |
| DELETE | `/api/documents/<doc_id>` | Yes | User | none | deleted | 401/404 | `delete_document` | `FileVaultPage.tsx` | deletes metadata/file |

## PCAP

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/analyze-pcap` or `/pcap/analyze` | Yes | User | multipart PCAP/settings | job id/status | 400/401/413/500 | `analyze_pcap` | `PcapAnalyzerPage.tsx` | validates magic bytes |
| GET | `/jobs` or `/pcap/jobs` | Yes | User | `limit` | job history | 401 | `list_jobs` | `PcapAnalyzerPage.tsx` | user-scoped |
| GET | `/job/<job_id>` or `/pcap/status/<job_id>` | Yes | User | id | job state/report | 401/403/404 | `get_job` | `PcapAnalyzerPage.tsx` | ownership checks |
| POST | `/api/pcap/cancel/<job_id>` | Yes | User | id | cancelled/status | 401/403/404 | `cancel_pcap_job` | `PcapAnalyzerPage.tsx` | can terminate process |
| GET | `/job/<job_id>/export?type=report|evidence` | Yes | User | query type | file/zip/json | 401/403/404 | `export_job_artifact` | `PcapAnalyzerPage.tsx` | protected artifacts |
| GET | `/api/pcap/alerts` | Yes | User | query limit | alerts | 401 | `list_pcap_alerts` | notification/dashboard utils | persisted alerts |
| POST | `/api/pcap/alerts/clear` | Yes | User | ids/all visible | dismissed result | 401 | `dismiss_visible_pcap_alerts` | notification utils | soft hide |

## Identity

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/api/identity/web-scan` | Yes | User | email/username/domain | scan/findings/risk | 400/401/500 | `identity_web_scan` | `IdentityLeakMonitorPage.tsx` | web scraper sources |
| GET | `/api/identity/scans` | Yes | User | none | scans | 401 | `identity_web_scans` | `IdentityLeakMonitorPage.tsx` | user-scoped |
| DELETE | `/api/identity/scans` | Yes | User | none | cleared | 401 | `identity_clear_scan_history` | page actions | clears history |
| GET | `/api/identity/scans/<scan_id>` | Yes | User | id | scan detail | 401/404 | `identity_web_scan_detail` | page actions | user-scoped |
| GET | `/api/identity/findings/<scan_id>` | Yes | User | id | findings | 401/404 | `identity_web_findings` | page actions | user-scoped |
| GET | `/api/identity/scans/<scan_id>/report.pdf` | Yes | User | id | PDF | 401/404/429 | `identity_web_scan_pdf_report` | `IdentityLeakMonitorPage.tsx` | export |
| GET/POST | `/api/identity/assets` | Yes | User | asset data for POST | list/created asset | 400/401 | `identity_assets`, `identity_create_asset` | `IdentityLeakMonitorPage.tsx` | monitored assets |
| DELETE | `/api/identity/assets/<asset_id>` | Yes | User | id | deleted | 401/404 | `identity_delete_asset` | page actions | ownership |
| POST | `/api/identity/full-scan-assets` | Yes | User | none/options | scan results | 401/500 | `identity_full_scan_assets` | page actions | all assets |
| GET | `/api/identity/alerts` | Yes | User | none | alerts | 401 | `identity_web_alerts` | notifications/page | unread support |

## Reports/activity/gamification/chatbot/admin

| Group | Confirmed routes | Backend functions | Frontend callers |
|---|---|---|---|
| Monthly reports | `/api/reports/monthly`, `/latest`, `/<month>`, `/<month>/download`, `/<month>/upload-drive`, `/generate` | `list_monthly_security_reports`, `download_monthly_security_report`, `generate_monthly_security_report` | `MonthlyReportsPage.tsx` |
| Activity logs | `/api/activity-logs/me`, `/summary`, `/export`, `/<event_id>`, `/track` | `list_my_activity_logs`, `export_my_activity_logs`, `track_user_activity_event` | `UserActivityLogsPage.tsx`, `activityLogs.ts` |
| Gamification | `/api/gamification/profile`, `/badges`, `/challenges`, `/history`, `/overview`, `/alert-context`, `/events` | `gamification_*` in `gamification/routes.py` | `utils/gamification.ts` |
| Chatbot | `/api/chatbot/llm`, `/pcap`, `/identity`, debug endpoints | `chatbot_llm`, `pcap_chatbot`, `identity_chatbot` | `ChatbotWorkspacePage.tsx` |
| Admin auth | `/api/admin/auth/login`, `/verify-2fa`, `/me`, `/logout` | `admin_console_*` | `AdminLoginPage.tsx`, `AdminConsolePage.tsx` |
| Admin management | `/api/admin/users*`, `/roles`, `/permissions`, `/threats*`, `/audit-logs*`, `/pcap/overview`, `/ai-governance/*`, `/security-simulation/*` | admin functions in `Backend/app.py` | `AdminConsolePage.tsx`, admin components/services |

## Settings, integrations, contact, dashboard support

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| PATCH/POST | `/api/settings/profile` | Yes | User | profile fields | profile/settings | 401/400 | `update_profile_settings` | `SettingsPage.tsx` | current user |
| PATCH/POST | `/api/settings/security` | Yes | User | security settings | updated settings | 401/400 | `update_security_settings` | `SettingsPage.tsx` | timeout/panic/security |
| PATCH/POST | `/api/settings/password` | Yes | User | current/new password | message | 401/400 | `update_password_settings` | `SettingsPage.tsx` | password change |
| GET/POST | `/api/settings/linked-accounts` | Yes | User | account for POST | list/created account | 401/400 | `get_linked_accounts_settings`, `create_linked_account_settings` | `SettingsPage.tsx` | linked emails |
| PUT/DELETE | `/api/settings/linked-accounts/<account_id>` | Yes | User | account update/delete | updated/deleted | 401/404 | `update_linked_account_settings`, `delete_linked_account_settings` | `SettingsPage.tsx` | ownership |
| POST | `/api/settings/linked-accounts/<account_id>/send-verification` | Yes | User | none | send status | 401/404 | `resend_linked_account_verification_settings` | `SettingsPage.tsx` | SMTP-dependent |
| POST | `/api/settings/linked-accounts/<account_id>/set-primary` | Yes | User | none | primary status | 401/404 | `set_primary_linked_account_settings` | `SettingsPage.tsx` | current user |
| POST | `/api/security/emergency-mode` | Yes | User | reason/duration | emergency state | 401/400 | `activate_emergency_mode` | `Layout.tsx` | panic/emergency mode |
| GET | `/api/security-score` | Yes | User | none | module score | 401 | `security_score` | identity/dashboard callers | identity-oriented score |
| GET | `/api/security/global-score` | Yes | User | none | global score | 401 | `global_security_score` | `SimpleDashboard.tsx` | dashboard score |
| GET/POST | `/api/ai/vault/analyze` | Yes | User | optional body | vault behavior analysis | 401 | `analyze_my_vault_behavior` | `SimpleDashboard.tsx`, `ChatbotWorkspacePage.tsx` | rule/behavior analysis |
| GET | `/api/ai/vault/alerts` | Yes | User | none | vault alerts | 401 | `list_my_vault_ai_alerts` | dashboard/chatbot callers | vault alerts |
| POST | `/api/contact/support` | No/optional | Public | contact form | saved/sent status | 400/500 | `submit_contact_support` | `ContactPage.tsx` | SMTP optional |
| GET | `/api/public/app-settings` | No | Public | none | public settings | 500 | `public_app_settings` | `AppSettingsContext.tsx` | app name/settings |

## Notifications and integration channels

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/notifications` | Yes | User | query | notifications | 401 | `list_notifications` | `NotificationCenter.tsx` | user feed |
| GET | `/notifications/unread-count` | Yes | User | none | count | 401 | `notification_unread_count` | `NotificationCenter.tsx` | unread badge |
| POST | `/notifications/read` | Yes | User | notification ids | updated | 401 | `mark_notifications_read` | `NotificationCenter.tsx` | bulk read |
| POST | `/notifications/<id>/read` | Yes | User | id | updated | 401/404 | `mark_notification_read` | `NotificationCenter.tsx` | one read |
| POST | `/notifications/read-all` | Yes | User | none | updated | 401 | `mark_all_notifications_read` | `NotificationCenter.tsx` | all read |
| GET | `/api/integrations/channels` | Yes | User/Admin | none | channel settings | 401 | `get_notification_channels` | `SettingsPage.tsx`, `adminNotificationsService.ts` | alias without `/api` also exists |
| PATCH/POST | `/api/integrations/channels/email` | Yes | User/Admin | email channel data | updated | 401/400 | `update_email_notification_channel` | `SettingsPage.tsx` | SMTP config not exposed |
| PATCH/POST | `/api/integrations/channels/sms` | Yes | User/Admin | sms channel data | updated | 401/400 | `update_sms_notification_channel` | settings/admin service | implementation/config caveat |
| PATCH/POST | `/api/integrations/channels/telegram` | Yes | User/Admin | telegram channel data | updated | 401/400 | `update_telegram_notification_channel` | settings/admin service | bot token config-dependent |
| POST | `/api/integrations/telegram/test` | Yes | User/Admin | test payload | test status | 401/500 | `test_telegram_integration` | settings/admin service | alias without `/api` |

## Admin detailed endpoints

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/api/admin/auth/login` | No | Admin | email/password | token or 2FA state | 400/401/429 | `admin_console_login` | `AdminLoginPage.tsx` | env/database credentials |
| POST | `/api/admin/auth/verify-2fa` | pending/admin | Admin | code | admin token | 400/401 | `admin_console_verify_2fa` | `AdminLoginPage.tsx` | admin 2FA |
| GET | `/api/admin/auth/me` | Yes | Admin | none | admin profile | 401 | `admin_console_me` | `AdminConsolePage.tsx` | scope check |
| POST | `/api/admin/auth/logout` | Yes | Admin | none | message | 401 | `admin_console_logout` | `AdminConsolePage.tsx` | logout |
| GET/POST | `/api/admin/users` | Yes | Admin | query/create body | users/created user | 401/403/400 | `admin_list_users`, `admin_create_user` | `AdminConsolePage.tsx` | user management |
| GET | `/api/admin/users/summary` | Yes | Admin | none | summary | 401/403 | `admin_users_summary` | `AdminConsolePage.tsx` | dashboard cards |
| PATCH | `/api/admin/users/<user_id>/status` | Yes | Admin | status | updated user | 401/403/404 | `admin_update_user_status` | `AdminConsolePage.tsx` | status management |
| PATCH | `/api/admin/users/<user_id>/role` | Yes | Admin | role | updated user | 401/403/404 | `admin_update_user_role` | `AdminConsolePage.tsx` | role change |
| DELETE | `/api/admin/users/<user_id>` | Yes | Admin | id | deleted | 401/403/404 | `admin_delete_user` | `AdminConsolePage.tsx` | destructive admin action |
| GET | `/api/admin/roles` | Yes | Admin | none | roles | 401/403 | `admin_list_roles` | `AdminConsolePage.tsx` | role options |
| GET | `/api/admin/permissions` | Yes | Admin | none | permissions | 401/403 | `admin_list_permissions` | `AdminConsolePage.tsx` | permission options |
| GET | `/api/admin/threats` | Yes | Admin | filters | threat rows | 401/403 | `admin_list_threats` | `AdminConsolePage.tsx` | threat monitoring |
| GET | `/api/admin/threats/summary` | Yes | Admin | filters | summary | 401/403 | `admin_threats_summary` | `AdminConsolePage.tsx` | threat dashboard |
| POST | `/api/admin/threats/audit-action` | Yes | Admin | action payload | audit logged | 401/403/400 | `admin_audit_threat_action` | `AdminConsolePage.tsx` | manual admin action |
| GET | `/api/admin/threats/export` | Yes | Admin | filters | CSV/file | 401/403 | `admin_export_threats` | `AdminConsolePage.tsx` | export |
| GET | `/api/admin/audit-logs` | Yes | Admin | filters | audit rows/summary | 401/403 | `admin_audit_logs` | `AdminAuditTrailPage.tsx` | combined audit |
| GET | `/api/admin/audit-logs/export` | Yes | Admin | filters | CSV/file | 401/403 | `admin_audit_logs_export` | `AdminAuditTrailPage.tsx` | export |
| GET | `/api/admin/pcap/overview` | Yes | Admin | filters/limit | overview | 401/403 | `admin_pcap_overview` | `adminPcapOverview.ts`, `AdminConsolePage.tsx` | PCAP monitoring |
| GET | `/api/admin/pcap/jobs/<job_id>/export` | Yes | Admin | query type | artifact | 401/403/404 | `admin_export_pcap_job_artifact` | `adminPcapOverview.ts` | admin export |
| GET/PATCH/POST | `/api/admin/system-settings` | Yes | Admin | settings | settings | 401/403 | `admin_system_settings` | `AdminConsolePage.tsx` | app/system settings |
| GET/PATCH | `/api/admin/settings/profile` | Yes | Admin | profile | profile | 401/403 | `admin_settings_profile` | `AdminConsolePage.tsx` | admin settings |
| POST | `/api/admin/settings/change-password` | Yes | Admin | current/new password | message | 401/403/400 | `admin_settings_change_password` | `AdminConsolePage.tsx` | admin password |
| GET/PATCH | `/api/admin/settings/notification-preferences` | Yes | Admin | preferences | preferences | 401/403 | `admin_settings_notification_preferences` | `AdminConsolePage.tsx` | notification prefs |
| GET/PATCH | `/api/admin/settings/preferences` | Yes | Admin | preferences | preferences | 401/403 | `admin_settings_preferences` | `AdminConsolePage.tsx` | general prefs |
| GET/PATCH/POST | `/api/admin/notification-control/settings` | Yes | Admin | settings | settings | 401/403 | `admin_notification_control_settings` | `NotificationControlCenterPage.tsx`, service | notification center |
| GET | `/api/admin/notification-control/status` | Yes | Admin | none | status/channels | 401/403 | `admin_notification_control_status` | `adminNotificationsService.ts` | status |
| POST | `/api/admin/notification-control/test` | Yes | Admin | test payload | result | 401/403/500 | `admin_notification_control_test` | `adminNotificationsService.ts` | delivery test |
| POST | `/api/admin/notification-control/telegram/test` | Yes | Admin | test payload | result | 401/403/500 | `admin_test_telegram_notification` | admin service | Telegram config-dependent |
| GET | `/api/admin/notifications` | Yes | Admin | query | notifications | 401/403 | `admin_list_notifications` | `NotificationCenter.tsx` | admin notification feed |
| GET | `/api/admin/notifications/unread-count` | Yes | Admin | none | count | 401/403 | `admin_notification_unread_count` | `NotificationCenter.tsx` | unread |
| POST | `/api/admin/notifications/read` | Yes | Admin | ids | updated | 401/403 | `admin_mark_notifications_read` | `NotificationCenter.tsx` | read selected |
| POST | `/api/admin/notifications/read-all` | Yes | Admin | none | updated | 401/403 | `admin_mark_all_notifications_read` | `NotificationCenter.tsx` | read all |
| GET | `/api/admin/security-simulation/tests` | Yes | Admin | none | allowed tests | 401/403 | `admin_security_simulation_tests` | `SecurityValidationLabPage.tsx` | allowlist tests |
| POST | `/api/admin/security-simulation/run` | Yes | Admin | test id | result | 401/403/400 | `admin_security_simulation_run` | `SecurityValidationLabPage.tsx` | predefined requests |

## Admin report endpoints

| Method | Route | Auth | Role | Request/query | Success response | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|
| GET | `/api/admin/reports/identity` | Yes | Admin | filters | summary payload | `admin_identity_report_summary` / early wrapper | `adminReportsService.ts` | identity report |
| GET | `/api/admin/reports/identity/export` | Yes | Admin | `format=csv` | CSV/file | `admin_identity_report_export` / early wrapper | `adminReportsService.ts` | export |
| GET | `/api/admin/reports/password-risk-summary` | Yes | Admin | filters | summary payload | `admin_password_risk_report_summary` / early wrapper | `adminReportsService.ts` | password report |
| GET | `/api/admin/reports/password-risk-summary/export` | Yes | Admin | `format=csv` | CSV/file | `admin_password_risk_report_export` / early wrapper | `adminReportsService.ts` | export |
| GET | `/api/admin/reports/phishing-incidents` | Yes | Admin | filters | summary payload | `admin_phishing_incidents_report_summary` / early wrapper | `adminReportsService.ts` | phishing report |
| GET | `/api/admin/reports/phishing-incidents/export` | Yes | Admin | format/filters | file | `admin_phishing_incidents_report_export` / early wrapper | `adminReportsService.ts` | export |
| GET | `/api/admin/reports/monthly-security` | Yes | Admin | filters | summary payload | `admin_monthly_security_report_summary` / early wrapper | `adminReportsService.ts` | monthly admin |
| GET | `/api/admin/reports/user-activity` | Yes | Admin | filters | summary payload | `admin_user_activity_report_summary` / early wrapper | `adminReportsService.ts` | activity report |
| GET | `/api/admin/reports/high-risk-users` | Yes | Admin | filters | summary payload | `admin_high_risk_users_report_summary` / early wrapper | `adminReportsService.ts` | risk report |
| GET | `/api/admin/reports/security-incidents` | Yes | Admin | filters | summary payload | `admin_security_incidents_report_summary` / early wrapper | `adminReportsService.ts` | incidents |
| GET | `/api/admin/reports/file-vault-activity-summary` | Yes | Admin | filters | summary payload | `admin_file_vault_activity_report_summary` / early wrapper | `ReportsExportCenterPage.tsx` | vault activity |

Frontend-only/not confirmed in backend route decorators during this inspection:
`adminReportsService.ts` calls `/api/admin/reports/pcap/generate`, `/api/admin/reports/pcap/<report_id>/export`, and `/api/admin/reports/pcap/<report_id>/regenerate`, but `Backend/app.py` route decorators found in this pass did not confirm matching endpoints. Treat these as frontend-only or pending verification until backend routes are found/added.

## Admin AI governance endpoints

| Method | Route | Auth | Role | Request | Success response | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|
| GET | `/api/admin/ai-governance/summary` | Yes | Admin | none | summary from metrics | `admin_ai_governance_summary` | Admin AI section | file-reported metrics |
| GET | `/api/admin/ai-governance/model-registry` | Yes | Admin | none | model registry | `admin_ai_governance_model_registry` | Admin AI section | local model files |
| GET | `/api/admin/ai-governance/classification-report` | Yes | Admin | none | report rows | `admin_ai_governance_classification_report` | Admin AI section | metrics file |
| GET | `/api/admin/ai-governance/false-positive-trend` | Yes | Admin | none | trend payload | `admin_ai_governance_false_positive_trend` | Admin AI section | derived/synthetic from metrics |
| PATCH | `/api/admin/ai-governance/confidence-thresholds` | Yes | Admin | thresholds | updated config | `admin_ai_governance_update_confidence_thresholds` | Admin AI section | runtime/config caveat |
| POST | `/api/admin/ai-governance/retrain` | Yes | Admin | retrain request | status | `admin_ai_governance_retrain` | Admin AI section | do not claim real retraining without running |

## Invitation endpoints

| Method | Route | Auth | Role | Request | Success response | Errors | Backend function | Frontend caller | Notes |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/api/invitations/<token>` | No | Invited user | token | invitation details | 404/410 | `get_invitation_details` | `AcceptInvitationPage.tsx` | admin-created invite |
| POST | `/api/invitations/<token>/accept` | No | Invited user | acceptance fields | user/session/2FA state | 400/404/410 | `accept_invitation` | `AcceptInvitationPage.tsx` | may require 2FA |
