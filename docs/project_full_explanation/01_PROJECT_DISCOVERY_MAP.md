# 01 - Project Discovery Map

## Backend files

| Path | Purpose | Important names | Module | Why it matters |
|---|---|---|---|---|
| `Backend/app.py` | Flask entry point, config, routes, auth, PCAP pipeline, admin, reports, notifications | `app`, `User`, `get_current_user`, `require_full_auth_user`, `run_pcap_pipeline`, `analyze_pcap`, `admin_required` | Core | أكبر ملف يثبت أغلب backend behavior |
| `Backend/extensions.py` | Shared SQLAlchemy object | `db` | Core storage | كل SQLAlchemy models تستخدمه |
| `Backend/upload_security.py` | Upload validation | `validate_pcap_upload`, `validate_vault_upload` | PCAP/Vault security | يثبت file type/header checks |
| `Backend/security_utils.py` | Path and error helpers | `ensure_path_within_directory`, `safe_error_response`, `sanitize_csv_row` | Security | يحمي exports/paths |
| `Backend/reports.py` | Monthly report aggregation and PDF rendering | `build_monthly_security_report_data`, `render_monthly_security_report_pdf`, `generate_and_store_monthly_security_report` | Reports | مصدر user monthly reports |
| `Backend/activity_logs.py` | User activity log model and helpers | `UserActivityLog`, `UserEventPayload`, `log_user_activity` | Activity logs | يثبت tracking/audit للأحداث |
| `Backend/identityleak.py` | Legacy identity leak SQLite flow | `init_db`, `perform_scan_for_asset`, `full_scan` | Identity | يثبت legacy monitored assets/leaked CSV path |

## Backend module files

| Path | Purpose | Important names | Module | Why it matters |
|---|---|---|---|---|
| `Backend/password_checker/routes.py` | Password API routes | `check_password`, `get_user_password_history`, `clear_user_password_history` | Password Checker | routes `/api/password/*` |
| `Backend/password_checker/hibp_client.py` | HIBP k-anonymity check | `check_pwned_password` | Password Checker | لا يخزن raw password، يستخدم SHA-1 prefix check |
| `Backend/phishing_scanner/scan.py` | URL scan API | `scan_url`, `combine_ml_and_virustotal`, `get_scans`, `delete_scan_route` | Phishing | routes `/api/v1/*` |
| `Backend/phishing_scanner/ml.py` | Runtime URL prediction | `predict_url` | Phishing ML | ML جزء من phishing |
| `Backend/phishing_scanner/url_features.py` | URL features | `extract_features` | Phishing ML | يثبت inputs للـ model |
| `Backend/phishing_scanner/virustotal.py` | Domain reputation integration | `get_domain_reputation`, `parse_virustotal_reputation` | Phishing | optional external reputation |
| `Backend/phishing_scanner/database.py` | SQLite scan history | `save_scan`, `get_user_scans`, `delete_scan` | Phishing storage | جدول `scans` |
| `Backend/encrypted_file_vault/routes.py` | Vault routes | `upload_document`, `download_document`, `verify_document_integrity`, `toggle_offline_access` | Vault | core vault behavior |
| `Backend/encrypted_file_vault/models.py` | Vault SQLAlchemy model | `VaultDocument` | Vault storage | stores file metadata/salt/hash/signature |
| `Backend/encrypted_file_vault/crypto.py` | Password-based crypto | `generate_salt`, `derive_key`, `get_cipher_from_password` | Vault crypto | يثبت encryption mechanism |
| `Backend/gamification/routes.py` | Gamification API | `gamification_overview`, `gamification_events` | Gamification | frontend dashboard section |
| `Backend/gamification/models.py` | Gamification models | `GamificationEvent`, `UserBadge`, `UserChallenge` | Gamification storage | points/badges/challenges |
| `Backend/gamification/service.py` | Gamification logic | `GamificationService` | Gamification | records scans/downloads/reviews |

## PCAP / model files

| Path | Purpose | Important names | Module | Why it matters |
|---|---|---|---|---|
| `Backend/pcap_engine/tshark_runner.py` | Run tshark export | `run_tshark_export` | PCAP | packet parsing dependency |
| `Backend/pcap_engine/cic_stream_features.py` | Build CIC-like features | `build_cic_features_from_tshark_csv` | PCAP features | prepares model inputs |
| `Backend/pcap_engine/ml_infer.py` | Model loading/inference/schema validation | `load_model_bundle`, `prepare_inference_frame`, `predict_flows`, `FeatureSchemaError` | PCAP ML | confirms trained feature contract |
| `Backend/pcap_engine/security_logic.py` | Verdict/severity/context logic | `label_to_severity`, `should_suppress`, `verdict_from_context`, `build_reason` | PCAP scoring | combines model/context rules |
| `Backend/pcap_engine/scorer.py` | Score fusion | `fuse_scores` | PCAP scoring | part of pipeline |
| `Backend/pcap_engine/reporter.py` | Report construction | `build_report` | PCAP reports | produces report JSON/security score |
| `Backend/pcap_engine/jobs.py` | Job registry | `JobRegistry`, `JobCancelled` | PCAP jobs | async status/history |
| `Backend/train_pcap65_model.py` | Training script | `main`, `load_csv` | PCAP training | evidence of training path |
| `Backend/model/metrics.json` | File-reported metrics for older model | `overall_accuracy`, `macro_f1`, labels | PCAP metrics | safe to mention as file-reported only |
| `Backend/model/metrics_pcap65.json` | File-reported metrics/feature columns for pcap65 model | `accuracy`, `macro_f1`, `feature_cols` | PCAP metrics | confirms 62 feature columns |

## Frontend files

| Path | Purpose | Important components/functions | Related module | Why it matters |
|---|---|---|---|---|
| `Cybersecurity Dashboard Design/src/App.tsx` | React routes | `App` | Frontend core | source of UI route map |
| `src/components/Layout.tsx` | Authenticated layout | `Layout` | Navigation/auth | checks token and `/api/auth/me` |
| `src/components/pages/SimpleDashboard.tsx` | User dashboard | `SimpleDashboard` | Dashboard | pulls documents, vault AI, security score, reports |
| `src/components/pages/PasswordCheckerPage.tsx` | Password UI | `PasswordCheckerPage` | Password Checker | calls `/api/password/check/history` |
| `src/components/pages/PhishingScannerPage.tsx` | Phishing UI | `PhishingScannerPage` | Phishing | calls `/api/v1/scan-url`, `/scans` |
| `src/components/pages/FileVaultPage.tsx` | Vault UI | `FileVaultPage` | Vault | upload/download/offline/delete |
| `src/components/pages/IdentityLeakMonitorPage.tsx` | Identity UI | `IdentityLeakMonitorPage` | Identity | scans/assets/report PDF |
| `src/components/pages/PcapAnalyzerPage.tsx` | PCAP UI | `PcapAnalyzerPage` | PCAP | upload, poll, export, charts |
| `src/components/pages/MonthlyReportsPage.tsx` | Monthly reports UI | `MonthlyReportsPage` | Reports | list/generate/download/upload |
| `src/components/pages/UserActivityLogsPage.tsx` | User logs UI | `UserActivityLogsPage` | Activity logs | list/detail/export |
| `src/components/pages/AdminConsolePage.tsx` | Admin dashboard | `AdminConsolePage` | Admin | users/threats/settings/audit sections |
| `src/components/pages/AdminLoginPage.tsx` | Admin login | `AdminLoginPage` | Admin auth | `/api/admin/auth/login`, `/verify-2fa` |
| `src/components/NotificationCenter.tsx` | Notifications UI | `NotificationCenter` | Notifications | user/admin notification fetch/read |
| `src/services/adminReportsService.ts` | Admin reports API client | report fetch/export helpers | Admin reports | evidence of frontend callers |
| `src/services/adminPcapOverview.ts` | Admin PCAP API client | `fetchAdminPcapOverview` | Admin PCAP | `/api/admin/pcap/overview` |
| `src/utils/gamification.ts` | Gamification API client | `fetchGamificationOverview`, `recordGamificationEvent` | Gamification | `/api/gamification/*` |
| `src/utils/activityLogs.ts` | Activity tracker | `trackActivityEvent` | Activity logs | `/api/activity-logs/track` |

## Important tests

| Path | Purpose | Related module |
|---|---|---|
| `Backend/tests/test_auth_rate_limits.py` | auth rate limit tests | Auth |
| `Backend/tests/test_password_reset.py` | forgot/reset password | Auth |
| `Backend/tests/test_upload_security.py` | upload validation | Vault/PCAP |
| `Backend/tests/test_pcap_route_contracts.py` | PCAP routes/export contracts | PCAP |
| `Backend/tests/test_pcap_scoring_regression.py` | PCAP scoring regressions | PCAP |
| `Backend/tests/test_pcap_artifact_protection.py` | artifact protection | PCAP security |
| `Backend/tests/test_pcap_alert_persistence_regression.py` | PCAP alerts persistence/ownership | PCAP notifications |
| `Backend/tests/test_export_hardening.py` | export safety | Reports/security |
| `Backend/tests/test_admin_audit_activity_modules.py` | audit/activity module coverage | Admin/activity |
| `Backend/tests/test_gamification_service.py` | gamification service | Gamification |
