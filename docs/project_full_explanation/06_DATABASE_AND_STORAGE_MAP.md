# 06 - Database and Storage Map

## SQLAlchemy models/tables

| Table/model | File/class | Main fields visible | Relationships/use | Module |
|---|---|---|---|---|
| `user` / `User` | `Backend/app.py` | `id`, `email`, `password_hash`, `full_name`, `is_email_verified`, `two_factor_secret`, `admin_role`, `admin_status`, session/emergency fields | referenced by many `user_id` foreign keys | Auth/admin |
| `password_reset_tokens` / `PasswordResetToken` | `Backend/app.py` | `user_id`, `token_hash`, `expires_at`, `used_at` | password reset | Auth |
| `password_checks` / `PasswordCheck` | `Backend/app.py` | `user_id`, `masked_password`, `strength_label`, `score`, `breach_count`, `verdict`, `created_at` | password history | Password |
| `password_history` / `PasswordHistory` | `Backend/app.py` | `user_id`, `password_hash`, `partial_password`, `breach_count`, `status` | legacy/older password tracking | Password |
| `refresh_token` / `RefreshToken` | `Backend/app.py` | `user_id`, `token`, `expires_at`, `user_agent` | login refresh | Auth |
| `security_audit_log` / `SecurityAuditLog` | `Backend/app.py` | `user_id`, `action`, `details_json`, `created_at` | audit events | Security |
| `admin_audit_log` / `AdminAuditLog` | `Backend/app.py` | actor fields, `action_type`, `module`, `target_*`, `status`, `severity`, `metadata_json` | admin audit | Admin |
| `user_notification` / `UserNotification` | `Backend/app.py` | `user_id`, `type`, `severity`, `title`, `body`, `job_id`, `metadata_json`, `is_read` | notifications | Notifications |
| `admin_notification_read` / `AdminNotificationRead` | `Backend/app.py` | `admin_email`, `notification_key`, `read_at` | admin read status | Admin notifications |
| `pcap_alert` / `PcapAlertRecord` | `Backend/app.py` | `user_id`, `job_id`, `alert_key`, `severity`, `risk_label`, `src_ip`, `dst_ip`, `dismissed_at` | persisted PCAP alerts | PCAP |
| `monthly_security_report` / `MonthlySecurityReport` | `Backend/app.py` | `user_id`, `report_month`, `report_year`, `report_payload_json`, `pdf_path`, `status` | monthly reports | Reports |
| `linked_account` / `LinkedAccount` | `Backend/app.py` | `user_id`, `email`, `account_type`, `verification_status`, `two_factor_enabled` | settings linked emails | Settings |
| `contact_message` / `ContactMessage` | `Backend/app.py` | `full_name`, `email`, `category`, `subject`, `message`, `status` | contact support | Public/contact |
| `vault_documents` / `VaultDocument` | `Backend/encrypted_file_vault/models.py` | `filename`, `stored_filename`, `user_id`, `file_hash`, `salt`, `offline_enabled`, `signature`, `hmac_key` | vault files | Vault |
| `user_activity_logs` / `UserActivityLog` | `Backend/activity_logs.py` | `event_id`, `user_id`, `module`, `action_type`, `status`, `severity`, `risk_score`, `metadata_json`, `is_sensitive` | user audit trail | Activity |
| `gamification_event` | `Backend/gamification/models.py` | `user_id`, `event_type`, `event_key`, `job_id`, `alert_id`, `points_awarded` | event history | Gamification |
| `user_gamification_profile` | `Backend/gamification/models.py` | `user_id`, points/level/streak/scans/badges | user progress | Gamification |
| `user_badge`, `user_challenge`, `gamification_daily_stat`, `user_alert_review_state`, `investigation_note` | `Backend/gamification/models.py` | badge/challenge/stats/review/note fields | gamification and PCAP alert review | Gamification/PCAP |

## SQLite module databases

| Database/table | File | Fields confirmed | Module |
|---|---|---|---|
| `scans` | `Backend/phishing_scanner/database.py` | `id`, `user_id`, `url`, `risk`, `result`, `timestamp` | Phishing |
| `leaked_data` | `Backend/identityleak.py` | email/phone/username/source-like fields from CSV import | Identity legacy |
| `monitored_assets` | `Backend/identityleak.py` | `user_id`, `asset`, `asset_type`, `auto_scan`, `enabled`, `last_status`, `last_matches` | Identity legacy |
| `asset_breaches`, `scan_logs` | `Backend/identityleak.py` | breach/log fields | Identity legacy |
| `identity_scans` | `services/identity_web_scraper/database.py` | `email`, `username`, `domain`, `status`, `created_at`, `user_id` | Identity web |
| `identity_findings` | same file | source/title/url/snippet/risk-like fields | Identity web |
| `identity_alerts` | same file | `scan_id`, `module`, `title`, `message`, `severity`, `is_read`, `user_id` | Identity web |
| `identity_monitored_assets` | same file | asset type/value, scan status/count fields, `user_id` | Identity web |

## What is stored

- Auth: password hashes, refresh tokens, 2FA secrets, verification tokens.
- Password Checker: masked password only (`********`), strength, score, breach count.
- Phishing: scanned URL and risk/category in SQLite.
- Vault: encrypted file on disk + metadata/salt/hash/signature in DB.
- Identity: scan identifiers and findings; sensitive identifiers should be sanitized in screenshots.
- PCAP: uploaded/runtime files, reports/evidence bundles, alert metadata with IPs.
- Reports: JSON payload and PDF path.
- Logs: user/admin audit metadata.

## File storage

- Vault upload directory: `get_upload_dir` in `Backend/encrypted_file_vault/routes.py` resolves project `upload`.
- PCAP run directory: `BASE_RUN_FOLDER = os.getenv("PCAP_RUN_FOLDER", Backend/pcap_runs)` in `Backend/app.py`.
- Monthly PDF path stored in `MonthlySecurityReport.pdf_path`; generated by `render_monthly_security_report_pdf`.
- Root repo contains sample/runtime Zeek logs like `conn.log`, `dns.log`, `ssl.log`, and PCAP sample `ids2017_benign_monday_00003_20170703141409.pcap`.

## Cleanup/deletion behavior

- Vault delete route `delete_document` removes document metadata and file.
- PCAP cleanup scheduler exists: `start_cleanup_scheduler` and `ensure_cleanup_scheduler_started`.
- PCAP alerts clear route soft-dismisses via `dismissed_at`.
- Identity web has `identity_clear_scan_history` and database `clear_history`.
- Phishing delete uses `delete_scan(scan_id, user.id)`.

## Sensitive data risks

- `.env` and `Backend/.env` may contain secrets and must not appear in screenshots.
- Identity screenshots may show real emails/usernames/domains.
- PCAP screenshots may show IPs, ports, filenames, and attack labels.
- Vault screenshots may show filenames.
- Admin audit logs may show actor email/IP/user agent.
- Report PDFs may include summaries from multiple modules.

## Sanitization for graduation screenshots

Blur or replace: emails, phone numbers, IP addresses, URLs, filenames, tokens, QR codes, TOTP secrets, API keys, SMTP settings, Google Drive folder IDs, raw PCAP filenames if private.
