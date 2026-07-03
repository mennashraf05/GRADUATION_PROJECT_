# 09 - Security, Privacy, and Limitations

## Access control

- User auth uses JWT/cookies and `get_current_user`, `require_full_auth_user` in `Backend/app.py`.
- Admin auth uses separate admin token scope `ADMIN_JWT_SCOPE = "admin_console"` and admin-only helpers in `Backend/app.py`.
- Frontend protected routes are wrapped by `Layout`, but real security must be backend checks.

## Ownership checks

Confirmed ownership/user scoping appears in:

- Password history: `PasswordCheck.query.filter_by(user_id=user.id)` in `password_checker/routes.py`.
- Phishing scans: `get_user_scans(user_id=user.id)` and `delete_scan(scan_id, user.id)`.
- Vault docs: routes use current user and doc id in `encrypted_file_vault/routes.py`.
- Identity web: functions query scans/assets with `user_id` in `services/identity_web_scraper/database.py`.
- PCAP jobs/alerts: helpers like `_get_authorized_job_for_context`, `_pcap_job_matches_context`, and scoped alert functions in `Backend/app.py`.

## File validation

- PCAP: `validate_pcap_upload` allows `.pcap/.pcapng` and checks magic bytes.
- Vault: `validate_vault_upload` blocks dangerous extensions (`.exe`, `.dll`, `.env`, `.key`, `.db`, etc.), dangerous MIME types, executable headers, and validates common file signatures.
- Path safety: `ensure_path_within_directory` and contained path helpers reduce path traversal risk.

## Upload size limits

- `Backend/app.py` handles `RequestEntityTooLarge`.
- Specific configured size limits should be confirmed from deployment config and Flask/Nginx settings. Do not claim a fixed size unless owner confirms.

## Sensitive fields

Sensitive data in DB/files may include:

- `User.password_hash`, `two_factor_secret`, verification/reset tokens.
- `RefreshToken.token`.
- Vault salts/hmac/signature and encrypted files.
- Identity emails/usernames/domains/findings.
- PCAP IPs/ports/filenames/report artifacts.
- SMTP/API/Google/LLM secrets in `.env`.

## Encryption

- Vault encryption is confirmed by `encrypted_file_vault/crypto.py` using password-derived Fernet key.
- PCAP artifact encryption/protection code exists in `Backend/app.py` but depends on `PCAP_ARTIFACT_ENCRYPTION_KEY` and mode. Treat as optional/config-dependent.
- Password storage uses hashing (`generate_password_hash`, `check_password_hash`) in `Backend/app.py`.

## Logs/audit trails

- User activity: `UserActivityLog` and `/api/activity-logs/*`.
- Admin audit: `AdminAuditLog` and `/api/admin/audit-logs`.
- Security audit: `SecurityAuditLog`.
- Notifications: `UserNotification` and admin read state.

## Artifact/report risks

- PCAP evidence bundles may include network metadata/IPs.
- Monthly report PDFs may include summaries from multiple modules.
- Identity PDF reports may show leaked identifiers/findings.
- Admin exports may include user emails, IP addresses, and activity metadata.

## What the system does NOT guarantee

- لا يضمن منع الهجمات.
- لا يضمن اكتشاف كل phishing أو كل network attack.
- لا يثبت أنه real-time IDS/IPS.
- لا يثبت أنه يفحص كل dark web.
- لا يثبت production accuracy بنفس أرقام metrics files.
- لا يثبت أن optional integrations شغالة في كل بيئة.

## Safe wording for limitations

"النظام يقدم أدوات تحليل ومتابعة أمنية مبنية على قواعد وML وintegrations اختيارية. النتائج تساعد المستخدم/الأدمن في الفهم واتخاذ القرار، لكنها لا تعتبر ضمان حماية كامل أو بديل عن monitoring production متخصص."
