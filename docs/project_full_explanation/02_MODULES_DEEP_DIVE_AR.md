# 02 - Modules Deep Dive

## 1. Authentication and user management

- Purpose: تسجيل مستخدمين، login، refresh tokens، logout، email verification، password reset، 2FA.
- User journey: user signup من `SignUpPage.tsx` -> `/api/auth/signup` -> email verification -> login -> dashboard.
- Backend evidence: `signup`, `login`, `refresh`, `get_me`, `logout`, `forgot_password`, `reset_password`, `setup_2fa`, `verify_2fa_setup`, `verify_2fa_login` في `Backend/app.py`.
- Frontend evidence: `SignUpPage.tsx`, `LoginPage.tsx`, `ForgotPasswordPage.tsx`, `ResetPasswordPage.tsx`, `Setup2FAPage.tsx`, `Login2FAPage.tsx`.
- Database: `User`, `RefreshToken`, `PasswordResetToken`, `LinkedAccount` في `Backend/app.py`.
- Security: JWT, refresh token storage، session version، 2FA secret، emergency mode.
- Limitations: email delivery depends on SMTP config.
- Safe discussion wording: "النظام يدعم login/signup و email verification و 2FA من خلال endpoints واضحة."
- Unsafe claims: "auth production-ready بالكامل" بدون security audit خارجي.

## 2. Password Checker

- Purpose: فحص password strength و breach count.
- User problem: يعرف إذا password ضعيف أو ظهر في breaches.
- Journey: `PasswordCheckerPage.tsx` -> `/api/password/check` -> response فيه `pwned`, `count`, `strength_label`, `score`, `history_item`.
- Backend files: `Backend/password_checker/routes.py`, `hibp_client.py`.
- Frontend files: `PasswordCheckerPage.tsx`.
- Database: `PasswordCheck` في `Backend/app.py`; legacy `PasswordHistory` موجود أيضاً.
- Inputs: JSON body فيه `password`.
- Processing: `_password_strength` يحسب score؛ `check_pwned_password` يفحص HIBP-style password exposure؛ raw password لا يتم تخزينه، history يستخدم `FIXED_PASSWORD_MASK = "********"`.
- Outputs: breach count, strength label, score, email/admin alert flags.
- Admin integration: admin password risk report functions في `Backend/app.py` مثل `admin_password_risk_report_summary`.
- Limitations: HIBP external service قد يكون unavailable ويرجع 503.
- Safe wording: "يفحص قوة كلمة المرور ويقارنها بخدمة breach check، ولا يحفظ raw password."
- Unsafe wording: "يضمن إن كلمة المرور آمنة 100%."

## 3. Phishing Scanner

- Purpose: فحص URL وتحويله إلى risk category.
- Journey: `PhishingScannerPage.tsx` -> `/api/v1/scan-url` -> ML prediction + risk score + VirusTotal optional reputation -> history.
- Backend files: `phishing_scanner/scan.py`, `ml.py`, `url_features.py`, `risk.py`, `virustotal.py`, `database.py`.
- Database: SQLite table `scans` في `phishing_scanner/database.py`.
- Inputs: JSON `url`.
- Processing: URL validation، `predict_url`, `calculate_risk`, `get_domain_reputation`, `combine_ml_and_virustotal`.
- Outputs: `ml_result`, `risk_score`, `category`, `virustotal`, `final_category`, `final_risk_score`.
- Admin integration: phishing incidents report functions في `Backend/app.py`: `admin_phishing_incidents_report_summary`, `admin_phishing_incidents_report_export`.
- Security/privacy: لا يفحص غير `http/https`; VirusTotal يحتاج `VIRUSTOTAL_API_KEY`.
- Limitations: يعتمد على model وقواعد وoptional reputation؛ لا يثبت اكتشاف كل phishing.
- Safe wording: "يعطي risk assessment للرابط بناءً على ML features وسمعة الدومين إن كانت مفعلة."
- Unsafe wording: "يحمي المستخدم من كل روابط phishing."

## 4. Encrypted File Vault

- Purpose: حفظ ملفات المستخدم بشكل encrypted مع integrity verification.
- Journey: `FileVaultPage.tsx` -> `/api/documents` upload/list -> `/download`, `/verify`, `/offline`, delete.
- Backend files: `encrypted_file_vault/routes.py`, `models.py`, `crypto.py`.
- Database: `VaultDocument` في `models.py`.
- Inputs: file upload + password عند upload/download/verify.
- Processing: `validate_vault_upload`, `derive_key`, `get_cipher_from_password`, file hash, salt, optional offline flag, HMAC/signature.
- Outputs: document list, encrypted download, integrity verification result.
- Storage: files under project `upload` folder, metadata in `vault_documents`.
- Admin integration: file vault activity summary report في `admin_file_vault_activity_report_summary`.
- Security/privacy: dangerous extensions/MIME/magic blocked في `upload_security.py`.
- Limitations: الأمن يعتمد على password المستخدم وإدارة التخزين؛ offline access يحتاج شرح عملي من owner.
- Safe wording: "Vault يشفر الملفات بكلمة مرور المستخدم ويحفظ metadata فقط."
- Unsafe wording: "ملفاتك غير قابلة للاختراق."

## 5. Identity Leak Detection

- Purpose: البحث عن email/username/domain في sources محلية/ويب حسب الكود.
- Journey: `IdentityLeakMonitorPage.tsx` -> `/api/identity/web-scan` أو assets -> findings/alerts/PDF.
- Backend files: `identityleak.py`, `services/identity_web_scraper/database.py`, `scraper.py`, `scoring.py`, `leakcheck_public.py`, `gitlab_search.py`, `stackexchange_search.py`.
- Database: legacy `leaked_data`, `monitored_assets`, `asset_breaches`, `scan_logs` في `identityleak.py`; web tables `identity_scans`, `identity_findings`, `identity_alerts`, `identity_monitored_assets`.
- Inputs: email, username, domain, monitored assets.
- Processing: validate asset, create scan, run web scraper, save findings, score risk, create alerts.
- Outputs: scan status, findings, risk level, PDF report via `identity_web_scan_pdf_report`.
- Admin integration: identity report summary/export in `Backend/app.py`.
- Limitations: data sources and final datasets need owner confirmation; not a full dark-web scanner unless proven.
- Safe wording: "الموديول يبحث في مصادر مؤكدة من الكود ويحفظ findings alerts."
- Unsafe wording: "يفحص كل dark web."

## 6. PCAP Analyzer / AI Threat Detection

- Purpose: تحليل PCAP/PCAPNG واستخراج flows وتشغيل ML + heuristics + report.
- Journey: `PcapAnalyzerPage.tsx` -> `/analyze-pcap` upload -> poll `/job/<id>` -> export `/job/<id>/export`.
- Backend files: `Backend/app.py`, `pcap_engine/tshark_runner.py`, `cic_stream_features.py`, `ml_infer.py`, `security_logic.py`, `scorer.py`, `reporter.py`, `jobs.py`, `zeek_runner.py`.
- Database/storage: runtime job registry/files in `PCAP_RUN_FOLDER`; persisted alerts in `PcapAlertRecord`.
- Inputs: `.pcap` or `.pcapng`; optional settings like confidence mode.
- Processing: upload validation, tshark/Zeek evidence, CIC features, model prediction, confidence, security rules, report generation.
- Outputs: job status, report JSON, evidence bundle, dashboard alerts, security score.
- Admin integration: `/api/admin/pcap/overview`, `/api/admin/pcap/jobs/<job_id>/export`.
- Limitations: depends on installed tshark/Zeek/tools and model schema; false positives/false negatives possible.
- Safe wording: "يحلل PCAP offline ويصنف flows بناءً على model وrules."
- Unsafe wording: "real-time IDS" أو "detects all attacks."

## 7. Reports

- Purpose: monthly/security/admin reports and exports.
- Journey: `MonthlyReportsPage.tsx` -> `/api/reports/monthly`, generate/download/upload-drive.
- Backend files: `Backend/reports.py`, report endpoints in `Backend/app.py`.
- Database: `MonthlySecurityReport`.
- Outputs: JSON summary + PDF path/download.
- Admin integration: admin reports under `/api/admin/reports/*`.
- Limitations: Google Drive upload optional/configured.
- Safe wording: "النظام يولد reports من البيانات المخزنة داخله."

## 8. Notifications and activity logs

- Purpose: user/admin notifications and traceable activity.
- Frontend: `NotificationCenter.tsx`, `UserActivityLogsPage.tsx`.
- Backend: `UserNotification`, `AdminNotificationRead`, `SecurityAuditLog`, `AdminAuditLog`, `UserActivityLog`, routes `/notifications*`, `/api/activity-logs/*`.
- Security: sensitive events can be marked `is_sensitive`.
- Limitation: email/telegram delivery config-dependent.

## 9. Admin Dashboard

- Purpose: management/monitoring.
- Frontend: `AdminLoginPage.tsx`, `AdminConsolePage.tsx`, `admin/*` components.
- Backend: `/api/admin/auth/*`, `/api/admin/users*`, `/api/admin/threats*`, `/api/admin/audit-logs*`, `/api/admin/ai-governance/*`.
- Limitations: final admin roles/permissions policy should be confirmed with project owner.

## 10. Chatbot / Assistant

- Purpose: explain security contexts using safe context.
- Frontend: `ChatbotWorkspacePage.tsx`.
- Backend: `chatbot_llm`, `pcap_chatbot`, `identity_chatbot`, context builders in `Backend/app.py`.
- Providers: `llm_providers/ollama_provider.py`, `gemini_provider.py`, `router.py`.
- Limitation: provider availability is config-dependent; fallback rule-based answers exist.
