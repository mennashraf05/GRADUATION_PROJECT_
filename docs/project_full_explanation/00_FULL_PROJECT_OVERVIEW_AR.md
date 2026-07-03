# 00 - النظرة العامة الكاملة للمشروع

## ما هو Sentinel AI؟

Sentinel AI هو Web Application للأمن السيبراني يجمع أكثر من أداة في Dashboard واحدة: فحص كلمات المرور، فحص روابط phishing، vault للملفات المشفرة، مراقبة تسريب الهوية، تحليل ملفات PCAP، تقارير، Notifications، ولوحة Admin.  
الدليل من الكود: `Backend/app.py` هو ملف Flask الرئيسي، و `Cybersecurity Dashboard Design/src/App.tsx` يعرّف صفحات React مثل `/dashboard`, `/password-checker`, `/file-vault`, `/phishing-scanner`, `/identityleak-monitor`, `/pcap-analyzer`, `/monthly-reports`, و `/admin/console`.

## المشكلة التي يحاول حلها

المشروع يساعد المستخدم على متابعة مخاطر أمنية شائعة من مكان واحد: كلمات مرور ضعيفة أو مسربة، روابط مشبوهة، ملفات حساسة، تسريبات بيانات شخصية، وملفات network capture. لا يوجد دليل كافي في الكود أنه يوفر حماية real-time أو يمنع الهجمات مباشرة، لذلك الصياغة الآمنة: "يساعد في الفحص والتحليل والمتابعة".

## من يستخدمه؟

- Normal User: يستخدم صفحات الفحص والـ dashboard والتقارير والإعدادات. الدليل: routes المحمية في `Cybersecurity Dashboard Design/src/App.tsx` داخل `Layout`.
- Admin: يستخدم `/admin/login` و `/admin/console`. الدليل: `AdminLoginPage.tsx`, `AdminConsolePage.tsx`, و endpoints مثل `admin_list_users`, `admin_audit_logs`, `admin_pcap_overview` في `Backend/app.py`.

## الأدوار الرئيسية

- User عادي: مصرح له عبر JWT أو cookies في `get_current_user`, `require_full_auth_user` داخل `Backend/app.py`.
- Admin console: له JWT scope منفصل `ADMIN_JWT_SCOPE = "admin_console"` ودوال `create_admin_console_token`, `admin_required` في `Backend/app.py`.

## الموديولات المؤكدة

- Password Checker: `Backend/password_checker/routes.py`, `PasswordCheckerPage.tsx`.
- Phishing Scanner: `Backend/phishing_scanner/scan.py`, `PhishingScannerPage.tsx`.
- Encrypted File Vault: `Backend/encrypted_file_vault/routes.py`, `FileVaultPage.tsx`.
- Identity Leak Detection: legacy SQLite في `Backend/identityleak.py` و web scan في `Backend/services/identity_web_scraper/*`, صفحة `IdentityLeakMonitorPage.tsx`.
- PCAP Analyzer / AI Threat Detection: pipeline في `Backend/app.py` و `Backend/pcap_engine/*`, صفحة `PcapAnalyzerPage.tsx`.
- Monthly Reports: `Backend/reports.py`, endpoints `/api/reports/monthly*`, صفحة `MonthlyReportsPage.tsx`.
- Notifications / Activity Logs: models ودوال داخل `Backend/app.py` و `Backend/activity_logs.py`, صفحات `NotificationCenter.tsx`, `UserActivityLogsPage.tsx`.
- Admin Dashboard: `AdminConsolePage.tsx` مع endpoints `/api/admin/*`.
- Chatbot/LLM Assistant: endpoints `chatbot_llm`, `pcap_chatbot`, `identity_chatbot` في `Backend/app.py`, providers في `Backend/llm_providers/*`.

## High-level workflow

1. المستخدم يعمل signup/login من `SignUpPage.tsx` و `LoginPage.tsx`.
2. Backend ينشئ JWT/refresh token في `signup`, `login`, `refresh` داخل `Backend/app.py`.
3. المستخدم يدخل Dashboard أو module page.
4. الصفحة تستدعي endpoint محدد، مثل `/api/password/check` أو `/api/v1/scan-url` أو `/analyze-pcap`.
5. Backend يحفظ metadata/results في SQLAlchemy أو SQLite أو ملفات runtime.
6. Dashboard يعرض النتائج والتنبيهات والتقارير.

## Frontend overview

Frontend مبني بـ React/Vite. الدليل: `Cybersecurity Dashboard Design/package.json`, `src/main.tsx`, `src/App.tsx`.  
التنقل الأساسي في `App.tsx`. Layout المشترك في `src/components/Layout.tsx`. UI components كثيرة تحت `src/components/ui`.

## Backend overview

Backend مبني بـ Flask و SQLAlchemy. الدليل: `Backend/app.py`, `Backend/extensions.py`.  
`app.py` يسجل blueprints:
- `scan_bp` من `phishing_scanner.scan`
- `gamification_bp`
- `password_checker_bp`
- vault عبر `init_vault(app)`

## Database/storage overview

- SQLAlchemy tables في `Backend/app.py`: `User`, `PasswordResetToken`, `PasswordCheck`, `RefreshToken`, `SecurityAuditLog`, `AdminAuditLog`, `UserNotification`, `PcapAlertRecord`, `MonthlySecurityReport`, `LinkedAccount`, `ContactMessage`.
- Vault table في `Backend/encrypted_file_vault/models.py`: `VaultDocument`.
- Gamification tables في `Backend/gamification/models.py`.
- User activity table في `Backend/activity_logs.py`: `UserActivityLog`.
- SQLite مستقل للـ phishing في `Backend/phishing_scanner/database.py`.
- SQLite مستقل للـ identity legacy في `Backend/identityleak.py`.
- SQLite مستقل للـ identity web scraper في `Backend/services/identity_web_scraper/database.py`.
- ملفات PCAP runtime تحت `PCAP_RUN_FOLDER` حسب `Backend/app.py`.
- ملفات vault في folder اسمه `upload` حسب `Backend/encrypted_file_vault/routes.py`.

## AI/ML overview

- PCAP ML: model files `Backend/model/threat_model.pkl`, `Backend/model/threat_model_pcap65.pkl`, metrics في `metrics.json`, `metrics_pcap65.json`, inference في `Backend/pcap_engine/ml_infer.py`.
- Phishing ML: `Backend/phishing_scanner/ml.py`, URL features في `url_features.py`, تدريب في `train.py`.
- Vault AI behavior analysis: endpoint `analyze_my_vault_behavior` في `Backend/app.py`.
- Chatbot LLM: `Backend/llm_providers/ollama_provider.py`, `gemini_provider.py`, `router.py`.

## Admin features overview

Admin console فيه user management, threats, reports, PCAP overview, audit logs, notification control, AI governance. الدليل: endpoints `/api/admin/users`, `/api/admin/threats`, `/api/admin/reports/*`, `/api/admin/pcap/overview`, `/api/admin/audit-logs`, `/api/admin/ai-governance/*` في `Backend/app.py`.

## Security/privacy features

- JWT auth و refresh tokens: `Backend/app.py`.
- Email verification و 2FA: endpoints `/api/auth/2fa/setup`, `/api/auth/2fa/verify-setup`, `/api/auth/2fa/verify-login`.
- Upload validation: `Backend/upload_security.py`.
- Vault encryption/signature: `Backend/encrypted_file_vault/crypto.py`, `routes.py`.
- Activity logs: `Backend/activity_logs.py`.
- Rate limits: `_apply_route_specific_rate_limits` في `Backend/app.py`.

## Fully implemented features

مؤكدة من routes + frontend callers:
- Auth/login/signup/refresh/logout/password reset.
- Password Checker مع history.
- Phishing Scanner مع ML + VirusTotal اختياري حسب `VIRUSTOTAL_API_KEY`.
- File Vault upload/list/download/delete/offline/verify.
- Identity web scan/assets/findings/PDF report.
- PCAP upload/analyze/jobs/export/cancel/alerts.
- Monthly reports list/generate/download/upload to Drive إذا Google Drive configured.
- User activity logs.
- Admin console core endpoints.

## Partially implemented / config-dependent

- SMTP email alerts: الكود موجود لكن يعتمد على `SMTP_*` أو `MAIL_*`.
- Google Drive upload: يعتمد على `GOOGLE_DRIVE_UPLOADS_ENABLED`, service account, folder id.
- LLM chatbot: Ollama/Gemini paths موجودة، لكن Gemini يحتاج `GEMINI_API_KEY` و Ollama يحتاج local service.
- PCAP artifact encryption: يعتمد على `PCAP_ARTIFACT_ENCRYPTION_KEY` و mode.
- Admin TOTP في frontend يخزن secret في browser `localStorage` حسب `adminTotp.ts`; backend admin 2FA موجود أيضاً في `Backend/app.py`.

## Not confirmed

- Deployment production settings النهائية.
- Production dataset المستخدم فعلياً.
- أن كل optional integrations مفعلة في بيئة المناقشة.
- دقة النموذج في بيئة production.

## Claims ممنوع قولها

- لا تقل "real-time protection" لأن النظام يحلل بناءً على user action أو jobs.
- لا تقل "detects all attacks" لأن ML/heuristics لها limits.
- لا تقل "enterprise-grade" بدون benchmark/security review خارجي.
- لا تقل إن كل التقارير تُرفع Google Drive تلقائياً؛ الكود يجعلها optional/config-dependent.
