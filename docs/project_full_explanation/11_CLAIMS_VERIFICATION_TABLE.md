# 11 - Claims Verification Table

| Possible claim | Evidence from code | File/function/component | Status | Safe wording | Unsafe wording |
|---|---|---|---|---|---|
| Sentinel AI is a web dashboard with multiple cybersecurity tools | React routes and Flask modules | `App.tsx`, `Backend/app.py` | Verified | "web dashboard يجمع أدوات فحص وتحليل" | "enterprise-grade security platform" |
| Users can sign up and log in | Auth routes and pages | `signup`, `login`; `SignUpPage.tsx`, `LoginPage.tsx` | Verified | "يدعم signup/login" | "auth لا يمكن اختراقه" |
| Email verification exists | Verify endpoint/page | `verify_email`, `VerifyEmailPage.tsx` | Verified | "يدعم email verification إذا email configured" | "emails always delivered" |
| Password reset exists | routes/pages | `forgot_password`, `reset_password`; pages | Verified | "يدعم forgot/reset password" | "password recovery guaranteed" |
| 2FA exists | TOTP routes/pages | `setup_2fa`, `verify_2fa_setup`, `verify_2fa_login` | Verified | "يدعم TOTP 2FA" | "2FA implementation fully audited" |
| Password checker does not store raw password | fixed mask and saved record | `FIXED_PASSWORD_MASK`, `PasswordCheck` | Verified | "لا يحفظ raw password في history" | "لا يوجد أي privacy risk" |
| Password checker checks breaches | HIBP client call | `check_pwned_password` | Verified | "يفحص exposure عبر breach check service" | "يضمن كلمة المرور آمنة" |
| Phishing scanner uses ML | `predict_url` call | `scan_url`, `ml.py` | Verified | "يستخدم ML prediction لروابط" | "detects all phishing" |
| Phishing scanner uses VirusTotal | `get_domain_reputation` and env key | `virustotal.py` | Partially verified | "يدعم VirusTotal إذا API key متاح" | "كل scan يستخدم VirusTotal دائماً" |
| Vault encrypts uploaded files | crypto helpers and upload route | `crypto.py`, `upload_document` | Verified | "يشفر الملفات باستخدام password-derived key" | "unbreakable encryption" |
| Vault validates dangerous files | validation lists/header checks | `validate_vault_upload` | Verified | "يحاول منع dangerous uploads" | "يمنع كل malware" |
| PCAP analyzer validates PCAP files | magic byte check | `validate_pcap_upload` | Verified | "يقبل pcap/pcapng valid headers" | "أي ملف network يتم تحليله" |
| PCAP analyzer uses ML model | model inference path | `predict_flows`, `run_pcap_pipeline` | Verified | "يستخدم model لتصنيف flows" | "real-time threat protection" |
| PCAP has file-reported metrics | metrics JSON files | `metrics.json`, `metrics_pcap65.json` | Verified | "metrics محفوظة في ملفات المشروع" | "production accuracy is 98/99%" |
| PCAP uses Zeek evidence | imports/loaders/runners | `zeek_runner.py`, `zeek_loader.py`, `run_pcap_pipeline` | Verified | "يدعم Zeek evidence في pipeline" | "Zeek always installed and always used" |
| PCAP exports reports/evidence | export route | `export_job_artifact` | Verified | "يدعم export لل report/evidence" | "exports are always encrypted" |
| Artifact encryption is available | env-based protection | `_protect_pcap_artifacts_after_terminal_state` | Partially verified | "artifact protection موجود ويعتمد على config" | "all artifacts encrypted by default" |
| Identity scanner checks local leaked CSV | legacy DB/import | `identityleak.py`, `leaked_data.csv` | Verified | "يوجد legacy local leak check" | "full dark web scan" |
| Identity web scan exists | routes and scraper DB | `identity_web_scan`, `services/identity_web_scraper/*` | Verified | "يدعم web identity scan من مصادر الكود" | "يفحص كل الإنترنت/dark web" |
| Monthly report generation exists | report functions/routes | `reports.py`, `/api/reports/monthly/generate` | Verified | "يولد monthly security reports" | "reports are legally/compliance complete" |
| Google Drive upload exists | Drive config/functions | `upload_monthly_report_to_drive`, env vars | Partially verified | "يدعم upload to Drive إذا configured" | "reports always uploaded to Drive" |
| Notifications exist | models/routes/UI | `UserNotification`, `NotificationCenter.tsx` | Verified | "يدعم in-app notifications" | "all alerts delivered instantly by email/telegram" |
| Email/Telegram notification delivery | SMTP/Telegram code/env | `send_*`, `TELEGRAM_BOT_TOKEN`, SMTP vars | Partially verified | "delivery depends on config" | "email/telegram guaranteed" |
| User activity logs exist | model/routes/page | `UserActivityLog`, `/api/activity-logs/me`, `UserActivityLogsPage.tsx` | Verified | "يسجل activity events داخل النظام" | "complete forensic logging" |
| Admin dashboard exists | admin routes/pages | `AdminConsolePage.tsx`, `/api/admin/*` | Verified | "يوجد admin console للإدارة والمراقبة" | "enterprise SOC console" |
| Admin can manage users | user endpoints | `admin_list_users`, `admin_create_user`, role/status/delete functions | Verified | "admin can list/create/update status/role/delete users" | "role model final without owner confirmation" |
| AI governance endpoints exist | endpoints/metrics loader | `admin_ai_governance_*` | Verified | "يعرض model metrics من files" | "continuous model governance" |
| Chatbot supports LLM providers | providers/router/endpoints | `llm_providers/*`, `chatbot_llm` | Partially verified | "يدعم LLM إذا provider configured مع fallback" | "AI assistant always online" |
| `/ai-threat-detector` is standalone page | route redirects | `App.tsx` | Not confirmed | "route redirects to dashboard" | "AIThreatDetectorPage is active standalone route" |
| System provides real-time protection | No blocking/inline protection proven | PCAP jobs are upload/poll | Unsafe | "offline/on-demand analysis" | "real-time protection" |
| System detects all attacks | No such proof | ML/rules limited | Unsafe | "يساعد في detection/risk assessment" | "detects all attacks" |
