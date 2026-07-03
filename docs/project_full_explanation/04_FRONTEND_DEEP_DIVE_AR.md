# 04 - Frontend Deep Dive

## Main frontend structure

Frontend في `Cybersecurity Dashboard Design/src`. Entry point في `main.tsx` و route tree في `App.tsx`. كل الصفحات الأساسية تحت `src/components/pages`.

## Navigation routes

`App.tsx` يثبت routes:

- Public: `/`, `/demo`, `/features`, `/learn`, `/about`, `/contact`.
- Auth: `/signup`, `/login`, `/forgot-password`, `/reset-password`, `/email-sent`, `/verify-email`, `/accept-invitation`, `/setup-2fa`, `/login-2fa`.
- Protected user: `/dashboard`, `/password-checker`, `/file-vault`, `/phishing-scanner`, `/identityleak-monitor`, `/chatbot`, `/settings`, `/monthly-reports`, `/user-activity-logs`, `/pcap-analyzer`.
- Admin: `/admin/login`, `/admin/console`, `/forbidden`.
- `/ai-threat-detector` redirects to `/dashboard`, so it is not a standalone active page in current routing.

## Protected layout

`Layout.tsx` checks `sentinel_auth_token`, calls `/api/auth/me`, handles logout via `/api/auth/logout`, and redirects to login/emergency page. It also includes navigation and notification hooks.

## Important pages/components

| Component | File path | Purpose | User actions | Backend endpoints called | Data displayed | Screenshot recommendation |
|---|---|---|---|---|---|---|
| `SimpleDashboard` | `src/components/pages/SimpleDashboard.tsx` | user overview | view score/cards/recent data | `/api/documents`, `/api/ai/vault/analyze`, `/api/security/global-score`, `/api/reports/monthly/latest` | security score, vault summary, reports | Must-have dashboard |
| `PasswordCheckerPage` | `src/components/pages/PasswordCheckerPage.tsx` | password check | enter password, clear history | `/api/password/check`, `/api/password/history` | strength, breach count, history | Must-have |
| `PhishingScannerPage` | `src/components/pages/PhishingScannerPage.tsx` | URL scan | scan URL, delete scan | `/api/v1/scan-url`, `/api/v1/scans`, `/api/v1/scan/<id>` | risk, category, history | Must-have |
| `FileVaultPage` | `src/components/pages/FileVaultPage.tsx` | encrypted vault | upload, download, delete, offline toggle | `/api/documents*`, `/api/auth/refresh` | file list, status, actions | Must-have, sanitize filenames |
| `IdentityLeakMonitorPage` | `src/components/pages/IdentityLeakMonitorPage.tsx` | identity monitoring | scan identifiers/assets, download PDF | `/api/identity/*`, `/api/auth/me` | scans, findings, alerts | Must-have, sanitize emails |
| `PcapAnalyzerPage` | `src/components/pages/PcapAnalyzerPage.tsx` | PCAP analysis | upload PCAP, poll job, export report/evidence, cancel | `/analyze-pcap`, `/jobs`, `/job/<id>`, `/api/pcap/cancel/<id>`, `/job/<id>/export` | job status, alerts, charts, score | Must-have, sanitize IPs |
| `MonthlyReportsPage` | `src/components/pages/MonthlyReportsPage.tsx` | monthly reports | list, generate, download, upload drive | `/api/reports/monthly*` | report cards/status | Good-to-have |
| `UserActivityLogsPage` | `src/components/pages/UserActivityLogsPage.tsx` | user audit trail | filter, view detail, export | `/api/activity-logs/me*` | events table/detail | Good-to-have |
| `SettingsPage` | `src/components/pages/SettingsPage.tsx` | profile/security/integrations | update profile/security/password/accounts/channels | `/api/settings/*`, `/api/integrations/channels*`, `/api/auth/me` | settings forms | Good-to-have |
| `ChatbotWorkspacePage` | `src/components/pages/ChatbotWorkspacePage.tsx` | assistant workspace | ask questions by module | `/api/chatbot/llm`, `/api/chatbot/identity`, `/api/chatbot/pcap`, `/api/ai/vault/analyze` | messages/provider/fallback | Optional |
| `AdminLoginPage` | `src/components/pages/AdminLoginPage.tsx` | admin login | login and 2FA | `/api/admin/auth/login`, `/api/admin/auth/verify-2fa` | auth state | Must-have for admin |
| `AdminConsolePage` | `src/components/pages/AdminConsolePage.tsx` | admin console | manage users/threats/settings/reports | many `/api/admin/*` endpoints | summaries/tables/settings | Must-have |
| `NotificationCenter` | `src/components/NotificationCenter.tsx` | notification popover | read/read all/open action | `/notifications*`, `/api/admin/notifications*` | alerts | Good-to-have |

## API service files

- `src/services/adminReportsService.ts`: admin report generation/export callers.
- `src/services/adminPcapOverview.ts`: admin PCAP overview/export helper.
- `src/services/adminNotificationsService.ts`: notification control/status/settings/test.
- `src/utils/gamification.ts`: gamification overview/event callers.
- `src/utils/activityLogs.ts`: frontend activity tracking.
- `src/utils/networkSecurityScore.ts`, `securityScore.ts`, `pcapChartSelectors.ts`: frontend calculations/selectors.

## State management and localStorage

Confirmed localStorage keys:

- `sentinel_auth_token`, `sentinel_refresh_token`, `sentinel_admin_token`: auth/session.
- `sentinel_pending_2fa_token`, `verifiedEmail`, `userEmail`: auth flow.
- `sentinel_remember_email`: login remember email.
- Admin TOTP storage in `src/config/adminTotp.ts`.
- Language/app settings in contexts.
- Learning progress in `LearnPage.tsx`.
- Report/admin notification caches in services.

## Forms and validations

- Signup/login/password reset pages perform frontend validation before fetch.
- `PhishingScannerPage` submits URL; backend enforces scheme/netloc.
- `FileVaultPage` asks for password and file; backend enforces file type/magic.
- `PcapAnalyzerPage` accepts file upload; backend enforces pcap magic.

## Result cards/tables/charts

PCAP has several visual components in `src/components/security`: `SecurityScoreCard`, `SeverityBreakdownCard`, `ThreatBreakdownCard`, `ThreatActivityAreaChart`, `RiskPerIpCard`, `RecentSecurityAlertsPanel`.  
Admin reports and audit pages use tables/export buttons.

## Error/loading states

Most pages use loading/error state around fetch. Examples: `PcapAnalyzerPage.tsx` has job/polling states; `MonthlyReportsPage.tsx` has refresh token retry; `FileVaultPage.tsx` has vaultFetch retry.
