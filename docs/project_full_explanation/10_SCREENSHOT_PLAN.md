# 10 - Screenshot Plan

| Title | Page/component | Action | Must be visible | Suggested caption | Why it matters | Priority | Sanitization |
|---|---|---|---|---|---|---|---|
| User Dashboard Overview | `/dashboard` / `SimpleDashboard` | Login as user | security score/cards/recent modules | "User dashboard summarizing module status" | Shows integrated system | Must-have | Blur email/name |
| Password Checker Result | `/password-checker` | Check demo password | strength, breach count, history item | "Password strength and breach check result" | Shows implemented checker | Must-have | Do not show real password |
| Phishing URL Scan | `/phishing-scanner` | Scan safe demo URL | final category/risk/guidance/history | "URL risk assessment with ML and reputation output" | Shows phishing module | Must-have | Use non-sensitive URL |
| File Vault List | `/file-vault` | Upload demo text/PDF | encrypted file row/actions | "Encrypted file vault document list" | Shows vault workflow | Must-have | Blur filenames if real |
| File Vault Verify | `/file-vault` | Verify demo file | integrity result | "Vault integrity verification" | Shows security handling | Good-to-have | Use demo file |
| Identity Scan Results | `/identityleak-monitor` | Scan demo email/domain | scan status/findings/alerts | "Identity leak monitoring scan result" | Shows identity module | Must-have | Use fake/demo email |
| Identity PDF Export | browser/download | Download scan report | PDF title/results | "Identity scan PDF report" | Shows export | Good-to-have | Sanitize identifiers |
| PCAP Upload Progress | `/pcap-analyzer` | Upload sample PCAP | job steps/progress | "PCAP analysis job processing" | Shows async pipeline | Must-have | Use sample PCAP |
| PCAP Final Report | `/pcap-analyzer` | Open completed job | score, severity, alerts, charts | "PCAP analysis report and risk breakdown" | Strong module evidence | Must-have | Blur IPs/filenames |
| PCAP Export | `/pcap-analyzer` | Click report/evidence export | export buttons/file prompt | "Report and evidence export actions" | Shows artifacts | Good-to-have | Avoid raw IPs |
| Monthly Reports | `/monthly-reports` | Generate/list report | report card/status/download | "Monthly security report center" | Shows reporting | Good-to-have | Blur user info |
| Activity Logs | `/user-activity-logs` | Filter/view event | activity table/detail | "User activity audit trail" | Shows auditability | Good-to-have | Blur IP/user agent |
| Notifications | `NotificationCenter` | Open notification bell | alerts/read actions | "Notification center" | Shows alert flow | Good-to-have | Blur sensitive metadata |
| Admin Login | `/admin/login` | Show login form only | admin login/2FA UI | "Admin console authentication" | Admin journey | Must-have | Do not show credentials/TOTP |
| Admin Console Overview | `/admin/console` | Login as admin | user/threat/PCAP/audit summary | "Admin monitoring console" | Shows admin role | Must-have | Blur emails/IPs |
| Admin Users | Admin users section | List users | roles/status/action buttons | "User management panel" | Shows management | Good-to-have | Blur emails/names |
| Admin Audit Trail | Admin audit page | Open audit logs | event table/filters/export | "Admin audit trail" | Shows accountability | Good-to-have | Blur IP/user agent |
| Admin PCAP Overview | PCAP admin section | Open PCAP section | jobs/families/queue health | "Admin PCAP monitoring overview" | Shows admin PCAP integration | Good-to-have | Blur IPs/files |
| AI Governance | Admin AI governance | Open section | model registry/metrics | "AI governance metrics from project files" | Shows ML transparency | Optional | Say metrics are file-reported |
| Settings Integrations | `/settings` | Open integrations/security | notification channels/security settings | "User settings and integrations" | Shows config surface | Optional | Hide secrets/tokens |

## Screenshot safety rules

- Use demo accounts and demo data.
- Never show `.env`, API keys, SMTP password, JWT tokens, TOTP secret/QR after setup, or real personal data.
- For PCAP, blur real IPs, ports if sensitive, filenames, and raw payload paths.
- For identity, use fake emails/domains or blur them.
