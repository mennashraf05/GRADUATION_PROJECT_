# Frontend PCAP Evidence

## Frontend Files

| File | Component/page | Purpose | Side | UI actions | API endpoints called | Screenshots to take |
|---|---|---|---|---|---|---|
| `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx` | `PcapAnalyzerPage` | Main PCAP analyzer workspace | User | Upload file, choose confidence mode, set max alerts/clusters, include Zeek, analyze, cancel, view results, open details, export report/evidence, view history | `/analyze-pcap`, `/job/<id>`, `/jobs`, `/api/pcap/cancel/<id>`, `/job/<id>/export?type=...` | Upload panel, running progress, completed summary, alerts table, clusters table, timeline, history modal, export buttons, detail drawer |
| `Cybersecurity Dashboard Design/src/components/admin/PcapAnalysisAdminControl.tsx` | `PcapAnalysisAdminControl` | Admin PCAP monitoring | Admin | Refresh overview, export summary, preview report, export evidence, filter timeline by job | `/api/admin/pcap/overview`, `/api/admin/pcap/jobs/<id>/export?type=...` | Metrics grid, queue health, latest results, suspicious files, engine status, timeline, report preview |
| `Cybersecurity Dashboard Design/src/services/adminPcapOverview.ts` | service module | Admin API normalization/export URL helpers | Admin | Fetch overview, normalize payload, build export URL | `/api/admin/pcap/overview`, `/api/admin/pcap/jobs/<id>/export` | No direct screenshot |
| `Cybersecurity Dashboard Design/src/utils/recentPcapAlerts.ts` | utility module | Normalizes report/alert data and localStorage cache | User/dashboard | Build dashboard alerts from reports, merge/persist/read cache | No direct fetch | No direct screenshot |
| `Cybersecurity Dashboard Design/src/components/security/RecentSecurityAlertsPanel.tsx` | `RecentSecurityAlertsPanel` | Dashboard recent alerts panel with PCAP live feed | User/dashboard | Load alerts, refresh, clear/dismiss visible alerts | `/api/pcap/alerts`, `/pcap/alerts`, clear/dismiss endpoints | Dashboard recent PCAP alerts, clear alerts action |
| `Cybersecurity Dashboard Design/src/utils/networkSecurityScore.ts` | utility module | Computes frontend-derived network score from recent successful PCAP jobs/reports | User/dashboard | Fetch history/details, calculate weighted score | `/jobs`, `/pcap/jobs`, `/job/<id>` | Network score card on dashboard |
| `Cybersecurity Dashboard Design/src/components/security/NetworkSecurityScoreCard.tsx` | `NetworkSecurityScoreCard` | Displays recent PCAP posture | User/dashboard | View score details, navigate to PCAP analyzer | Uses `loadNetworkSecurityScoreSummary` | Network Security Score card and details sheet |
| `Cybersecurity Dashboard Design/src/utils/pcapChartSelectors.ts` | chart selectors | Builds severity, top attack, timeline chart data from report | User | No direct action | No direct fetch | Charts derived on PCAP page |
| `Cybersecurity Dashboard Design/src/components/security/RiskPerIpCard.tsx` | `RiskPerIpCard` | Displays `risk_per_ip` report rows | User | View per-IP risk rows | No direct fetch | Risk per IP card |
| `Cybersecurity Dashboard Design/src/components/pages/DashboardPage.tsx` | dashboard page | Embeds PCAP dashboard widgets | User | View network score/recent alerts | Indirect through child components | Dashboard with PCAP widgets |
| `Cybersecurity Dashboard Design/src/components/pages/AdminConsolePage.tsx` | admin console | Embeds PCAP admin control section | Admin | Switch to PCAP analysis admin section | Indirect through child component | Admin console PCAP section |

## UI Features Confirmed

- File input accepts `.pcap,.pcapng`.
- Frontend max upload size constant matches 15 GB.
- Confidence modes shown as Strict, Balanced, Relaxed.
- Include Zeek Evidence checkbox exists.
- Progress card shows job status, message, job ID, started time, duration, polling interval.
- Results include SecurityScoreCard, SeverityBreakdownCard, ThreatBreakdownCard, KPI tiles, RiskPerIpCard, cluster table, alerts table, timeline.
- Export report/evidence buttons call backend artifact endpoints.
- Dashboard alert cache is updated after successful analysis.

Evidence:
- `PcapAnalyzerPage.tsx`: API constants and `startAnalysis`, `cancelPcapAnalysis`, polling effect, `downloadJobArtifact`.
- `PcapAnalyzerPage.tsx`: rendered analyzer panel and result cards/tables.

## Frontend-Only Evidence

- Some dashboard/network score calculations are frontend-derived from recent report data in `networkSecurityScore.ts`; they are not the same as backend `summary.security_score`.
- `recentPcapAlerts.ts` localStorage cache is frontend-only; backend persistence is through `PcapAlertRecord`.
- Admin report-generation demo behavior exists in `adminReportsService.ts`, but a connected backend generation endpoint was not confirmed in PCAP route code.

## Limitations

- Frontend text says Strict reduces false positives; backend has confidence presets and suppression logic, but quantitative false-positive reduction is not proven by code.
- Frontend can show cached snapshots; cached data should not be treated as authoritative for backend behavior.
