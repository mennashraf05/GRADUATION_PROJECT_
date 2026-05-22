# PCAP User and Admin Journeys

## User Journey

| Step | UI component | Backend endpoint | Data produced | Screenshot needed | Evidence |
|---|---|---|---|---|---|
| Upload PCAP | `PcapAnalyzerPage` upload panel | `POST /analyze-pcap` | saved PCAP, `JobState` | Upload panel | `PcapAnalyzerPage.tsx`, `Backend/app.py` |
| Start analysis | Analyze button | `POST /analyze-pcap` | `job_id`, queued state | Running progress | same |
| Wait/poll status | Progress card | `GET /job/<job_id>` | progress/status/report when done | Progress card | polling effect in `PcapAnalyzerPage.tsx`; `get_job` |
| View results | Summary/cards/tables | `GET /job/<job_id>` inline report | normalized report | Completed summary | `reporter.py`, `PcapAnalyzerPage.tsx` |
| View alerts | Alerts drilldown table | report inline | alert rows | Alerts table | `reporter.py` `alerts` |
| View clusters | Cluster table | report inline | cluster rows | Clusters table | `cluster_alerts` |
| View risk per IP | `RiskPerIpCard` | report inline | `risk_per_ip` rows | Risk per IP card | `_build_risk_per_ip` |
| View evidence/report | Detail drawer / raw JSON | report inline | selected alert/cluster raw data | Detail drawer | `PcapAnalyzerPage.tsx` |
| Export report | Export button | `/job/<id>/export?type=report` | JSON download | Export action | `export_job_artifact` |
| Export evidence | Export evidence button | `/job/<id>/export?type=evidence` | ZIP download | Evidence export | `_build_job_evidence_bundle` |
| Cancel analysis | Cancel button | `POST /api/pcap/cancel/<id>` | cancelled state | Cancelled state | `cancel_pcap_job` |
| Clear/dismiss alerts | Dashboard recent alerts panel | clear/dismiss PCAP alerts endpoints | dismissed DB records | Recent alerts panel | `RecentSecurityAlertsPanel.tsx`, `dismiss_visible_pcap_alerts` |

## Admin Journey

| Step | UI component | Backend endpoint | Data produced | Screenshot needed | Evidence |
|---|---|---|---|---|---|
| View PCAP jobs overview | `PcapAnalysisAdminControl` | `GET /api/admin/pcap/overview` | summary, queue, job rows | Admin metrics | `admin_pcap_overview` |
| Monitor queue | Queue Health card | same | queued/running/failed/completed counts | Queue health | `_pcap_admin_queue_health` |
| View latest results | Latest Analysis Results table | same | latest job rows | Latest files table | `_pcap_admin_job_row` |
| View suspicious files | suspicious/ranked files section | same | top suspicious files | Suspicious files | admin component |
| View timeline | Admin timeline section | same | job workflow events | Timeline | `_pcap_admin_timeline_for_job` |
| Preview report | Eye action | `/api/admin/pcap/jobs/<id>/export?type=report` | JSON text preview | Report preview | admin component |
| Export report | Report export action | same endpoint | JSON download | Export toast/button | `admin_export_pcap_job_artifact` |
| Export evidence | Evidence action | `/api/admin/pcap/jobs/<id>/export?type=evidence` | ZIP download | Evidence button | same |
| Inspect user activity | User Activity Logs page | activity endpoints outside PCAP scope | PCAP module activity logs | Activity logs filtered to PCAP | `UserActivityLogsPage.tsx`, `log_user_event` calls |
