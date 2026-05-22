# PCAP Project Discovery Map

## Core PCAP Logic

- `Backend/app.py` - core PCAP routes, pipeline orchestration, ownership checks, alert persistence, admin overview/export.
- `Backend/pcap_engine/jobs.py` - job registry, background executor, state/report JSON persistence, cancellation.
- `Backend/pcap_engine/tshark_runner.py` - packet export using `tshark`, optional `editcap` chunking.
- `Backend/pcap_engine/cic_stream_features.py` - CIC-like flow feature extraction.
- `Backend/pcap_engine/ml_infer.py` - model bundle loading and inference.
- `Backend/pcap_engine/flow_features.py` - context feature extraction.
- `Backend/pcap_engine/heuristics.py` - supporting heuristic signals.
- `Backend/pcap_engine/security_logic.py` - severity, confidence, support, validation, suppression, verdict/reason logic.
- `Backend/pcap_engine/scorer.py` - ML/heuristic/context score fusion.
- `Backend/pcap_engine/reporter.py` - report, alerts, clusters, risk per IP.
- `Backend/pcap_engine/zeek_runner.py` - optional Zeek execution.
- `Backend/pcap_engine/zeek_loader.py` - Zeek log loading.
- `Backend/pcap_engine/cleanup.py` - stale artifact/job cleanup.

## Model / Metrics / Training

- `Backend/model/threat_model_pcap65.pkl` - runtime PCAP65 model bundle.
- `Backend/model/metrics_pcap65.json` - PCAP65 metrics and feature contract.
- `Backend/model/threat_model.pkl`, `Backend/model/metrics.json`, `Backend/model/label_encoder.pkl` - older/alternate model artifacts; not primary runtime PCAP65 path.
- `Backend/train_pcap65_model.py` - training script for PCAP65 bundle.
- `Backend/data/RT_IOT2022.csv`, `Backend/data/train_set_LYCOS.csv`, `Backend/data/test_set_LYCOS.csv`, `Backend/data/crossval_set_LYCOS.csv` - training/evaluation data referenced by training script.

## Runtime Artifacts

- `Backend/pcap_runs/` - PCAP uploads, packet CSVs, encrypted artifacts, Zeek folders.
- `Backend/pcap_runs/_jobs/<job_id>/state.json` - job state.
- `Backend/pcap_runs/_jobs/<job_id>/report.json` - report JSON.
- Root `ids2017_benign_monday_00003_20170703141409.pcap` - sample PCAP file present.
- Root `conn.log`, `dns.log`, `ssl.log`, `ntp.log`, `quic.log`, `weird.log`, `packet_filter.log` - Zeek-like/sample logs; indirectly related but not core runtime code.

## Frontend UI

- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx` - core user PCAP UI.
- `Cybersecurity Dashboard Design/src/components/admin/PcapAnalysisAdminControl.tsx` - admin PCAP UI.
- `Cybersecurity Dashboard Design/src/components/admin/PcapAnalysisAdminControl.css` - admin PCAP styling.
- `Cybersecurity Dashboard Design/src/services/adminPcapOverview.ts` - admin PCAP API client.
- `Cybersecurity Dashboard Design/src/utils/recentPcapAlerts.ts` - PCAP alert normalization/cache.
- `Cybersecurity Dashboard Design/src/utils/networkSecurityScore.ts` - PCAP-derived dashboard score.
- `Cybersecurity Dashboard Design/src/utils/pcapChartSelectors.ts` - report chart selectors.
- `Cybersecurity Dashboard Design/src/components/security/NetworkSecurityScoreCard.tsx` - PCAP score card.
- `Cybersecurity Dashboard Design/src/components/security/RecentSecurityAlertsPanel.tsx` - recent alerts panel including PCAP feed.
- `Cybersecurity Dashboard Design/src/components/security/RiskPerIpCard.tsx` - risk per IP display.
- `Cybersecurity Dashboard Design/src/components/security/SeverityBreakdownCard.tsx`, `ThreatBreakdownCard.tsx`, `ThreatActivityAreaChart.tsx`, `ChartEmptyState.tsx`, `SecurityScoreCard.tsx` - shared security visual components used by PCAP page.

## Admin / Reports / Monitoring

- `Cybersecurity Dashboard Design/src/services/adminReportsService.ts` - PCAP report summary/demo/export integration; partly connected to admin overview, includes demo report fallback.
- `Cybersecurity Dashboard Design/src/components/admin/ReportsExportCenterPage.tsx` - report export center; indirectly PCAP-related.
- `Backend/reports/monthly_security_report_service.py`, `monthly_security_report_renderer.py`, `monthly_security_report_job.py` - monthly report code includes PCAP alert/job counts indirectly.
- `Cybersecurity Dashboard Design/src/components/pages/MonthlyReportsPage.tsx` - displays monthly report PCAP section indirectly.
- `Cybersecurity Dashboard Design/src/components/pages/UserActivityLogsPage.tsx` - filters/displays PCAP activity logs.

## Tests / Helpers

- `Backend/tests/test_pcap_route_contracts.py` - PCAP route contract tests.
- `Backend/tests/test_pcap_scoring_regression.py` - scoring regression tests.
- `Backend/tests/test_pcap_artifact_protection.py` - artifact protection tests.
- `Backend/tests/test_pcap_alert_persistence_regression.py` - alert persistence tests.
- `Backend/tests/test_pcap_summary_evidence_merge_regression.py` - summary/evidence merge regression.
- `Backend/tests/validate_with_labels.py`, `Backend/tests/run_from_file.py` - test/helper scripts.
- `test_predict.py`, `test_comprehensive.py` - root-level test/demo files; PCAP relevance should be verified before citing.
- `Backend/dev_reset_pcap_alerts.py` - development helper for PCAP alerts.

## Existing Docs Related to PCAP

- `docs/PCAP_DEEP_REFERENCE.md`
- `docs/PCAP_QUICK_REVIEW.md`
- `docs/PCAP_GAMIFICATION_MASTER_REPORT.md`
- `docs/PCAP_FULL_PROJECT_REFERENCE_AR.md`
- `docs/pcap_final_acceptance_report.md`
- `docs/pcap_artifact_protection_plan.md`
- `docs/chapter4/pcap_chapter4_mermaid_diagrams.md`

Use these as owner-provided context only; this evidence pack prioritizes code evidence.

## Not Relevant After Inspection

- Password checker, file vault, phishing scanner, identity leak files are out of PCAP scope except where monthly reports, dashboard alerts, high-risk users, or activity logs aggregate PCAP with other modules.
- `Backend/venv`, `Cybersecurity Dashboard Design/node_modules`, `__pycache__`, `.db`, `.log`, `.enc`, and binary artifacts should not be cited as source evidence except to note artifact presence.
