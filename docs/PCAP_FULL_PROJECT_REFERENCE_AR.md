# Sentinel AI PCAP Full Project Reference

آخر تحديث: 2026-05-14

الملف ده مرجع شامل لكل اللي اتعمل في جزء PCAP داخل مشروع Sentinel AI: باك إند، فرونت إند، يوزر، أدمن، شات بوت، تقارير، تنبيهات، تخزين، حماية artifacts، scoring، وارتباطه بباقي السيستم.

مهم جدا: PCAP Analyzer منفصل عن Security Score الشخصي. Security Score الشخصي لا يدخل فيه PCAP نهائيا. Security Score يتكون فقط من:

- Password Checker 25%
- File Vault 25%
- Phishing Scanner 25%
- Identity Leak 25%

PCAP له score/report خاص به داخل تقرير تحليل الشبكة، لكنه ليس component في Security Score.

---

## 1. فكرة PCAP Module

PCAP Analyzer هو موديول network forensics داخل Sentinel AI. وظيفته إن المستخدم يرفع ملف `.pcap` أو `.pcapng`، والسيستم يحوله من packets إلى flows، يشغل ML model، يضيف heuristics، optionally يستخدم Zeek evidence، ثم يطلع report شامل.

هو يجاوب على أسئلة زي:

- الملف فيه كام flow؟
- هل فيه suspicious أو malicious traffic؟
- إيه أعلى risk level؟
- إيه attack families أو labels اللي ظهرت؟
- إيه IPs أو ports محتاجة review؟
- هل Zeek evidence دعمت أو ضعفت قرار الـ ML؟
- هل التقرير جاهز للتصدير؟
- هل فيه evidence bundle؟

---

## 2. أهم ملفات PCAP في المشروع

### Backend

- `Backend/app.py`
  - routes الخاصة بالـ PCAP
  - orchestration للـ pipeline
  - job lifecycle
  - auth/ownership
  - alerts persistence
  - admin overview
  - chatbot context/fallback
  - notifications
  - artifact export/protection

- `Backend/pcap_engine/jobs.py`
  - `JobRegistry`
  - job state persistence
  - background thread execution
  - cancellation
  - `state.json`
  - `report.json`

- `Backend/pcap_engine/tshark_runner.py`
  - تشغيل tshark وتحويل PCAP إلى packet CSV

- `Backend/pcap_engine/cic_stream_features.py`
  - تحويل packet CSV إلى CIC-style flow features

- `Backend/pcap_engine/ml_infer.py`
  - تحميل model وتشغيل inference

- `Backend/pcap_engine/flow_features.py`
  - بناء flow context features

- `Backend/pcap_engine/heuristics.py`
  - rules/heuristics لتقوية أو تفسير detections

- `Backend/pcap_engine/security_logic.py`
  - canonical detection logic
  - severity mapping
  - support levels
  - validation/suppression
  - verdict floors/caps

- `Backend/pcap_engine/scorer.py`
  - `fuse_scores()`
  - دمج ML score + heuristic score + context support + validation

- `Backend/pcap_engine/reporter.py`
  - بناء `report.json`
  - summary, alerts, clusters, timeline, risk_per_ip, module_contract

- `Backend/pcap_engine/zeek_runner.py`
  - تشغيل Zeek

- `Backend/pcap_engine/zeek_loader.py`
  - تحميل `conn.log`, `dns.log`, `http.log`, `ssl.log`

- `Backend/pcap_engine/cleanup.py`
  - cleanup scheduler للـ old artifacts

- `Backend/model/threat_model_pcap65.pkl`
  - trained PCAP65 model bundle

- `Backend/model/metrics_pcap65.json`
  - model metrics/version metadata

### Frontend

- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`
  - صفحة المستخدم الرئيسية لتحليل PCAP
  - upload
  - include Zeek
  - confidence mode
  - progress/job polling
  - report visualization
  - alerts/clusters/timeline
  - history
  - export report/evidence

- `Cybersecurity Dashboard Design/src/components/admin/PcapAnalysisAdminControl.tsx`
  - لوحة الأدمن لمراقبة PCAP operations
  - queue health
  - latest jobs
  - top suspicious files
  - attack families
  - exports
  - timeline

- `Cybersecurity Dashboard Design/src/services/adminPcapOverview.ts`
  - frontend service contract لـ `/api/admin/pcap/overview`
  - normalize admin overview payload
  - admin export URLs

- `Cybersecurity Dashboard Design/src/utils/recentPcapAlerts.ts`
  - cache/normalize recent PCAP alerts
  - localStorage snapshots
  - dashboard/notification integration

- `Cybersecurity Dashboard Design/src/utils/networkSecurityScore.ts`
  - network-only PCAP score summary للواجهة
  - ده score منفصل خاص بالـ PCAP/network analysis وليس Security Score الشخصي

- `Cybersecurity Dashboard Design/src/utils/pcapChartSelectors.ts`
  - تجهيز chart data من report alerts/clusters/timeline

- `Cybersecurity Dashboard Design/src/components/NotificationCenter.tsx`
  - يعرض PCAP alerts/report/evidence notifications

- `Cybersecurity Dashboard Design/src/components/Layout.tsx`
  - nav item للـ PCAP Analyzer
  - recent PCAP alert cache/session handling

### Docs/Tests

- `docs/PCAP_DEEP_REFERENCE.md`
- `docs/PCAP_QUICK_REVIEW.md`
- `docs/pcap_artifact_protection_plan.md`
- `docs/pcap_final_acceptance_report.md`
- `docs/PCAP_GAMIFICATION_MASTER_REPORT.md`
- `Backend/tests/test_pcap_route_contracts.py`
- `Backend/tests/test_pcap_scoring_regression.py`
- `Backend/tests/test_pcap_summary_evidence_merge_regression.py`
- `Backend/tests/test_pcap_artifact_protection.py`
- `Backend/tests/test_pcap_alert_persistence_regression.py`

---

## 3. Backend Routes الخاصة باليوزر

### Analyze uploaded PCAP

Routes:

- `POST /pcap/analyze`
- `POST /analyze-pcap`

Request:

- multipart form-data
- `file`: required, `.pcap` or `.pcapng`
- `include_zeek`: optional, default true
- `confidence_mode`: optional
- `max_alerts`: optional
- `max_clusters`: optional

Behavior:

- يرفض الملف لو أكبر من 15 GB.
- يقبل فقط `.pcap` و `.pcapng`.
- يحفظ الملف باسم UUID مش باسم المستخدم.
- يحسب SHA-256 لو قدر.
- يحسب sample fingerprint للـ dedup.
- يبني `analysis_key`.
- ينشئ job أو يعيد استخدام active job مشابه.
- يسجل User Activity:
  - `pcap_uploaded`
  - `pcap_analysis_started`
  - `pcap_reanalysis_started` لو نفس المصدر اتكرر
- يسجل gamification upload event.
- ينشئ notification أن job بدأ.
- يرجع `202` وفيه `job_id`.

Response example:

```json
{
  "job_id": "...",
  "status": "queued",
  "poll": "/job/..."
}
```

### Analyze local PCAP path

Routes:

- `POST /pcap/analyze-local`
- `POST /analyze-local`

Request JSON:

```json
{
  "pcap_path": "path/to/file.pcap",
  "include_zeek": true,
  "confidence_mode": "balanced",
  "max_alerts": 100,
  "max_clusters": 100
}
```

Behavior:

- يستخدم authenticated PCAP context.
- يتحقق إن path داخل `LOCAL_PCAP_ALLOWED_ROOT`.
- يمنع arbitrary filesystem traversal.
- يحسب file hash.
- يحسب local source key من path/size/mtime.
- يستخدم نفس job registry والدedup.
- يسجل:
  - local PCAP queued
  - reanalysis لو موجود قبل كده

### Job history

Routes:

- `GET /pcap/jobs`
- `GET /jobs`

يرجع jobs الخاصة بالـ owner الحالي فقط.

Response:

```json
{
  "jobs": [],
  "count": 0
}
```

### Job status / result

Routes:

- `GET /pcap/result/<job_id>`
- `GET /pcap/status/<job_id>`
- `GET /job/<job_id>`

Behavior:

- يتحقق من ownership.
- يرجع state:
  - job_id
  - status
  - created_at / started_at / finished_at
  - progress
  - message
  - error summary
  - upload_name/path
  - report_available
  - evidence_available
  - artifact_protection
- لو job `done` وفيه report، بيرجع report inline.
- لو queued/running، بيرجع `poll_after_ms`.
- يضيف header `Retry-After`.

### Cancel job

Routes:

- `POST /api/pcap/cancel/<job_id>`
- `POST /pcap/cancel/<job_id>`

Behavior:

- يسمح بإلغاء job في `queued/running/processing`.
- لو job خلص بالفعل يرجع message أنه completed.
- لو failed يرجع already failed.
- لو cancelled يرجع cancelled.
- يسجل activity:
  - `pcap_analysis_cancel_requested`
  - `pcap_analysis_cancelled`
  - `pcap_analysis_cancel_failed` عند الخطأ
- يحاول terminate subprocesses المرتبطة مثل tshark/Zeek.

### Export report/evidence

Routes:

- `GET /pcap/report/<job_id>`
- `GET /job/<job_id>/export?type=report`
- `GET /job/<job_id>/export?type=evidence`
- `GET /job/<job_id>/export?type=bundle`

Behavior:

- report export يرجع `pcap_report_<job_id>.json`.
- evidence/bundle export يرجع `pcap_evidence_<job_id>.zip`.
- evidence bundle قد يحتوي:
  - `report.json`
  - `state.json`
  - Zeek logs مثل `conn.log`, `dns.log`, `http.log`, `ssl.log`
- يسجل activity:
  - `pcap_report_downloaded`
  - `pcap_evidence_downloaded`
- يسجل gamification download event.

### PCAP alerts feed

Routes:

- `GET /api/pcap/alerts`
- `GET /pcap/alerts`

Behavior:

- يرجع recent PCAP alerts للمستخدم.
- يعمل backfill من recent jobs لو محتاج.
- يستخدم `PcapAlertRecord`.
- يحترم owner scope.
- لا يرجع dismissed alerts إلا حسب mode/filters.

### Dismiss/Clear PCAP alerts

Routes:

- `POST /api/pcap/alerts/dismiss-visible`
- `POST /api/pcap/alerts/clear`
- `POST /pcap/alerts/dismiss-visible`
- `POST /pcap/alerts/clear`

Request:

```json
{
  "alert_ids": [1, 2, 3],
  "dismiss_all_visible": false
}
```

Behavior:

- يخفي alerts المرئية للمستخدم.
- يمنع dismiss لalerts غير مملوكة للمستخدم.
- يسجل:
  - `security_alert_dismissed`
  - `security_alerts_cleared`

---

## 4. Auth و Ownership

PCAP routes تستخدم `PcapRequestContext`.

ممكن owner يكون:

- authenticated user
- localhost fallback client في development/local PCAP routes

Important:

- فيه cookie اسمه `sentinel_pcap_client_id` للـ local fallback.
- fallback ده مفيد أثناء التطوير، لكنه ممكن يخفي مشاكل auth في الفرونت.
- jobs مربوطة بـ:
  - `owner_user_id`
  - `owner_user_scope`
  - `owner_client_id`
  - `analysis_key`

أي job status/export/alerts بيتحقق من ownership قبل الرد.

---

## 5. Job Registry و Storage

PCAP jobs بتتخزن في:

- `Backend/pcap_runs/_jobs/<job_id>/state.json`
- `Backend/pcap_runs/_jobs/<job_id>/report.json`

Job statuses:

- `queued`
- `running`
- `done`
- `error`
- `cancelled`

`JobRegistry`:

- in-memory registry
- persistent state on disk
- background `ThreadPoolExecutor`
- `create_or_reuse_active()`
- `submit()`
- `update()`
- `request_cancel()`
- `list_recent()`

`state.json` يحتوي:

- job_id
- status
- timestamps
- progress/message
- owner
- upload_path
- packet_csv_path
- report_path
- evidence_dir
- error
- analysis_key
- file_hash
- artifact_protection
- cancellation flags

---

## 6. Pipeline بالتفصيل

Architecture الأساسية:

```text
tshark -> CIC -> ML -> base context -> heuristics -> optional Zeek -> fuse_scores -> comparison -> report
```

### 6.1 Request Intake

المستخدم يرفع ملف أو يختار local path.

Backend:

- validates file/path
- saves file
- computes hash/fingerprint
- creates/reuses job
- starts background pipeline

### 6.2 tshark Export

File:

- `Backend/pcap_engine/tshark_runner.py`

Function:

- `run_tshark_export()`

وظيفته:

- يشغل tshark.
- يطلع packet CSV.
- يستخدم native Windows tshark أو fallback لـ WSL tshark.

Fields exported تشمل:

- frame time
- IP src/dst
- IPv6 src/dst
- TCP/UDP ports
- protocol
- frame length
- TCP flags

### 6.3 CIC Flow Features

File:

- `Backend/pcap_engine/cic_stream_features.py`

Function:

- `build_cic_features_from_tshark_csv()`

وظيفته:

- يحول packets إلى flows.
- يبني CIC-like schema.
- يحسب:
  - duration
  - packet counts
  - byte counts
  - IAT stats
  - active/idle stats
  - flag counts
  - forward/backward direction stats

مهم:

- schema لازم يطابق `EXPECTED_CIC65`.
- أي drift بين tshark output وCIC features ممكن يكسر model inference.

### 6.4 ML Inference

Files:

- `Backend/pcap_engine/ml_infer.py`
- `Backend/model/threat_model_pcap65.pkl`

Functions:

- `prepare_inference_frame()`
- `predict_flows()`

Output fields:

- `ml_label`
- `ml_confidence`

Behavior:

- يحمل model bundle.
- يطابق feature columns مع trained columns.
- يسمح safe missing فقط لبعض categoricals مثل `ip_prot` و `service`.
- أي missing خطير في model features يعتبر failure.

### 6.5 Flow Context + Heuristics

Files:

- `Backend/pcap_engine/flow_features.py`
- `Backend/pcap_engine/heuristics.py`

Context features ممكن تشمل:

- source connection counts
- unique destination ports
- failed connection ratio
- source-destination flow counts
- packet rate
- bytes per second

Heuristics تضيف:

- `heuristic_type`
- `heuristic_score`
- `heuristic_reason`

### 6.6 Optional Zeek Enrichment

Files:

- `Backend/pcap_engine/zeek_runner.py`
- `Backend/pcap_engine/zeek_loader.py`

Zeek ينتج evidence logs مثل:

- `conn.log`
- `dns.log`
- `http.log`
- `ssl.log`

Zeek mode:

- ممكن يشتغل parallel مع tshark/CIC/ML.
- بعد كده evidence يتم تحميلها ودمجها مع flows.

Zeek evidence يستخدم لتقوية أو إضعاف detections. لو ML قال threat لكن evidence/context ضعيف، ممكن verdict ينزل.

### 6.7 Evidence Merge

Backend يدمج:

- conn evidence
- dns summary evidence
- http summary evidence
- ssl summary evidence

Important safety:

- conn merge protocol-aware.
- DNS/HTTP/SSL merge تعتمد على endpoint/port/time bucket مع fallback guards.
- fallback guards لازم تفضل strict عشان evidence ما تتركبش على flow غلط.

### 6.8 Score Fusion

File:

- `Backend/pcap_engine/scorer.py`

Function:

- `fuse_scores()`

Scoring logic:

```text
raw_score = 0.95 * ml_score + 0.05 * heuristic_score
context_scaled = raw_score * support_multiplier
final_score = clamp/context adjusted by verdict cap/floor
Normal verdict => final_score = 0
confidence = final_score
```

Support multiplier:

- none: 0.15
- weak: 0.35
- moderate: 0.70
- strong: 1.00

Verdict caps:

- Normal: 0.0
- Low: 0.30
- Medium: 0.60
- High: 0.82
- Critical: 0.97

Verdict floors:

- Normal: 0.0
- Low: 0.20
- Medium: 0.40
- High: 0.65
- Critical: 0.85

Non-normal verdict floor يعتمد على support level:

- none/weak: no effective floor
- moderate: 50% من floor
- strong: full floor

Output columns:

- severity
- ml_score
- confidence_tier
- validation_failed
- validation_reason
- support_level
- support_multiplier
- signal_verdict
- verdict
- support_promoted
- support_demoted
- final_score
- confidence
- reason

### 6.9 Base vs Enriched Comparison

لو Zeek enabled:

- backend يحسب base scoring قبل evidence.
- بعد evidence يحسب final scoring.
- يعمل comparison:
  - compared_rows
  - changed_by_evidence_up
  - changed_by_evidence_down
  - base_only_rows
  - enriched_only_rows

ده مفيد عشان نعرف Zeek غير قرارات إيه.

### 6.10 Report Generation

File:

- `Backend/pcap_engine/reporter.py`

Function:

- `build_report()`

Report sections:

- `meta`
- `summary`
- `module_contract`
- `risk_per_ip`
- `clusters`
- `alerts`
- `timeline`

---

## 7. PCAP Report Contract

### meta

يشمل:

- generated_at
- pcap_path
- run_folder
- zeek_requested
- zeek_enrichment_succeeded
- zeek_evidence_available
- analysis_mode
- comparison
- pipeline details

### summary

يشمل:

- total_flows
- alerts_count
- suspicious
- malicious
- overall_risk
- risk_level
- risk_context_label
- risk_display
- top_attackers
- security_score
- score_explanation
- security_score_level
- top_risk
- security_summary
- security_trend
- cluster_count
- severity_counts

ملاحظة مهمة:

- `summary.security_score` هنا خاص بتقرير PCAP فقط، وليس Security Score الشخصي.

### module_contract

يشمل normalized PCAP module data:

- module: `pcap_analyzer`
- module_score
- status
- summary
- supporting_metrics
- severity_counts
- top_risk
- source_type

مهم:

- فيه `weight: 0.30` كـ placeholder/default داخل module contract القديم، لكن ده ليس مستخدم في Security Score الشخصي الحالي.
- Security Score الشخصي يستبعد PCAP تماما.

### alerts

Promoted findings فقط:

- type
- ts
- src_ip
- dst_ip
- dst_port
- ml_label
- ml_confidence
- classification_confidence
- confidence / threat_confidence
- severity
- reason
- Zeek evidence fields
- heuristic object

### clusters

Grouped suspicious behavior:

- attack_type
- src_ip
- dst_ip
- count_flows
- top_dst_ports
- top_dst_ips
- max_confidence
- max_threat_confidence
- max_ml_confidence
- severity

### risk_per_ip

IP-level risk summary:

- ip
- role
- threat_count
- suspicious_count
- max_confidence
- ip_risk_score
- top_attack

### timeline

كل flow-level events:

- ts
- src_ip
- dst_ip
- dst_port
- ml_label
- ml_confidence
- confidence
- threat_confidence
- verdict

---

## 8. PCAP Risk/Score في التقرير

داخل `reporter.py`:

- overall_risk محسوب من signals المترقية في alerts/clusters.
- risk level:
  - 0 => Normal
  - `< 0.20` => Low
  - `< 0.45` => Medium
  - `< 0.75` => High
  - `>= 0.75` => Critical

PCAP report security_score mapping:

- risk <= 0 => 100
- risk < 0.20 => من 95 إلى 80
- risk < 0.45 => من 79 إلى 55
- risk < 0.75 => من 54 إلى 30
- risk >= 0.75 => من 29 إلى 0

ده score خاص بتحليل PCAP فقط.

---

## 9. User Frontend: PcapAnalyzerPage

صفحة المستخدم:

- route: `/pcap-analyzer`
- file: `PcapAnalyzerPage.tsx`

الوظائف:

- رفع `.pcap` أو `.pcapng`
- تحديد confidence mode
- اختيار Include Zeek Evidence
- تشغيل analysis
- إلغاء analysis
- polling job status
- فتح job history
- فتح historical job من query param `?job=<job_id>`
- عرض report summary
- عرض posture/network score للـ PCAP
- عرض Attack Clusters
- عرض Alerts Drilldown
- عرض Activity Timeline
- detail drawer للـ evidence/reasoning
- export report JSON
- export evidence ZIP

### UI Sections

- Analyzer Panel
- Upload PCAP
- confidence mode selector
- Include Zeek Evidence checkbox
- Analyze PCAP / Cancel button
- Live job telemetry
- artifact readiness
- Security summary cards
- Attack Clusters table
- Alerts Drilldown table
- Activity Timeline table
- Job History drawer/modal

### Polling

الفرونت يعمل polling على:

- `/job/<job_id>`

ويستخدم:

- `poll_after_ms`
- `Retry-After`

الـ backend حاليا يوصي بـ 600000 ms، يعني 10 دقائق، لتقليل الضغط.

### History

الفرونت يقرأ:

- `/jobs`
- `/pcap/jobs`

ويعرض آخر jobs persisted في backend registry.

### Exports

الفرونت يستخدم:

- `/job/<job_id>/export?type=report`
- `/job/<job_id>/export?type=evidence`

ويحمل:

- `pcap_report_<job_id>.json`
- `pcap_evidence_<job_id>.zip`

---

## 10. Admin PCAP Operations

### Backend endpoint

Route:

- `GET /api/admin/pcap/overview`

Auth:

- `@admin_auth_required`

يرجع:

- summary
- queue_health
- latest_attack_families
- top_suspicious_files
- latest_files
- performance
- engine_status
- timeline
- generated_at

### Admin export endpoint

Route:

- `GET /api/admin/pcap/jobs/<job_id>/export?type=report`
- `GET /api/admin/pcap/jobs/<job_id>/export?type=evidence`

Behavior:

- report => JSON
- evidence => ZIP
- يسجل admin action:
  - `report_exported`
  - target module: PCAP Analysis

### Admin frontend files

- `PcapAnalysisAdminControl.tsx`
- `adminPcapOverview.ts`

### Admin UI shows

- Total Uploaded Files
- Total Jobs
- Running Jobs
- Completed Jobs
- Failed Jobs
- Queued Jobs
- Average Processing Time
- Last Analysis Time
- Queue Health
- Processing Performance
- Latest 5 PCAP Analysis Results
- Top Suspicious Files
- Observed Classification Labels
- Analysis Timeline

### Queue health logic

- failed >= 3 => critical
- failed > 0 أو queued >= 10 => warning
- running > 3 ومعاه queued => warning
- no activity => unknown
- otherwise healthy

### Admin job row

كل job row يحتوي:

- job_id
- filename
- status
- score
- risk_level
- detected_family
- analysis_mode
- zeek_used
- processing_time_seconds
- created_at
- started_at
- finished_at
- report_available
- evidence_available
- threat_detected
- timeline_available

### Analysis mode normalization

- Hybrid Logic
- ML Only
- Heuristics Only
- Unknown

Hybrid لو:

- Zeek evidence موجود
- أو ML + heuristics موجودين
- أو report meta يقول enriched/hybrid

---

## 11. PCAP Alerts

PCAP alerts يتم توليدها من:

- report summary
- alerts
- clusters
- timeline fallback

Database model:

- `PcapAlertRecord`
- table: `pcap_alert`

Schema مهم:

- id
- user_id
- owner_user_scope
- job_id
- alert_key
- type
- title
- message
- severity
- risk_label
- confidence
- threats_count
- flows_analyzed
- top_pattern
- filename
- status
- event_at
- created_at
- dismissed_at
- metadata_json

فيه schema initializer:

- `_ensure_pcap_alert_schema_initialized()`

بيضيف columns/indexes لو ناقصة.

Alerts تظهر في:

- Recent Security Alerts
- Notification Center
- Dashboard feeds
- Admin threat views
- User Activity Logs

---

## 12. Notifications

PCAP يدخل في notification system.

Events:

- job started
- analysis completed
- report ready
- evidence ready
- high-risk PCAP analysis
- failed analysis

Channels:

- in-app Notification Center
- email completion notification لو SMTP/user settings متاحة
- Telegram completion notification لو configured

Email payload:

- subject مثل:
  - `Sentinel AI: PCAP analysis completed (<risk_level> risk)`
- يحتوي summary ورابط Open PCAP Analysis.

Telegram:

- يرسل completion notification مع risk/status summary.

---

## 13. User Activity Logs

PCAP activities المسجلة تشمل:

- `pcap_uploaded`
- `pcap_analysis_started`
- `pcap_reanalysis_started`
- `pcap_analysis_completed`
- `pcap_analysis_failed`
- `pcap_analysis_cancel_requested`
- `pcap_analysis_cancelled`
- `pcap_analysis_cancel_failed`
- `pcap_report_downloaded`
- `pcap_evidence_downloaded`
- `pcap_chatbot_question`
- alert dismissed/cleared events

UI:

- `UserActivityLogsPage.tsx`
- filters include PCAP Analyzer.

---

## 14. Gamification

PCAP متصل بـ gamification service.

Events:

- record upload
- record report download
- record evidence download

Docs:

- `docs/PCAP_GAMIFICATION_MASTER_REPORT.md`

Frontend عنده components عامة:

- SecurityProgressCard
- BadgeCollectionCard
- RewardHistoryCard
- ActiveChallengesCard

PCAP score هنا منفصل/شبكي وليس Security Score الشخصي.

---

## 15. Monthly Reports / Reports Center

PCAP يظهر في التقارير كـ network-traffic report category منفصل.

ممكن يظهر في:

- Monthly Reports
- Reports & Export Center
- user-facing exports

Allowed user-facing exports:

- PCAP user report JSON
- PCAP evidence ZIP
- Monthly security PDF where renderer available

Important:

- PCAP report ممكن يدخل في Reports Center كملخص منفصل.
- لا يتم دمجه كcomponent داخل Security Score.

---

## 16. Chatbot الخاص بـ PCAP

### Dedicated endpoint

Route:

- `POST /api/chatbot/pcap`

Behavior:

- يستخدم optional authenticated user.
- يقدر ياخد `analysis_id`.
- يبني context من latest أو specific PCAP job.
- يسجل User Activity:
  - `pcap_chatbot_question`

### LLM endpoint العام

Route:

- `POST /api/chatbot/llm`

لو module = `pcap`:

- backend يبني safe PCAP context.
- يحاول Ollama لو متاح.
- fallback rule-based لو Ollama مش شغال/model missing/timeout/error.

### Safe PCAP context

مسموح للشات بوت يشوف:

- latest analysis status
- total flows
- suspicious/malicious counts
- alert counts
- severity counts
- top detections
- risk level
- risk score
- top IPs if available
- top risky flows summary
- ML labels
- heuristic reasons
- Zeek evidence availability
- report sections availability
- PCAP scoring logic summary

ممنوع:

- raw packets
- raw payloads
- raw PCAP content
- secrets
- tokens
- encryption keys

### Unified PCAP chatbot context

آخر تحسين للشات بوت خلّى الـ backend يبني object واحد واضح وآمن اسمه `pcap_context`، وده اللي Ollama أو fallback يعتمدوا عليه في أسئلة PCAP بدل إجابات عامة ضعيفة.

الشكل العام:

```json
{
  "has_latest_report": true,
  "latest_job_id": "...",
  "latest_report_id": "...",
  "status": "done",
  "analyzed_at": "...",
  "filename": "safe-stored-name.pcap",
  "summary": {
    "total_flows": 0,
    "suspicious_flows": 0,
    "malicious_flows": 0,
    "total_alerts": 0,
    "risk_level": "Low/Medium/High/Critical/Normal/Unknown",
    "overall_risk": null,
    "security_score": null,
    "is_clean": true
  },
  "severity_counts": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "top_threats": [],
  "top_alerts": [],
  "ip_review_summary": {
    "available": true,
    "source": "risk_per_ip | alerts | flows | clusters | unavailable",
    "top_ips": []
  },
  "pipeline_summary": {
    "steps": [
      "Upload PCAP",
      "Extract flows with tshark/CIC/available extractor",
      "Apply ML model if available",
      "Apply heuristic rules",
      "Fuse scores",
      "Generate alerts",
      "Build report",
      "Store summary for dashboard/reports/chatbot"
    ]
  },
  "scoring_summary": {
    "available": true,
    "explanation": "Based only on the actual project scorer/reporter logic."
  },
  "context_safe": true
}
```

ملاحظات مهمة:

- `pcap_context` لا يحتوي raw packets أو payloads أو raw PCAP content.
- لا يحتوي credentials أو tokens أو API keys أو encryption keys.
- لا يتم إرسال ملفات PCAP الخام إلى Ollama.
- الشات بوت يستخدم summary فقط، وليس packet-level data.
- PCAP score/report منفصل تماما عن Security Score الشخصي.

### PCAP chatbot intents

يدعم:

- latest summary
- detected threats
- why PCAP is risky
- severity explanation
- recommendations
- suspicious IPs
- is latest PCAP clean
- suspicious flow definition
- confidence meaning
- ML vs heuristics
- downgraded threat
- export report
- project overview
- project workflow
- report output
- Zeek enrichment
- scoring logic
- integrations
- important files

### PCAP Quick Actions النهائية

الشات بوت بقى يدعم كل أزرار Quick Actions الخاصة بـ PCAP، بالإنجليزي والعربي، وكلها لازم تتبعت من الفرونت بـ `module: "pcap"`:

1. `Summarize my latest PCAP analysis`
   - عربي: `لخص آخر تحليل PCAP`
   - يستخدم status, risk level, alerts, flows, suspicious/malicious counts, top threats, severity counts.

2. `What threats were detected?`
   - عربي: `إيه التهديدات اللي ظهرت؟`
   - يستخدم `top_threats` و `top_alerts` فقط.

3. `Why is this PCAP risky?`
   - عربي: `ليه ملف PCAP ده خطر؟`
   - يشرح المخاطر من critical/high alerts، suspicious/malicious flows، repeated detections، وhigh confidence signals لو موجودة.

4. `Explain the severity`
   - عربي: `اشرحلي severity`
   - يشرح Critical/High/Medium/Low ويربطها بـ `severity_counts`.

5. `What should I do next?`
   - عربي: `أعمل إيه بعد كده؟`
   - يعطي خطوات عملية: راجع critical/high alerts، راجع IPs، تحقق من detection types، أكد هل الترافيك متوقع، ثم export/report evidence.

6. `Which IPs should I review?`
   - عربي: `أراجع أنهي IPs؟`
   - يستخدم `pcap_context.ip_review_summary.top_ips`.
   - لا يخترع IPs لو البيانات غير موجودة.

7. `What is a suspicious flow?`
   - عربي: `يعني إيه suspicious flow؟`
   - يشرح إنها network conversation ظهر فيها سلوك غير طبيعي حسب features أو ML أو heuristics.

8. `What does confidence mean?`
   - عربي: `يعني إيه confidence؟`
   - يشرح إن confidence قوة الدليل وليس إثبات نهائي للهجوم.

9. `ML vs heuristics`
   - عربي: `الفرق بين ML و heuristics`
   - يشرح الفرق بين model-based detection وrule-based checks وhybrid fusion.

10. `Was the latest PCAP clean?`
    - عربي: `هل آخر PCAP clean؟`
    - يجاوب حسب alerts/suspicious/malicious counts، بدون fake result.

11. `Explain the PCAP Analyzer project module`
    - عربي: `اشرحلي موديول PCAP Analyzer`
    - يشرح upload, flow extraction, ML/heuristics, alerts, report, dashboard.

12. `How does the PCAP pipeline work?`
    - عربي: `البايبلاين بيشتغل إزاي؟`
    - يستخدم `pipeline_summary.steps`.

13. `What does the PCAP report contain?`
    - عربي: `التقرير بيحتوي على إيه؟`
    - يذكر summary, risk level, score لو متاح، alerts, severity distribution, detections, flows, IP summary, timeline/evidence.

14. `How PCAP connects to logs and reports`
    - عربي: `PCAP مرتبط بالتقارير واللوجز إزاي؟`
    - يشرح إن PCAP results تغذي alerts، Recent Security Alerts، Reports & Export Center، وسياق الشات بوت، لكنها لا تدخل في Security Score.

### Which IPs should I review logic

السؤال ده كان قبل كده أحيانا يرجع إجابة ضعيفة زي:

```text
The latest report does not include enough IP-level detail to rank suspicious hosts.
```

السبب إن الشات بوت كان مستني IP-level summary جاهز في report، ولو `risk_per_ip` فاضي كان يعتبر إن مفيش data كفاية، مع إن report ممكن يكون فيه IPs داخل timeline/flows.

المنطق الحالي لا يغيّر scoring ولا detection. هو فقط يبني summary آمن للشات بوت بالترتيب ده:

1. يستخدم `risk_per_ip` لو موجود ومليان.
2. لو فاضي، يجمع IPs من `alerts` حسب `src_ip` و `dst_ip`.
3. لو مفيش alerts فيها IPs، يجمع IPs من timeline/flow observations غير benign أو suspicious.
4. لو timeline غير كافي، يستخدم clusters/top talkers لو موجودة.
5. لو مفيش أي IP-level fields، يقول بوضوح إن IP-level detail غير متاح ولا يخترع IP addresses.

شكل الإجابة لو IPs متاحة:

```text
Review these IPs first:
1. x.x.x.x — High risk — 25 observations — repeated suspicious flows / top detection types...
2. y.y.y.y — Medium risk — 8 observations — unusual traffic pattern...

Start with the highest severity and highest alert count.
```

شكل الإجابة لو IPs غير متاحة:

```text
The latest PCAP report does not include IP-level fields such as risk_per_ip, alert source IP, or destination IP. I cannot safely rank suspicious hosts without inventing data.
```

في آخر اختبار محلي بعد التعديل:

- `risk_per_ip` كان موجود كحقل لكنه فاضي.
- `alerts` كانت فاضية.
- `timeline` كان فيه flow observations.
- `ip_review_summary.source = "flows"`.
- `top_ips_count = 8`.
- لم يتم اختراع أي IP خارج البيانات المتاحة.

### Frontend quick action routing

في صفحة الشات بوت، كل Quick Action الخاصة بـ PCAP بقت تبعت:

```json
{
  "message": "quick action label",
  "module": "pcap"
}
```

ده يمنع إن أسئلة PCAP تروح بالغلط لـ `general` أو `security_score` أو `identity`.

الـ provider badge ما زال:

- `Local Ollama Assistant` لو الرد من Ollama.
- `Fallback Mode` لو Ollama غير متاح أو model missing أو timeout/error.

### Debug context الخاص بـ PCAP

Route:

- `GET /api/chatbot/debug-context?module=pcap`

بيرجع diagnostics آمنة فقط، مثل:

```json
{
  "module": "pcap",
  "has_latest_report": true,
  "latest_job_id": "...",
  "status": "done",
  "risk_level": "Normal",
  "total_alerts": 0,
  "severity_counts": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "top_threats_count": 3,
  "has_ip_review_summary": true,
  "ip_summary_source": "flows",
  "top_ips_count": 8,
  "context_safe": true
}
```

لا يرجع:

- raw packets
- raw payloads
- raw PCAP content
- secrets
- credentials
- encryption keys

### Common answers

لو مفيش analysis:

```text
No PCAP analysis results were found yet. Upload and analyze a PCAP file first, then I can explain the results.
```

لو السؤال عن scoring:

- يشرح إن PCAP scoring hybrid.
- يذكر ML + heuristics + Zeek evidence + validation/suppression.
- يوضح إن PCAP منفصل عن Security Score الشخصي.

---

## 17. Ollama / Fallback behavior مع PCAP

Ollama provider:

- `Backend/llm_providers/ollama_provider.py`

Target model:

- `qwen2.5:7b`

لو Ollama مش شغال أو model missing:

- fallback يجاوب من rule-based PCAP logic.

Provider badge في الفرونت:

- `Local Ollama Assistant`
- `Fallback Mode`

PCAP fallback لا يخترع data. لو latest context مفيهوش IP details يقول إنها غير متاحة.

بعد آخر تعديل، fallback بقى يغطي كل PCAP Quick Actions المذكورة فوق. يعني حتى لو Ollama مش شغال أو model `qwen2.5:7b` مش متحمل، الشات بوت يفضل يجاوب من `pcap_context` بشكل آمن وواضح.

Ollama system/context prompt اتقوى بقواعد PCAP:

- يستخدم PCAP context فقط.
- لا يخترع alerts أو IPs أو scores أو threats.
- لو IP data ناقصة، يقول إنها ناقصة.
- يجاوب بنفس لغة المستخدم.
- لو المستخدم كتب عربي، يرد عربي بسيط مع الحفاظ على المصطلحات التقنية المفيدة بالإنجليزي.
- يعطي investigation steps عملية في أسئلة PCAP.
- لا يخرج raw packet payloads.
- يؤكد أن PCAP منفصل عن Security Score.

---

## 18. Artifact Protection / Encryption

Env vars:

- `PCAP_PROTECT_ARTIFACTS`
- `PCAP_ARTIFACT_ENCRYPTION_KEY`
- `PCAP_ARTIFACT_ENCRYPTION_MODE`
- `PCAP_ARTIFACT_RETENTION_DAYS`

Behavior:

- يحمي raw artifacts بعد terminal state فقط.
- terminal statuses:
  - done
  - error
  - failed
  - cancelled
- mode supported:
  - `copy_encrypt_verify`
- artifacts المرشحة:
  - raw `.pcap`
  - `.pcapng`
  - packet CSV
  - raw Zeek logs names
- يستخدم encrypted `.enc` artifacts.
- لا يحذف original إلا بعد verify.

مهم:

- لا تطبع encryption key.
- لا تعرض key في debug.
- لا تمس PCAP encryption env vars بدون قصد.

---

## 19. Cleanup

`pcap_engine/cleanup.py` يشغل cleanup scheduler.

الهدف:

- حذف artifacts القديمة حسب retention.
- حماية active jobs.
- تفادي حذف jobs queued/running.

Runtime risks:

- لو cleanup اتغير غلط ممكن يمس evidence/report/active job.
- لازم أي تعديل يتأكد من status protection.

---

## 20. Model / Dataset

Model file:

- `Backend/model/threat_model_pcap65.pkl`

Metrics:

- `Backend/model/metrics_pcap65.json`

Admin model version:

- مبني من modified time لـ `metrics_pcap65.json`
- format مثل `pcap65-YYYYMMDDHHMM`

Training script:

- `Backend/train_pcap65_model.py`

Model type في metadata:

- PCAP65 XGBoost Multiclass Classifier

---

## 21. Frontend Network PCAP Score

File:

- `src/utils/networkSecurityScore.ts`

ده يحسب summary للـ PCAP/network posture من آخر successful analyses.

Important:

- ده ليس Security Score الشخصي.
- يعتمد على recent PCAP jobs/reports.

Inputs:

- `/jobs`
- `/pcap/jobs`
- `/job/<job_id>`
- cached report snapshots

Score components داخل frontend helper:

- trafficCleanliness
- threatSafety
- detectionStability
- repeatedAttackPenalty

Formula:

```text
rawScore =
  0.5 * trafficCleanliness +
  0.3 * threatSafety +
  0.2 * detectionStability -
  repeatedAttackPenalty
```

Weighted recent analyses:

- weights: 0.35, 0.25, 0.20, 0.12, 0.08
- يستخدم آخر 5 analyses

Ratings:

- >= 90 Excellent
- >= 75 Good
- >= 60 Moderate
- >= 40 Risky
- else Critical

Again: ده network/PCAP-only score.

---

## 22. Security Score Relationship

PCAP Analyzer مستبعد من Security Score.

Security Score الحالي:

```text
overall =
  password_score * 0.25 +
  vault_score * 0.25 +
  phishing_score * 0.25 +
  identity_score * 0.25
```

لو component missing:

- لا يتم اختراع 50 أو 60.
- يظهر Not assessed.
- overall ممكن null أو partial/setup_incomplete حسب data.

PCAP فقط:

- يظهر كnetwork module/report.
- يظهر في admin PCAP operations.
- يظهر في reports كcategory منفصلة.
- يظهر في chatbot كموضوع منفصل.
- لا يزيد ولا يقلل Security Score الشخصي.

---

## 23. Admin vs User Differences

### User

اليوزر يقدر:

- يرفع PCAP.
- يشغل analysis.
- يلغي job.
- يشوف job progress.
- يشوف report.
- يشوف alerts/clusters/timeline.
- يحمل report JSON.
- يحمل evidence ZIP لو متاح.
- يشوف alerts في Notification Center.
- يخفي alerts.
- يسأل chatbot عن PCAP.
- يشوف PCAP events في activity logs/monthly reports.

### Admin

الأدمن يقدر:

- يشوف كل PCAP operations overview.
- يشوف total jobs/files.
- يراقب queue health.
- يشوف failed/running/completed/queued jobs.
- يشوف latest analysis results.
- يشوف top suspicious files.
- يشوف observed classification labels.
- يشوف processing performance.
- يشوف timeline generated from job metadata.
- يفتح report preview.
- يحمل report/evidence.
- يرى attack families aggregated.
- يرى engine status/model version/Zeek status.

Admin لا يحتاج ownership check الخاص بالمستخدم في overview/export، لكنه يحتاج admin auth.

---

## 24. Error Handling

Common user errors:

- no file => 400
- invalid type => 400
- too large => 413
- local path missing => 400
- local path outside allowed root => 403
- unauthorized non-local request => 401
- job not found => 404
- job not owned => 403
- export before done => 409
- artifact missing => 404

Pipeline errors:

- tshark missing/fails
- no flows extracted
- model bundle mismatch
- Zeek timeout/failure
- evidence load failure
- JSON serialization issue
- cancellation

Jobs store error trace internally but UI receives summarized error.

---

## 25. Logs مهمة للتشخيص

راقب:

- `Starting tshark export`
- `tshark export completed`
- `Packet export ready`
- `CIC feature extraction`
- `Inference schema check`
- `Inference label distribution`
- `ML inference completed`
- `Zeek run completed`
- `Zeek evidence loaded`
- `Merged conn evidence`
- `Merged dns evidence`
- `Merged http evidence`
- `Merged ssl evidence`
- `Detection scoring | stage=base_pre_evidence`
- `Detection scoring | stage=post_evidence`
- `Detection scoring | stage=final_no_zeek`
- `Detection comparison`
- `PCAP alerts feed built`
- `PCAP alert persistence skipped`
- `PCAP auth fallback enabled for localhost`
- `cleanup started`
- `cleanup completed`

---

## 26. Runtime Risks / Caveats

- Large PCAPs مكلفة جدا في disk/RAM/CPU.
- tshark يطلع intermediate CSV كبير.
- pandas يمسك dataframes كبيرة.
- JobRegistry max workers ممكن يعمل ضغط لو كذا job كبير شغال.
- Zeek-enabled job يضيف WSL/process overhead.
- schema drift يكسر inference.
- evidence merge guards لازم تفضل strict.
- localhost fallback مفيد development لكنه ممكن يخفي auth bugs.
- frontend حساس جدا لشكل report:
  - summary
  - alerts
  - clusters
  - timeline

---

## 27. Safe Modification Rules

لا تكسر الآتي:

- pipeline order:
  - tshark -> CIC -> ML -> context -> heuristics -> optional Zeek -> fuse_scores -> report
- `EXPECTED_CIC65` alignment
- model trained columns
- `Normal => final_score = 0`
- verdict caps/floors
- strict evidence fallback guards
- ownership checks
- report JSON finite values
- frontend report contract
- PCAP exclusion from Security Score

لو هتغير scoring:

- اختبر no-Zeek وZeek.
- راجع false positives.
- راجع report rendering.
- راجع admin overview.
- راجع chatbot answer.

---

## 28. Tests الموجودة

Backend tests:

- `test_pcap_route_contracts.py`
- `test_pcap_scoring_regression.py`
- `test_pcap_summary_evidence_merge_regression.py`
- `test_pcap_artifact_protection.py`
- `test_pcap_alert_persistence_regression.py`

Recommended verification:

```powershell
python -m py_compile Backend/app.py Backend/pcap_engine/*.py
npm run build
```

Manual tests:

1. Upload small PCAP بدون Zeek.
2. Upload small PCAP مع Zeek.
3. Check `/job/<job_id>` until done.
4. Export report.
5. Export evidence.
6. Open admin console PCAP section.
7. Ask chatbot:
   - How is PCAP score calculated?
   - What happened in my latest PCAP analysis?
   - What should I review next?
8. Confirm Security Score does not include PCAP.

---

## 29. Quick Mental Model

لو حد سألك PCAP عندنا بيعمل إيه:

```text
User uploads PCAP.
Backend saves it as UUID.
JobRegistry creates background job.
tshark extracts packets to CSV.
CIC extractor builds flow features.
ML model predicts traffic labels.
Heuristics and validation check the ML output.
Optional Zeek evidence enriches conn/dns/http/ssl context.
Scorer fuses ML + heuristic + support into verdict/final_score.
Reporter builds summary, alerts, clusters, risk_per_ip, timeline.
User UI renders results and exports artifacts.
Alerts/notifications/activity logs/monthly reports/admin overview consume the same safe report signals.
Chatbot explains the report safely.
PCAP stays separate from personal Security Score.
```

---

## 30. أهم جملة تحفظها

PCAP Analyzer في Sentinel AI هو موديول network-risk مستقل: يحلل ملفات PCAP، ينتج report وalerts وevidence وadmin monitoring وchatbot explanations، لكنه لا يدخل في Security Score الشخصي الذي يعتمد فقط على Password Checker وFile Vault وPhishing Scanner وIdentity Leak بنسبة 25% لكل واحد.
