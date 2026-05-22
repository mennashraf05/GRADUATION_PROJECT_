# PCAP, Scoring, and Gamification Master Report

Date: 2026-04-16

## Purpose

This file is the single project-level reference for:

- the full PCAP subsystem
- final scoring and risk evaluation
- report generation and export behavior
- frontend score consumption
- gamification backend and frontend integration
- relevant tests and source files

This report is intentionally written as a master index plus implementation reference.
For the deepest line-by-line PCAP internals, the canonical deep references already in the repo remain:

- `docs/PCAP_DEEP_REFERENCE.md`
- `docs/PCAP_QUICK_REVIEW.md`
- `docs/pcap_final_acceptance_report.md`

## High-Level System Map

The project has three tightly connected layers:

1. Backend PCAP analysis pipeline in `Backend/app.py` and `Backend/pcap_engine/*`
2. Frontend PCAP visualization and score presentation in `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx` and `src/utils/*`
3. Gamification and user progression in `Backend/gamification/*` and `Cybersecurity Dashboard Design/src/utils/gamification.ts`

## PCAP Backend Architecture

Core backend entrypoint:

- `Backend/app.py`

Core PCAP engine modules:

- `Backend/pcap_engine/tshark_runner.py`
- `Backend/pcap_engine/cic_stream_features.py`
- `Backend/pcap_engine/ml_infer.py`
- `Backend/pcap_engine/flow_features.py`
- `Backend/pcap_engine/heuristics.py`
- `Backend/pcap_engine/security_logic.py`
- `Backend/pcap_engine/scorer.py`
- `Backend/pcap_engine/zeek_runner.py`
- `Backend/pcap_engine/zeek_loader.py`
- `Backend/pcap_engine/reporter.py`
- `Backend/pcap_engine/jobs.py`
- `Backend/pcap_engine/cleanup.py`

The effective pipeline preserved by the project is:

`tshark -> CIC features -> ML inference -> base context -> heuristics -> optional Zeek -> fuse_scores -> comparison -> report`

## Main PCAP Routes

Declared in `Backend/app.py`:

- `POST /pcap/analyze`
- `POST /analyze-pcap`
- `POST /pcap/analyze-local`
- `POST /analyze-local`
- `GET /job/<job_id>`
- `GET /jobs`
- `GET /pcap/jobs`
- `GET /pcap/result/<job_id>`
- `GET /pcap/status/<job_id>`
- `GET /pcap/report/<job_id>`
- `GET /job/<job_id>/export?type=report`
- `GET /job/<job_id>/export?type=evidence`
- `GET /api/pcap/alerts`
- `GET /pcap/alerts`

## PCAP Job Lifecycle

Job registry:

- `Backend/pcap_engine/jobs.py`

Runtime folders:

- base runs folder: `Backend/pcap_runs`
- jobs folder: `Backend/pcap_runs/_jobs`

Stored artifacts per job can include:

- `state.json`
- `report.json`
- Zeek logs folder
- generated `evidence_bundle.zip`

The system supports:

- queued and background analysis
- dedup for repeated analyze-local requests
- report export
- evidence export
- cleanup/retention scheduling

Retention and scheduler wiring live in:

- `Backend/pcap_engine/cleanup.py`
- scheduler startup in `Backend/app.py`

## PCAP Processing Stages

### Stage 1: Capture ingestion

Input comes from either uploaded PCAP or local path.

Relevant code:

- `Backend/app.py`
- `_resolve_analyze_local_path`

Valid file types:

- `.pcap`
- `.pcapng`

### Stage 2: Packet export with tshark

Module:

- `Backend/pcap_engine/tshark_runner.py`

Responsibility:

- flatten packet-level data into CSV suitable for later flow aggregation

### Stage 3: CIC-style flow feature generation

Module:

- `Backend/pcap_engine/cic_stream_features.py`

Responsibility:

- convert packet CSV into CIC-style flow rows
- align output to expected model schema

### Stage 4: ML inference

Modules:

- `Backend/pcap_engine/ml_infer.py`
- model files under `Backend/model/`

Key assets present in the repo:

- `Backend/model/threat_model_pcap65.pkl`
- `Backend/model/threat_model.pkl`
- `Backend/model/label_encoder.pkl`
- `Backend/model/metrics_pcap65.json`
- `Backend/model/metrics.json`

### Stage 5: Context and flow features

Modules:

- `Backend/pcap_engine/flow_features.py`
- `Backend/pcap_engine/heuristics.py`

Responsibilities:

- build contextual connection features
- add heuristic indicators
- generate evidence-supporting metrics such as ratios, port fanout, failed-connection signals, and service context

### Stage 6: Canonical decision logic

Canonical source:

- `Backend/pcap_engine/security_logic.py`

This file is the project’s scoring vocabulary and decision-policy source.
It defines:

- label-to-severity mapping
- severity base scores
- suspicious/confirm thresholds
- confidence mode presets
- rare labels
- scan labels
- brute-force labels
- DoS family labels
- web attack labels
- non-alert suspicious labels
- suppression and validation logic
- context support logic
- verdict caps and floors
- reason-building helpers

Important constants visible in the code:

- `SEVERITY_BASE_SCORES`
- `CONFIDENCE_SUSPICIOUS`
- `CONFIDENCE_CONFIRM`
- `RARE_CONFIRM`
- `CONFIDENCE_MODE_PRESETS`
- `HTTP_PORTS`
- `TLS_PORTS`
- `FAILED_STATES`
- `DOS_FAMILY_LABELS`
- `SCAN_LABELS`
- `BRUTE_FORCE_LABELS`
- `WEBATTACK_LABELS`
- `VERDICT_RANK`

## Label Severity Mapping

Implemented in `Backend/pcap_engine/security_logic.py`.

Examples:

- `benign`, `mqtt_publish`, `thing_speak`, `wipro_bulb` -> `Low`
- `portscan`, `nmap_*` -> `Medium`
- `dos_*`, `ftp_patator`, `ssh_patator`, `webattack_*`, `arp_poisoning` -> `High`
- `ddos`, `dos_syn_hping`, `bot`, `heartbleed` -> `Critical`

## Final Scoring Logic

Implemented in:

- `Backend/pcap_engine/scorer.py`
- dependent logic from `Backend/pcap_engine/security_logic.py`

Main function:

- `fuse_scores(df, confidence_mode=None)`

Documented effective order:

1. ensure required columns
2. normalize ML and heuristic columns
3. compute suppression via `should_suppress`
4. compute severity via `label_to_severity`
5. compute raw ML score via `severity_to_score`
6. compute confidence tier
7. compute validation failure reason
8. compute context support level
9. compute support multiplier
10. derive signal verdict
11. force suppression on validation failure or ignore-tier rows
12. derive final verdict from context
13. optionally suppress generic HTTP DoS if subtype-specific alert already explains the window
14. calculate raw score blend
15. apply support scaling
16. apply verdict cap
17. apply verdict floor for non-Normal verdicts
18. force `Normal -> final_score = 0.0`
19. build human-readable reason text
20. copy `final_score` into `confidence`

The current score blend in code is:

`raw_score = 0.95 * ml_score + 0.05 * heuristic_score`

Then:

- multiply by `support_multiplier`
- cap using `verdict_score_cap`
- floor using `verdict_score_floor` with support-based floor factor
- zero out all `Normal` verdicts

Key guarantees explicitly preserved:

- `security_logic.py` remains the canonical scoring source
- `Normal` always ends with `final_score = 0.0`
- `confidence` becomes the post-validation final score

## Risk Levels and Report Severity

At the flow and report level, the project uses:

- `Normal`
- `Low`
- `Medium`
- `High`
- `Critical`

Frontend-facing score labels also exist:

- `Secure`
- `Warning`
- `Risky`
- `Critical`

## Evidence Enrichment

Optional Zeek-related modules:

- `Backend/pcap_engine/zeek_runner.py`
- `Backend/pcap_engine/zeek_loader.py`

Evidence summarization in `Backend/app.py` includes:

- DNS evidence summarization
- HTTP evidence summarization
- SSL evidence summarization
- ARP evidence summarization
- connection evidence merge
- summary evidence merge
- evidence default filling

Important behavior:

- Zeek enrichment is additive
- Zeek does not bypass the scorer
- scoring is rerun after evidence merge
- comparison fields track rows changed by evidence

Important meta fields seen in reports:

- `zeek_requested`
- `zeek_enrichment_succeeded`
- `zeek_evidence_available`
- `analysis_mode`
- `comparison.changed_by_evidence_up`
- `comparison.changed_by_evidence_down`

## Report Generation Contract

Implemented in:

- `Backend/pcap_engine/reporter.py`

Top-level report keys explicitly preserved:

- `meta`
- `summary`
- `clusters`
- `alerts`
- `timeline`

Optional extra payloads used by the frontend:

- `risk_per_ip`
- `evidence`
- `assets`

### Summary payload

Important fields in `summary`:

- `total_flows`
- `alerts_count`
- `suspicious`
- `malicious`
- `overall_risk`
- `risk_level`
- `risk_context_label`
- `risk_display`
- `security_score`
- `score_explanation`
- `security_score_level`
- `security_summary`
- `summary`
- `security_trend`
- `cluster_count`
- `severity_counts`
- `top_risk`

### Reporter score model

`Backend/pcap_engine/reporter.py` also defines frontend-consumable security scoring helpers:

- severity weights:
  - `Low = 5`
  - `Medium = 12`
  - `High = 25`
  - `Critical = 45`
- overall risk to score transformation
- score-to-level mapping:
  - `>= 90 -> Secure`
  - `>= 70 -> Warning`
  - `>= 40 -> Risky`
  - otherwise `Critical`

It also constructs a `pcap_analyzer` module contract for downstream consumers.

## Frontend PCAP Consumer

Primary screen:

- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`

This page handles:

- upload flow
- polling job status
- report retrieval
- report export
- evidence export
- charts
- risk breakdown tables
- recent alert persistence
- gamification events from analyst actions

Connected frontend security components:

- `src/components/security/SecurityScoreCard.tsx`
- `src/components/security/SeverityBreakdownCard.tsx`
- `src/components/security/ThreatBreakdownCard.tsx`
- `src/components/security/ThreatActivityAreaChart.tsx`
- `src/components/security/RiskPerIpCard.tsx`
- `src/components/security/RecentSecurityAlertsPanel.tsx`

Frontend utilities:

- `src/utils/securityScore.ts`
- `src/utils/networkSecurityScore.ts`
- `src/utils/pcapChartSelectors.ts`
- `src/utils/recentPcapAlerts.ts`

## Frontend Security Score Utilities

### `src/utils/securityScore.ts`

This file normalizes threat inputs and converts them into:

- numeric score
- level
- trend
- top threat
- summary text
- explanation structure
- metrics object

It defines:

- severity weights
- risk level order
- score bands
- overall risk normalization
- count softening via log factor
- threat impact and signal-risk derivation

### `src/utils/networkSecurityScore.ts`

This file computes cross-analysis / historical network score summaries from recent successful PCAP jobs.

Responsibilities:

- fetch recent job history
- filter successful completed PCAP jobs
- read latest report snapshots
- compute multi-analysis score trend
- expose:
  - `finalScore`
  - `rating`
  - `filesUsed`
  - `latestCompletedAt`
  - `trendDelta`
  - per-analysis breakdown

## Gamification Backend Architecture

Modules:

- `Backend/gamification/definitions.py`
- `Backend/gamification/helpers.py`
- `Backend/gamification/models.py`
- `Backend/gamification/service.py`
- `Backend/gamification/routes.py`
- `Backend/gamification/__init__.py`

The backend service is registered in `Backend/app.py` as:

- `gamification_service = GamificationService()`
- stored in `app.extensions["gamification_service"]`

Blueprint:

- `gamification_bp`

## Gamification API Routes

Declared in `Backend/gamification/routes.py`:

- `GET /api/gamification/profile`
- `GET /api/gamification/badges`
- `GET /api/gamification/challenges`
- `GET /api/gamification/history`
- `GET /api/gamification/overview`
- `GET /api/gamification/alert-context`
- `POST /api/gamification/events`

## Gamification Data Model

Defined in `Backend/gamification/models.py`.

Tables:

- `gamification_event`
- `user_gamification_profile`
- `user_badge`
- `user_challenge`
- `gamification_daily_stat`
- `user_alert_review_state`
- `investigation_note`

### Key stored concepts

- event ledger with `event_key` uniqueness
- accumulated points
- level and level name
- streaks
- total scans
- total reviewed alerts
- unlocked badges
- challenge progress
- alert review state
- investigation notes

## Gamification Event Types

Defined in `Backend/gamification/definitions.py`.

Important groups:

- upload / analysis:
  - `pcap_uploaded`
  - `analysis_completed`
  - `analysis_failed`
- report / evidence access:
  - `report_accessed`
  - `report_opened`
  - `report_downloaded`
  - `evidence_accessed`
  - `evidence_opened`
  - `evidence_downloaded`
- analyst actions:
  - `alert_viewed`
  - `alert_reviewed`
  - `investigation_note_added`
  - `alert_marked_true_positive`
  - `alert_marked_false_positive`
- score and progression:
  - `security_score_improved`
  - `critical_alerts_reduced`
  - `safe_scan_completed`
  - `clean_scan_completed`
  - `daily_streak_extended`
  - `weekly_goal_completed`
  - `challenge_completed`
  - `level_up`
  - `first_scan_completed`

Important aliasing:

- `report_opened` and `report_downloaded` canonicalize into report-access behavior
- `evidence_opened` and `evidence_downloaded` canonicalize into evidence-access behavior

## Gamification Point Values

Visible in `Backend/gamification/definitions.py`.

Examples:

- `pcap_uploaded = 5`
- `analysis_completed = 5`
- `report_accessed = 2`
- `alert_viewed = 1`
- `evidence_accessed = 2`
- `alert_reviewed = 3`
- `investigation_note_added = 4`
- `safe_scan_completed = 12`
- `clean_scan_completed = 20`
- `daily_streak_extended = 3`
- `weekly_goal_completed = 15`

Some progression events intentionally award zero direct points:

- `analysis_failed`
- `level_up`
- `first_scan_completed`

## Levels

Defined in `Backend/gamification/definitions.py`.

Levels:

- Level 1: `Beginner Analyst` (`0-49`)
- Level 2: `Threat Observer` (`50-149`)
- Level 3: `Security Reviewer` (`150-299`)
- Level 4: `Threat Hunter` (`300-499`)
- Level 5: `Security Champion` (`500-799`)
- Level 6: `Defense Strategist` (`800-1199`)
- Level 7: `Elite Guardian` (`1200+`)

Computed by:

- `compute_level_details(total_points)`

## Badges

Defined in `BADGE_DEFINITIONS` inside `Backend/gamification/definitions.py`.

Badge examples:

- `first_scan`
- `report_explorer`
- `evidence_explorer`
- `alert_reviewer`
- `investigator`
- `risk_reducer`
- `critical_cleaner`
- `safe_streak`
- `daily_defender`
- `weekly_analyst`
- `security_champion`
- `elite_guardian`

Rarity values used:

- `common`
- `rare`
- `epic`
- `legendary`

## Challenges

Defined in:

- `DAILY_CHALLENGE_DEFINITIONS`
- `WEEKLY_CHALLENGE_DEFINITIONS`

Daily examples:

- access one report
- review three alerts
- access evidence twice

Weekly examples:

- complete three analyses
- improve security score once
- review ten alerts

## Gamification Derived Rewards

Implemented in `Backend/gamification/service.py`.

### Security score improvement reward

`score_improvement_points(previous_score, current_score)`:

- `+15` if delta `>= 10`
- `+10` if delta `>= 5`
- `+5` if delta `>= 1`
- otherwise `0`

### Critical alert reduction reward

`critical_reduction_points(previous_count, current_count)`:

- `+20` if critical count becomes zero
- `+15` if reduction ratio `>= 50%`
- `+8` if reduction ratio `>= 25%`
- otherwise `0`

## Gamification Dedup and Activity Protection

The service explicitly avoids double-awarding for:

- duplicate uploads by file hash
- repeated review of same alert
- repeated report access for same job
- report download + report open double counting
- evidence download + evidence open double counting

This is built on:

- unique `event_key`
- logical access keys per job / alert / evidence resource
- canonical event aliases

## Frontend Gamification Integration

Frontend files:

- `Cybersecurity Dashboard Design/src/utils/gamification.ts`
- `Cybersecurity Dashboard Design/src/hooks/useGamification.ts`

Frontend responsibilities:

- fetch overview/profile/badges/challenges/history
- fetch alert context
- post UI event records
- broadcast update events via:
  - `sentinel-gamification-updated`
  - `sentinel_gamification_updated_at`
- show toasts for:
  - points gain
  - badge unlock
  - level up

Hook:

- `useGamification()`

This hook:

- loads overview
- refreshes on custom update event
- refreshes on storage event for multi-tab coherence

## Where PCAP and Gamification Meet

In `Backend/app.py`, gamification is tied to PCAP lifecycle at these moments:

- upload record on new PCAP submission
- download record on report export
- download record on evidence export
- completion record when analysis finishes
- failure record when analysis fails

In the frontend `PcapAnalyzerPage.tsx`, user behavior can trigger gamification events for:

- viewing reports
- viewing alerts
- viewing evidence
- reviewing alerts
- adding notes
- marking true positive / false positive

## Existing Canonical Project Docs

The repo already contains three important PCAP references:

- `docs/PCAP_DEEP_REFERENCE.md`
  - exhaustive architecture and contract reference
- `docs/PCAP_QUICK_REVIEW.md`
  - compact engineer summary
- `docs/pcap_final_acceptance_report.md`
  - stabilization and regression outcome notes

This master report should be read together with those files, not instead of them.

## Tests Covering This Area

Relevant backend tests:

- `Backend/tests/test_pcap_scoring_regression.py`
- `Backend/tests/test_pcap_route_contracts.py`
- `Backend/tests/test_pcap_alert_persistence_regression.py`
- `Backend/tests/test_pcap_summary_evidence_merge_regression.py`
- `Backend/tests/test_gamification_service.py`

### What the tests validate

PCAP scoring tests validate:

- benign false-positive demotion
- HTTP/DNS DoS suppression
- internal auth chatter demotion
- strong attack resurfacing
- verdict and final score alignment

Route contract tests validate:

- analyze-local dedup
- report availability
- report export contract
- evidence export contract
- top-level report shape

Gamification tests validate:

- dedup of repeated events
- report/evidence access dedup
- level computation
- score-improvement and critical-reduction reward helpers
- streak behavior
- badge unlock uniqueness

## Files You Should Treat as Most Sensitive

If these change, behavior can shift materially:

- `Backend/pcap_engine/security_logic.py`
- `Backend/pcap_engine/scorer.py`
- `Backend/pcap_engine/reporter.py`
- `Backend/app.py`
- `Backend/gamification/service.py`
- `Backend/gamification/definitions.py`
- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`
- `Cybersecurity Dashboard Design/src/utils/securityScore.ts`
- `Cybersecurity Dashboard Design/src/utils/networkSecurityScore.ts`
- `Cybersecurity Dashboard Design/src/utils/gamification.ts`

## Practical Summary

If you want the shortest truthful description of this subsystem:

- PCAP analysis is a background job pipeline that converts packet captures into flow features, applies ML plus context-aware validation, optionally merges Zeek evidence, rescoring the results before generating a frontend-facing report.
- Final surfaced confidence is the validated `final_score`, not raw ML confidence.
- `Normal` verdicts are forced to zero risk score.
- Frontend score cards use both backend-provided report fields and client-side score utilities.
- Gamification is not decorative; it is integrated into upload, completion, report/evidence access, alert review, note taking, score improvement, challenge progress, badge unlocks, streaks, and level progression.

## Recommended Reading Order

For someone onboarding into this part of the project:

1. `docs/PCAP_QUICK_REVIEW.md`
2. this file
3. `docs/PCAP_DEEP_REFERENCE.md`
4. `Backend/pcap_engine/security_logic.py`
5. `Backend/pcap_engine/scorer.py`
6. `Backend/pcap_engine/reporter.py`
7. `Backend/gamification/definitions.py`
8. `Backend/gamification/service.py`
9. `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`

