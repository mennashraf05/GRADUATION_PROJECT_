# PCAP Final Stabilization Acceptance Report

Date: 2026-04-07

## Scope

This pass kept the existing Flask pipeline and report contract intact:

`tshark -> CIC features -> ML inference -> base context -> heuristics -> optional Zeek -> fuse_scores -> comparison -> report`

No routes, report top-level keys, export endpoints, job lifecycle, dedup behavior, or Zeek optional-mode fallbacks were redesigned.

## What Was Broken

- Benign traffic had previously produced high false positives, especially weak HTTP/DNS DoS-style promotions, weak brute-force shapes, and weak internal scan-like chatter.
- Subsequent hardening reduced benign noise, but some real focused flood traffic stopped surfacing unless it also had strong HTTP context.
- Alert reason text could overclaim evidence, especially by implying stronger HTTP support than actually existed.
- Fresh Zeek failures in this Windows/WSL environment could become opaque because the failure detail was often empty.

## Code Changes

### Detection and explainability

File: `Backend/pcap_engine/security_logic.py`

- Preserved the existing benign guards for:
  - trivial HTTP-based false DoS/DDoS
  - trivial DNS-based false DDoS
  - weak FTP brute-force shapes
  - weak local-noise portscan shapes
  - RPC-like internal chatter
  - internal Kerberos/auth chatter
- Added explicit internal-auth DoS/DDoS demotion:
  - `Suppressed: internal auth chatter does not confirm DoS/DDoS`
- Added explicit Heartbleed TLS gating:
  - `Suppressed: Heartbleed label lacks TLS/SSL context`
  - `Suppressed: Heartbleed label needs TLS/SSL evidence`
- Narrowed burst interpretation so ultra-short, low-volume internal chatter does not get inflated into flood evidence by raw packet/byte rates alone.
- Recovered generic `ddos` / `dos` support when there is strong target concentration plus SYN-heavy or failed-connection pressure even without rich HTTP evidence.
- Tightened surfaced reason text so scan alerts describe `port fanout` / `target fanout`, and DoS/DDoS alerts prioritize target concentration, failed ratio, and SYN evidence instead of overclaiming from a single HTTP request.

### Zeek failure diagnostics

File: `Backend/pcap_engine/zeek_runner.py`

- Zeek runner errors now include `returncode`, `stdout`, and `stderr` instead of only an often-empty `stderr`.

### Regression and contract tests

Files:

- `Backend/tests/test_pcap_scoring_regression.py`
- `Backend/tests/test_pcap_route_contracts.py`

Added/updated regressions for:

- benign DNS/HTTP/FTP/scan/internal-auth false positives
- recovered DDoS, portscan, SSH brute-force, FTP brute-force, and TLS/Heartbleed representative cases
- explanation text correctness for scan and DDoS cases
- final score / confidence / verdict alignment
- route-level dedup behavior
- report export contract
- evidence export contract against a completed Zeek-backed job

## Labels Recovered or Explicitly Protected

- Recovered in scoring logic:
  - `ddos`
  - generic `dos` flood-like cases with strong concentration + SYN/failure evidence
- Explicitly protected by regression coverage:
  - `dos_hulk`
  - `portscan`
  - `ftp_patator`
  - `ssh_patator`
  - `heartbleed`

## Benign Guards Preserved

- trivial HTTP DoS/DDoS suppression
- trivial DNS-flood suppression
- weak FTP brute-force suppression
- weak local-noise portscan suppression
- RPC-like internal scan suppression
- internal Kerberos/auth chatter suppression
- internal RFC1918 low-support suppression

## End-to-End Verification

## Live current-code runs

### 1. Benign PCAP without Zeek

PCAP: `ids2017_benign_monday_00003_20170703141409.pcap`

- `total_flows`: 287
- `alerts_count`: 0
- `suspicious`: 0
- `overall_risk`: 0.0
- `risk_level`: `Normal`
- surfaced labels: none
- verdict distribution: `Normal=287`
- support distribution: `strong=284`, `none=3`
- suppressed count: 10
- top suppression reasons:
  - `Invalid context: SSH brute-force should target port 22` x2
  - `Noise: broadcast/DHCP-like traffic` x1
  - `Suppressed: ThingSpeak label but dst_port is not 80/443` x1
- top surfaced reasons: none
- JSON safety: `json.dumps(..., allow_nan=False)` passed

### 2. Benign PCAP with Zeek requested

PCAP: `ids2017_benign_monday_00003_20170703141409.pcap`

- surfaced outcome stayed clean:
  - `alerts_count=0`
  - `risk_level=Normal`
  - no surfaced labels
- report meta:
  - `zeek_requested=true`
  - `zeek_enrichment_succeeded=false`
  - `zeek_evidence_available=false`
  - `analysis_mode=base_only`
- verdict/support/suppression counts matched the clean benign baseline above
- JSON safety: passed

Reason: this session could request Zeek, but fresh Zeek execution was blocked by the host WSL environment.

### 3. Real attack PCAP without Zeek

PCAP: `Backend/pcap_runs/54c03680-a670-49ac-a215-fee9e2bce665.pcap`

- `total_flows`: 226893
- `alerts_count`: 1
- `suspicious`: 1
- `overall_risk`: `0.16`
- `risk_level`: `Low`
- surfaced labels:
  - `ddos` x1
- surfaced reason:
  - `DDoS suspected: target connections=4380, failed-connection ratio 1.00, SYN count=23, ml_confidence=0.83`
- verdict distribution:
  - `Normal=226892`
  - `Medium=1`
- support distribution:
  - `strong=214894`
  - `none=11847`
  - `weak=120`
  - `moderate=32`
- suppressed count: 21948
- top suppression reasons:
  - `Suppressed: trivial HTTP evidence does not confirm web DoS/DDoS` x4556
  - `Suppressed: scan label lacks short-connection scan pattern` x1631
  - `Suppressed: HTTP DoS label lacks reliable HTTP context` x549
  - `Suppressed: scan label without enough port fanout` x258
  - `Noise: broadcast/DHCP-like traffic` x249
  - `Suppressed: internal auth chatter does not confirm DoS/DDoS` x37
- JSON safety: passed

Interpretation: the real flood-like alert surfaced, while the previous internal Kerberos false positives were removed.

## Historical real Zeek-backed run available in repo

Completed job: `Backend/pcap_runs/_jobs/82a677cc-18b9-47bf-9906-ddead302eed7/state.json`

- `status=done`
- `zeek_enrichment_succeeded=true`
- `zeek_evidence_available=true`
- Zeek evidence bundle contains 23 log files including `conn.log`, `dns.log`, `http.log`, `ssl.log`, `kerberos.log`, `ssh.log`, and others.
- Historical report summary for that full Zeek-backed run:
  - `total_flows=226893`
  - `alerts_count=3`
  - `risk_level=High`
  - `changed_by_evidence_up=1`

This historical report predates the final scoring fix and still includes the internal-auth false positives that were removed in the current pass.

## Current-code Zeek validation status

- Earlier in this session, current-code replay against the saved real Zeek artifacts for the same attack capture reduced the surfaced result to the single real web-focused `ddos` alert and removed the false internal Kerberos alerts.
- An additional full enriched replay during report assembly exceeded the local command timeout on the 226k-flow capture, so I am not claiming a second complete enriched metric dump beyond the surfaced-outcome check above.
- Public Zeek-mode contracts were still verified:
  - report export works for a completed Zeek-backed job
  - evidence export works for a completed Zeek-backed job
  - the exported JSON remained finite / parse-safe

## Route / Contract Verification

Automated route tests confirmed:

- repeated `/pcap/analyze-local` requests reuse the same active job id instead of breaking dedup
- `/job/<job_id>` still returns inline report content
- `/job/<job_id>/export?type=report` still returns report JSON
- `/pcap/report/<job_id>` still returns report JSON
- `/job/<job_id>/export?type=evidence` still returns a ZIP with:
  - `report.json`
  - `state.json`
  - `zeek/*.log`
- required top-level report keys remain present:
  - `meta`
  - `summary`
  - `clusters`
  - `alerts`
  - `timeline`

## Test Results

Command:

`python -m unittest Backend.tests.test_pcap_scoring_regression Backend.tests.test_pcap_route_contracts -v`

Result:

- 19 tests
- 19 passed

## Remaining Limitations

- Only two real PCAPs are present in this workspace:
  - one benign capture
  - one real DDoS-style attack capture
- No real portscan PCAP and no real brute-force/TLS attack PCAP were available locally for additional live replay.
- Fresh Zeek execution from this session is currently blocked by the host WSL environment. Direct shell probing returned `Wsl/Service/CreateInstance/E_ACCESSDENIED`, and a benign Zeek-requested run fell back to `analysis_mode=base_only`.

## Final Conclusion

- System stability: acceptable for the current code path and report/export/job contracts.
- Benign behavior: acceptable on the available benign capture; surfaced alerts stayed at zero.
- Attack detection: acceptable on the available real attack capture; the real focused `ddos` alert surfaces and the prior internal-auth false positives are suppressed.
- Demo readiness:
  - yes for base-mode demos and report/export flows
  - yes for Zeek artifact review/export using the completed saved Zeek job
  - not fully signed off for a fresh live Zeek demo on this specific machine until WSL/Zeek execution permissions are restored
