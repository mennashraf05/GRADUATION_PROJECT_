# PCAP Artifact Protection Plan

## 1. Current PCAP Artifact Lifecycle

This document describes the current PCAP artifact lifecycle and a safe future protection design. It is intentionally conservative: the current PCAP analysis behavior must remain unchanged when `PCAP_PROTECT_ARTIFACTS=false`.

Current storage locations:

- Raw uploaded `.pcap` / `.pcapng` files are saved under `Backend/pcap_runs` using a generated filename during upload.
- Background job state is persisted under `Backend/pcap_runs/_jobs/<job_id>/state.json`.
- `tshark` packet-level CSV exports are written under `Backend/pcap_runs` as `<uuid>_packets.csv`, and the path is stored in `state.json` as `packet_csv_path`.
- Large native-Windows `tshark` exports may temporarily split captures with `editcap` inside a temporary directory under the CSV parent. The temporary directory is removed by Python's `TemporaryDirectory` after export.
- Zeek logs are written under a generated run folder in `Backend/pcap_runs/<uuid>/`. The job state stores this folder as `evidence_dir`.
- The primary Zeek files currently collected for evidence export are `conn.log`, `dns.log`, `http.log`, and `ssl.log`.
- `report.json` is written only after the pipeline returns a completed report, under `Backend/pcap_runs/_jobs/<job_id>/report.json`.
- Evidence ZIPs are generated on demand as `Backend/pcap_runs/_jobs/<job_id>/evidence_bundle.zip`. They include `report.json`, `state.json`, and selected Zeek logs when available.
- Alerts, timeline, clusters, and summary data are embedded in `report.json` and/or persisted to the `pcap_alert` database table for the Recent Security Alerts feed.
- Completed job folders remain readable through `state.json` and `report.json` until current retention cleanup removes stale artifacts.
- Failed or cancelled jobs keep `state.json`; partial artifacts such as uploaded PCAPs, packet CSVs, or Zeek output may exist depending on where the job stopped.

Existing cleanup behavior is separate from artifact protection. The current cleanup scheduler deletes stale terminal artifacts according to the existing `ARTIFACT_RETENTION_HOURS` and `JOB_RETENTION_HOURS` settings. This plan does not change that behavior.

## 2. Sensitive Artifacts

Sensitive artifacts that may be protected later only when explicitly enabled:

- Raw `.pcap` files.
- Raw `.pcapng` files.
- Packet-level CSV exports produced by `tshark`.
- Temporary chunk PCAP/PCAPNG files created during large capture handling.
- Raw `tshark` outputs and partial CSV outputs.
- Raw Zeek logs, especially `conn.log`, `dns.log`, `http.log`, `ssl.log`, and any other detailed protocol logs.
- Evidence ZIPs if they contain raw or packet-level artifacts.
- Failed or cancelled job partial artifacts that include packet-level data.

## 3. Artifacts That Must Remain Readable

These files and data structures must remain readable by default and must not be encrypted by the disabled protection layer:

- `report.json`.
- `state.json`.
- Safe report summaries.
- Alerts metadata.
- Timeline metadata.
- Cluster summaries.
- Fields used by the UI report/workspace.
- Fields used by the PCAP history list.
- Fields used by Recent Security Alerts and PCAP alert backfill.
- Fields used by chatbot PCAP context.
- Fields used by Reports Center and monthly/security summaries.
- Database rows such as `pcap_alert` that point to user-facing alert metadata.

## 4. Why Raw PCAP Files Are Sensitive

Raw PCAP artifacts can contain full packet payloads, internal IPs, DNS lookups, hostnames, URLs, cookies, session identifiers, credentials, tokens, private file transfers, email content, and other sensitive traffic. Even when payloads are encrypted, metadata such as timing, endpoints, SNI, DNS, ports, and traffic volume can disclose operational details. Packet-level CSVs and raw Zeek logs can also expose detailed network evidence and should be treated as sensitive.

## 5. Safe Future Protection Design

The safest future design is a post-analysis protection phase that runs only after a job reaches a terminal state:

- `done`
- `failed` / `error`
- `cancelled`

The protection phase must never run:

- Before `tshark`.
- Before Zeek.
- During feature extraction.
- During ML inference.
- During heuristics.
- During scoring.
- Before `report.json` is safely written for successful jobs.
- While UI/report/chatbot/alert readers still require a file.

Recommended future behavior when explicitly enabled:

- Keep `report.json` and `state.json` readable.
- Encrypt only sensitive raw artifacts after terminal state.
- Store protection metadata separately or in `state.json` without breaking existing readers.
- Keep original filenames discoverable through metadata, but do not expose secrets.
- Use authenticated encryption with a configured key, not a hard-coded key.
- Make decryption an explicit admin/user action with authorization checks.
- Add tests that prove UI, alerts, chatbot, reports, history, and exports still work.

## 6. What Must Never Be Encrypted By Default

Never encrypt these by default:

- `report.json`
- `state.json`
- UI report/workspace fields
- Chatbot context fields
- Recent Security Alerts feed data
- Reports Center summaries
- PCAP history metadata
- Safe summaries, timeline metadata, cluster summaries, and alert metadata

The goal is to protect raw evidence later, not to hide the product data needed by user-facing features.

## 7. Testing That Analysis Is Unaffected

With `PCAP_PROTECT_ARTIFACTS=false`, verify:

1. Run a PCAP analysis.
2. Confirm `report.json` is generated under `_jobs/<job_id>/report.json`.
3. Confirm `_jobs/<job_id>/state.json` is readable.
4. Confirm the UI report/workspace loads.
5. Confirm Recent Security Alerts receives the PCAP result.
6. Confirm chatbot PCAP context can read the saved report.
7. Confirm Reports Center still sees PCAP summaries.
8. Confirm raw `.pcap` / `.pcapng` files are not encrypted.
9. Confirm packet CSV files are not encrypted.
10. Confirm no files are deleted, moved, or renamed by artifact protection.
11. Confirm refresh/backfill behavior does not change.

## 8. Future Optional Encryption Mode

Reserved environment variables:

```env
PCAP_PROTECT_ARTIFACTS=false
PCAP_ARTIFACT_ENCRYPTION_KEY=
PCAP_ARTIFACT_RETENTION_DAYS=7
```

Current behavior:

- `PCAP_PROTECT_ARTIFACTS` defaults to `false`.
- No encryption is implemented for enabled mode.
- The disabled helper returns metadata only and performs no file I/O.
- The future enabled mode is intentionally documented rather than implemented until the exact product and recovery requirements are clear.

If encryption is implemented later, it should be isolated in a dedicated module and should have integration tests for successful, failed, and cancelled jobs.

## 9. Cancelled And Failed Jobs

Cancelled and failed jobs may leave partial sensitive artifacts:

- Uploaded raw PCAP files.
- Partial packet CSV output.
- Partial Zeek run folders/logs.
- Temporary split artifacts if a process stops unexpectedly.

Future protection can protect or clean partial raw artifacts only after the job status becomes `cancelled`, `failed`, or `error`. No cleanup, deletion, encryption, movement, or renaming should happen by default in this protection layer.

## 10. Limitations

- This plan does not implement encryption.
- This plan does not change the existing cleanup scheduler.
- This plan does not change PCAP analysis, Zeek, `tshark`, feature extraction, ML inference, heuristics, scoring, reports, alerts, chatbot, or Reports Center.
- The current evidence bundle may contain detailed Zeek evidence and should be treated as sensitive.
- Raw artifacts already on disk remain as they are unless current retention cleanup removes them according to existing settings.
