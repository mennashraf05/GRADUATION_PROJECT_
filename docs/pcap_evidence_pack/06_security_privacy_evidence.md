# Security and Privacy Evidence

## Access Control

Confirmed:
- PCAP user routes resolve an authenticated PCAP request context before processing.
- Job status/export/cancel/history filters use `_pcap_job_matches_context`.
- Authenticated users must match both `owner_user_id` and immutable `owner_user_scope`.
- Admin PCAP routes require `@admin_auth_required`.

Evidence:
- `Backend/app.py` `_resolve_authenticated_pcap_request_context`.
- `Backend/app.py` `_get_authorized_job_for_context`.
- `Backend/app.py` `_pcap_job_matches_context`.
- `Backend/app.py` `admin_pcap_overview`, `admin_export_pcap_job_artifact`.

## Ownership Checks

Confirmed:
- `list_jobs` only returns jobs where `_pcap_job_matches_context(st, ctx)[0]`.
- `get_job`, `cancel_pcap_job`, and user export call `_get_authorized_job_for_context`.
- Alert dismissal queries filter by `PcapAlertRecord.user_id` and scope metadata.

Evidence:
- `Backend/app.py` `list_jobs`, `get_job`, `cancel_pcap_job`, `export_job_artifact`, dismissal helpers.

## Safe File Handling

Confirmed:
- Upload filenames are not reused; backend saves UUID file names.
- Upload extension limited to `.pcap` and `.pcapng`.
- Max upload size is 15 GB through Flask `MAX_CONTENT_LENGTH` and explicit checks.
- Local-path analysis is restricted to `LOCAL_PCAP_ALLOWED_ROOT`.
- Partial upload is removed on save failure.
- Export type is allowlisted to `report`, `evidence`, or `bundle`.

Evidence:
- `Backend/app.py` `analyze_pcap`, `_resolve_analyze_local_path`, `export_job_artifact`.

Limitations:
- File magic/header validation is not confirmed.
- The system relies on external tools to parse captures safely.

## Sensitive Evidence Handling

Confirmed:
- Optional artifact protection can encrypt raw PCAP and packet CSV after terminal state using AES-GCM when `PCAP_PROTECT_ARTIFACTS` and `PCAP_ARTIFACT_ENCRYPTION_KEY` are configured.
- `report.json` and `state.json` stay plaintext so UI can read them.
- Zeek logs can be skipped from encryption as `required_by_ui`.

Evidence:
- `Backend/app.py` `_protect_pcap_artifacts_after_terminal_state`, `_encrypt_file_copy_verify_delete`.

Limitations:
- Encryption is disabled by default unless env config enables it.
- Do not claim all raw artifacts are encrypted in every deployment.

## Raw Payload Exposure

Confirmed:
- `tshark_runner.py` exports selected packet fields: timestamps, IPs, ports, protocol, frame length, TCP flags, ARP fields, MAC fields.
- Zeek loader reads metadata logs: conn, DNS query/answer info, HTTP method/host/URI/status/user agent, SSL server name/JA3/version/cipher.
- Report alerts include IPs, ports, DNS top query, HTTP host/URI, TLS SNI/cipher, byte counts, and reasons.

Cannot confirm:
- Full packet payload extraction or storage in report.
- Payload redaction beyond not exporting payload fields.

## Error Handling

Confirmed:
- Missing file returns `400`.
- Invalid extension returns `400`.
- Oversize file returns `413`.
- Unauthorized/forbidden job access returns `403`.
- Missing job returns `404`.
- Not-completed export returns `409`.
- Invalid export type returns `400`.
- `tshark` errors raise friendly messages and remove partial CSV.
- Empty flow extraction raises `No flows extracted`.
- Zeek load failure logs exception and continues without Zeek evidence.

Evidence:
- `Backend/app.py`, `Backend/pcap_engine/tshark_runner.py`.

## Activity / Audit Logs

Confirmed:
- PCAP upload/start/reanalysis/cancel/report download/evidence download/dismissal events are logged through user activity helpers.
- Admin export logs admin actions.

Evidence:
- `Backend/app.py` `_log_pcap_analysis_activity`, `log_user_event`, `log_admin_action` calls.

## Privacy Risks / Limitations

- Reports may contain IP addresses, DNS queries, HTTP hosts/URIs, TLS SNI, user-agent values, and local/server file paths.
- Evidence ZIP can include Zeek logs and state/report metadata.
- Uploaded PCAPs may persist until cleanup or artifact protection.
- Do not include real `pcap_path` examples with private paths in book screenshots unless sanitized.
