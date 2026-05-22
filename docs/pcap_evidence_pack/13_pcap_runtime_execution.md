# PCAP Runtime and Execution Evidence

## Backend Startup

Confirmed:
- Main Flask app is `Backend/app.py`.
- `Backend/run_server_no_reload.py` exists as a server helper.
- Cleanup scheduler is started before serving when supported and also via startup helper logic in `app.py`.

Not fully confirmed:
- Exact command used by the project owner to start backend in final demo. Likely Flask/Python, but do not invent command.

## How Analysis Is Triggered

- User upload: `POST /analyze-pcap` or `/pcap/analyze`.
- Local path: `POST /analyze-local` or `/pcap/analyze-local`.

Evidence: `Backend/app.py` `analyze_pcap`, `analyze_local`.

## Synchronous or Background

Background job.

Evidence:
- `Backend/app.py` creates pipeline closure and calls `jobs.submit(...)`.
- `Backend/pcap_engine/jobs.py` uses `ThreadPoolExecutor`.
- Initial response is `202` with `job_id` and poll URL.

## Job Storage

Both memory and disk:
- In-memory `_jobs` dict.
- Disk `state.json` per job under `Backend/pcap_runs/_jobs/<job_id>/`.
- `report.json` stored on success.

Evidence: `JobRegistry` in `Backend/pcap_engine/jobs.py`.

## Polling

Confirmed:
- Frontend polls `/job/<job_id>`.
- Backend includes `poll_after_ms` and `Retry-After` for queued/running jobs.
- Backend constant `PCAP_RECOMMENDED_POLL_MS = 600000`.
- Frontend starts with `pollIntervalMs` around 6000 ms and increases to 8000 ms on `429`.

Evidence:
- `Backend/app.py` `get_job`.
- `PcapAnalyzerPage.tsx` polling `useEffect`.

## Cancellation

Confirmed:
- `POST /api/pcap/cancel/<job_id>` and `/pcap/cancel/<job_id>`.
- Marks job as cancelled and sets cancellation metadata.
- Pipeline checks `_raise_if_pcap_cancelled`.
- Active subprocesses are terminated best effort.

Evidence:
- `Backend/app.py` `cancel_pcap_job`, `_terminate_active_pcap_process`.
- `Backend/pcap_engine/jobs.py` `request_cancel`, `is_cancel_requested`.

## Timeouts

Confirmed:
- `tshark` timeout default `TSHARK_TIMEOUT=1800` seconds.
- Zeek timeout: min 300 seconds, max 3600 seconds, roughly 2 seconds per MB.
- Frontend alert/network score fetch has timeout helper in some dashboard utilities.

Evidence:
- `Backend/pcap_engine/tshark_runner.py`.
- `Backend/pcap_engine/zeek_runner.py`.

## Max File Size

Confirmed:
- `MAX_FILE_SIZE = 15 * 1024 * 1024 * 1024`.
- Flask `MAX_CONTENT_LENGTH` set.
- Explicit request/content and stream size checks.
- Frontend `PCAP_MAX_UPLOAD_BYTES` also 15 GB.

Evidence:
- `Backend/app.py`.
- `PcapAnalyzerPage.tsx`.

## Large Files

Confirmed:
- `tshark_runner.py` supports chunked export with `editcap` when native `tshark` and `editcap` are available and PCAP size exceeds `TSHARK_CHUNK_THRESHOLD_BYTES` default 4 GB.
- Memory-pressure errors can trigger chunked retry.

## Local-Path Analysis

Confirmed backend endpoint:
- `/pcap/analyze-local`, `/analyze-local`.

Not confirmed in frontend:
- Main PCAP UI uses file upload, not local path endpoint.

## Job Reuse / Deduplication

Confirmed:
- `analysis_key` includes owner, source fingerprint/path, Zeek option, confidence mode, max alerts, max clusters.
- `create_or_reuse_active` reuses only queued/running matching jobs.
- Duplicate upload file is removed when active job reused.

Evidence:
- `Backend/app.py` `_build_analysis_key`, `_reuse_existing_analysis_job`, `_cleanup_unused_upload`.
- `Backend/pcap_engine/jobs.py` `create_or_reuse_active`.

## Cleanup Rules

Confirmed:
- Artifact retention default 72 hours.
- Job retention default 168 hours.
- Cleanup interval default 60 minutes.
- Active jobs protected.

Evidence:
- `Backend/app.py` constants.
- `Backend/pcap_engine/cleanup.py`.

## Commands

Confirmed inferable command internals:
- `tshark` command includes `-n -r <pcap> -T fields ...`.
- Zeek command through WSL: `wsl bash -lc 'cd "<output>" && /usr/local/zeek/bin/zeek -C -r "<pcap>" LogAscii::use_json=T'`.

Do not present these as user setup commands unless owner confirms setup documentation.
