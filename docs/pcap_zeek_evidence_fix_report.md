# PCAP Zeek Evidence Export Fix Report

## A. What root cause was fixed

Evidence export could stay unavailable even when Zeek logs existed because the real pipeline writes `evidence_dir` under `Backend/pcap_runs/<uuid>`, while evidence bundle creation validated Zeek files as if they had to live under `_jobs/<job_id>`.

The fix keeps path safety, but allows recognized Zeek logs from the trusted job state's `evidence_dir` when that directory resolves inside `BASE_RUN_FOLDER`.

## B. Files changed

- `Backend/app.py`
- `Backend/pcap_engine/jobs.py`
- `Backend/tests/test_pcap_route_contracts.py`
- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`
- `docs/pcap_zeek_evidence_fix_report.md`

## C. Exact behavior before

- `evidence_available` was true only when recognized Zeek files were found.
- `_collect_job_export_artifacts` could find logs in `state.evidence_dir`.
- `_build_job_evidence_bundle` then rejected those same logs unless they were inside the job directory.
- The frontend disabled Evidence when `evidence_available !== true`, with no Zeek-specific reason shown.

## D. Exact behavior after

- `evidence_available` is still based on actual recognized files only.
- Recognized files are still limited to `conn.log`, `dns.log`, `http.log`, and `ssl.log`.
- `state.evidence_dir` is accepted only if it resolves inside `BASE_RUN_FOLDER`.
- Evidence ZIP includes existing `report.json`, `state.json`, and recognized Zeek logs under `zeek/<name>`.
- Outside or malicious `evidence_dir` paths are blocked.
- Job/status/history payloads include safe Zeek diagnostics:
  - `zeek_requested`
  - `zeek_status`
  - `zeek_error`
  - `zeek_required_files_found`
  - `zeek_log_count`
- The frontend keeps Evidence disabled unless `evidence_available=true`, but now shows a small disabled reason for completed history jobs and a tooltip/status string.

## E. Tests added/updated

Updated `Backend/tests/test_pcap_route_contracts.py` with coverage for:

- Completed job with `evidence_dir` outside `_jobs/<job_id>` but inside `BASE_RUN_FOLDER`, containing `conn.log`.
- Completed job with no Zeek files.
- Completed job with `evidence_dir` outside `BASE_RUN_FOLDER`.
- Existing report export and existing synthetic Zeek bundle export still pass.

## F. Tests run and results

Passed:

```powershell
python Backend\tests\test_pcap_route_contracts.py
python Backend\tests\test_pcap_artifact_protection.py
python Backend\tests\test_pcap_summary_evidence_merge_regression.py
python -m py_compile Backend\app.py Backend\pcap_engine\jobs.py Backend\tests\test_pcap_route_contracts.py
npm.cmd run build
```

`python -m pytest ...` was attempted, but this environment does not have `pytest` installed:

```text
No module named pytest
```

## G. Remaining limitations

- Base PCAP analysis still completes even if Zeek fails. This is intentional.
- Old jobs only become evidence-exportable if their `state.evidence_dir` still points to existing recognized Zeek logs under `BASE_RUN_FOLDER`.
- If cleanup already removed the Zeek folder, old jobs cannot export evidence unless the logs are restored.
- The frontend displays a concise Zeek status, not a full debug log.

## H. How to verify manually from the UI

1. Start a new PCAP analysis.
2. Keep `Include Zeek Evidence` selected.
3. Wait for the job to reach `DONE`.
4. Open job history.
5. If Zeek produced `conn.log`, `dns.log`, `http.log`, or `ssl.log`, the Evidence button should be enabled.
6. Click Evidence and confirm a ZIP downloads.
7. If Evidence is disabled, the history card should show a short Zeek reason such as failed, no logs, or not requested.

## I. Whether old completed jobs will work or only new jobs

Both can work, with one condition.

Old completed jobs will work if their `state.json` still has a valid `evidence_dir` under `Backend/pcap_runs` and that folder still contains at least one recognized Zeek log. New jobs will also work with the same rule.

If an old job's Zeek folder was deleted by cleanup, Evidence remains unavailable for that old job.
