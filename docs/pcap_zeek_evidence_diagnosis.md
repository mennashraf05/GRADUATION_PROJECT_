# PCAP Zeek Evidence Export Diagnosis

## A. Short problem summary

The PCAP job can finish with status `DONE` and still have the Evidence button disabled because completion of the base PCAP analysis is separate from Zeek evidence availability.

In this codebase, the frontend enables Evidence export only when the backend returns `evidence_available: true`. The backend sets that value from physical Zeek log files found under the job state's `evidence_dir`, specifically `conn.log`, `dns.log`, `http.log`, or `ssl.log`.

Local persisted jobs were not available in this checkout: `Backend/pcap_runs/_jobs` exists but contains no `state.json` or `report.json` files. Therefore the exact latest runtime job cannot be confirmed from artifacts in this workspace.

## B. Confirmed facts from code

- Frontend file inspected: `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`.
- Backend file inspected: `Backend/app.py`.
- Zeek runner inspected: `Backend/pcap_engine/zeek_runner.py`.
- Zeek loader inspected: `Backend/pcap_engine/zeek_loader.py`.
- Cleanup inspected: `Backend/pcap_engine/cleanup.py`.
- Tests inspected:
  - `Backend/tests/test_pcap_route_contracts.py`
  - `Backend/tests/test_pcap_artifact_protection.py`
  - `Backend/tests/test_pcap_summary_evidence_merge_regression.py`
  - `Backend/tests/test_pcap_alert_persistence_regression.py`

The backend constant is:

```python
ZEEK_EVIDENCE_FILES = ("conn.log", "dns.log", "http.log", "ssl.log")
```

The UI does not independently decide whether Zeek should be available. It trusts the backend `evidence_available` field.

## C. What happens when Include Zeek is selected

When the checkbox is selected:

1. React stores the checked state in `includeZeek`.
2. Upload builds a `FormData`.
3. The frontend appends:

```ts
fd.append("include_zeek", String(includeZeek));
```

So the submitted value is the string `"true"` when selected and `"false"` when not selected.

The backend then:

1. Parses `include_zeek`.
2. Starts `run_pcap_pipeline(... include_zeek=include_zeek ...)`.
3. If true, creates a Zeek run folder under `Backend/pcap_runs/<uuid>`.
4. Saves that folder path into job state as `evidence_dir`.
5. Starts Zeek in a background thread.
6. Continues tshark, CIC feature extraction, and ML.
7. Later waits for the Zeek future and attempts to load Zeek logs.
8. If Zeek loading fails, the exception is logged and the pipeline continues without Zeek evidence.

That means `DONE` does not prove Zeek evidence succeeded.

## D. Whether frontend sends include_zeek correctly

Yes. The frontend checkbox appears correctly wired.

Confirmed:

- Checkbox is controlled by `checked={includeZeek}`.
- Toggle uses `setIncludeZeek((v) => !v)`.
- Upload sends `String(includeZeek)`.
- The exact value sent is `"true"` or `"false"`.

I did not find a frontend bug where the checkbox can be visually checked but sends false.

## E. Whether backend receives include_zeek correctly

Yes, for the upload route.

`analyze_pcap` reads:

```python
include_zeek_raw = str(request.form.get("include_zeek", "true")).strip().lower()
include_zeek = include_zeek_raw not in {"false", "0", "no", "off"}
```

So `"true"` becomes `True`, and missing `include_zeek` also defaults to `True`.

The local analysis route also supports strings and booleans correctly.

## F. Whether Zeek is executed

Code says Zeek is executed when `include_zeek=True`.

`run_pcap_pipeline` calls:

```python
zeek_run_folder = prepare_zeek_run_folder(BASE_RUN_FOLDER)
jobs.update(job_id, evidence_dir=str(zeek_run_folder))
zeek_future = zeek_bg_pool.submit(run_zeek, ...)
```

The Zeek command is built in `zeek_runner.py`:

```python
wsl bash -lc 'cd "<wsl_output>" && /usr/local/zeek/bin/zeek -C -r "<wsl_path>" LogAscii::use_json=T'
```

The path `/usr/local/zeek/bin/zeek` is hardcoded.

Windows paths are converted to WSL paths like:

```text
E:\path\file.pcap -> /mnt/e/path/file.pcap
```

Possible execution failure points:

- WSL cannot access the Windows drive path under `/mnt/e/...`.
- The backend process environment cannot find `wsl`.
- Zeek exists interactively but not for the backend service user/session.
- Zeek times out on a large PCAP.
- Zeek exits non-zero because the PCAP path is inaccessible or invalid.

Important: Zeek failure is logged, but it does not fail the whole PCAP job.

## G. Whether Zeek logs are generated

Not confirmed from local artifacts because no completed job folders were present under `Backend/pcap_runs/_jobs`.

From code, logs are expected in the generated `evidence_dir`, not necessarily inside the job folder. The required filenames are:

- `conn.log`
- `dns.log`
- `http.log`
- `ssl.log`

If none of these files exist under `evidence_dir`, `evidence_available` is false.

Also note: Zeek may generate no `dns.log`, `http.log`, or `ssl.log` if the PCAP has no such traffic. However, a readable IP PCAP would normally be expected to produce `conn.log`. If even `conn.log` is missing, Zeek likely did not run successfully, wrote somewhere unexpected, or the evidence folder was removed.

## H. Whether logs are loaded successfully

The loader expects JSON lines, not default Zeek TSV.

`zeek_runner.py` passes:

```text
LogAscii::use_json=T
```

`zeek_loader.py` then uses `json.loads(line)` for each log line. If Zeek outputs TSV instead of JSON, the loader silently skips every line and returns empty DataFrames.

In the current runner, JSON output is requested correctly. So the main format risk is if the Zeek command does not honor that option in the actual runtime or if another Zeek configuration overrides output.

## I. Why Evidence button is disabled

The Evidence button is disabled because the frontend receives `evidence_available` as false.

Frontend condition:

```ts
const cardCanExportEvidence =
  normalizedStatus === "done" && j.evidence_available === true;
```

Backend condition:

```python
"evidence_available": bool(artifacts["zeek_files"])
```

`artifacts["zeek_files"]` is populated only when `_collect_job_export_artifacts` finds at least one of:

- `conn.log`
- `dns.log`
- `http.log`
- `ssl.log`

inside `state.evidence_dir`.

So the disabled button means: for that job, the backend did not find any recognized Zeek evidence log files at the recorded evidence path at the time the UI polled history/status.

## J. Exact root cause if found

The exact code-level cause is:

`evidence_available` is calculated from the presence of recognized Zeek log files, not from `include_zeek`, not from job status, and not from `zeek_requested`.

The exact runtime cause for your latest job is not fully confirmed because this workspace has no persisted latest job artifacts to inspect.

Most likely, Zeek was requested but did not leave any of the required files in the job state's `evidence_dir`. Because Zeek errors are swallowed by design, the PCAP job can still complete successfully and the report can be enabled while evidence export stays disabled.

## K. Top 3 likely causes with evidence

1. Zeek failed or timed out, and the pipeline continued without evidence.

Evidence:

- `run_pcap_pipeline` catches exceptions around `zeek_future.result()` and `load_zeek_evidence`.
- It logs `"Zeek evidence loading failed; continuing with base detection only"`.
- It then continues to score, build the report, and finish the job.

2. Zeek ran but produced no required evidence files in `evidence_dir`.

Evidence:

- Backend only checks `conn.log`, `dns.log`, `http.log`, and `ssl.log`.
- UI only enables Evidence when these files are physically present.
- A completed report does not require these files.

3. Artifact cleanup removed the Zeek run folder after completion.

Evidence:

- Zeek folders are created under `Backend/pcap_runs/<uuid>`, outside `_jobs/<job_id>`.
- Cleanup protects `evidence_dir` only for active jobs.
- Completed job evidence folders can later be deleted by stale artifact cleanup after `ARTIFACT_RETENTION_HOURS`, default `72`.

Secondary issue found:

The real pipeline stores `evidence_dir` outside the job directory, but `_build_job_evidence_bundle` later validates Zeek files as if they must be inside `job_dir`. If evidence files do exist, this can make actual evidence export fail even when the button becomes enabled. The route-contract test does not catch this because its synthetic Zeek folder is created inside `_jobs/<job_id>/zeek`, unlike the real pipeline.

## L. Safe diagnostic commands to run in PowerShell

Run these from the repository root.

List latest job states:

```powershell
Get-ChildItem -LiteralPath "Backend\pcap_runs\_jobs" -Recurse -Filter state.json |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 10 FullName, LastWriteTime
```

Print key fields from latest states:

```powershell
Get-ChildItem -LiteralPath "Backend\pcap_runs\_jobs" -Recurse -Filter state.json |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5 |
  ForEach-Object {
    $s = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
    [PSCustomObject]@{
      job_id = $s.job_id
      status = $s.status
      message = $s.message
      error = $s.error
      evidence_dir = $s.evidence_dir
      report_path = $s.report_path
      upload_path = $s.upload_path
      packet_csv_path = $s.packet_csv_path
      artifact_protection = ($s.artifact_protection | ConvertTo-Json -Compress)
    }
  } | Format-List
```

Check whether required Zeek files exist for a job:

```powershell
$statePath = "Backend\pcap_runs\_jobs\<JOB_ID>\state.json"
$s = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
"Evidence dir: $($s.evidence_dir)"
Get-ChildItem -LiteralPath $s.evidence_dir -Force -ErrorAction SilentlyContinue |
  Select-Object Name, Length, LastWriteTime
```

Check report metadata:

```powershell
$reportPath = "Backend\pcap_runs\_jobs\<JOB_ID>\report.json"
$r = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
$r.meta | ConvertTo-Json -Depth 8
```

Search for Zeek logs anywhere under `pcap_runs`:

```powershell
Get-ChildItem -LiteralPath "Backend\pcap_runs" -Recurse -Include conn.log,dns.log,http.log,ssl.log,evidence_bundle.zip -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime |
  Sort-Object LastWriteTime -Descending
```

Validate that WSL can see the uploaded PCAP path from `state.json`:

```powershell
$s = Get-Content -Raw -LiteralPath "Backend\pcap_runs\_jobs\<JOB_ID>\state.json" | ConvertFrom-Json
$wslPath = ($s.upload_path -replace "\\","/")
$wslPath = "/mnt/" + $wslPath.Substring(0,1).ToLower() + $wslPath.Substring(2)
wsl bash -lc "ls -lh '$wslPath'"
```

Try a read-only Zeek version check:

```powershell
wsl bash -lc "/usr/local/zeek/bin/zeek --version"
```

Look for Zeek failure logs in backend output/log files if your run writes logs to disk:

```powershell
rg -n "Zeek failed|Zeek background task failed|Zeek evidence loading failed|Starting Zeek run|Zeek run completed" Backend
```

## M. Minimal suggested fix, but not applied

Do not apply automatically yet. Suggested minimal fix:

1. Store Zeek run output inside the job directory, for example `_jobs/<job_id>/zeek`, or update bundling validation to explicitly allow the recorded `evidence_dir` under `BASE_RUN_FOLDER`.
2. Persist a clear Zeek status in `state.json`, such as:
   - `zeek_requested`
   - `zeek_status`
   - `zeek_error`
   - `zeek_log_count`
   - `zeek_required_files_found`
3. Return this diagnostic status to the frontend so the UI can distinguish:
   - Zeek not requested
   - Zeek still running
   - Zeek failed
   - Zeek succeeded but no logs were generated
   - Evidence available
4. Keep `evidence_available` based on actual files, but make failures visible instead of silently appearing as "disabled".

## N. Files/functions that would need changes if approved later

- `Backend/app.py`
  - `run_pcap_pipeline`
  - `_collect_job_export_artifacts`
  - `_build_job_evidence_bundle`
  - `get_job`
  - `_job_history_item`
- `Backend/pcap_engine/zeek_runner.py`
  - `run_zeek`
  - possibly output folder handling
- `Backend/pcap_engine/jobs.py`
  - `JobState` fields if persistent Zeek diagnostics are added
- `Cybersecurity Dashboard Design/src/components/pages/PcapAnalyzerPage.tsx`
  - Evidence disabled reason display
  - optional Zeek status badge/message
- Tests:
  - `Backend/tests/test_pcap_route_contracts.py`
  - add a real-pipeline-shaped evidence folder test where `evidence_dir` is outside `_jobs/<job_id>`
  - add a Zeek failure/status contract test

## O. Risk level of suggested fix

Medium.

Reason:

- Making Zeek status visible is low risk.
- Changing evidence folder location or export path validation touches artifact export behavior and path-safety checks, so it should be tested carefully.
- The real pipeline/test mismatch around evidence folder location should be fixed with tests before changing export behavior.

## P. Final conclusion in simple Arabic

المشكلة غالبا ليست في زرار الواجهة ولا في اختيار `Include Zeek Evidence`. الواجهة ترسل الاختيار صح، والباك إند يستقبله صح.

السبب أن تحليل الـ PCAP الأساسي يخلص بنجاح، لكن أدلة Zeek تعتبر متاحة فقط لو ملفات Zeek نفسها موجودة في `evidence_dir`، خصوصا `conn.log` أو `dns.log` أو `http.log` أو `ssl.log`.

لو Zeek فشل، أو لم يكتب هذه الملفات، أو الملفات اتحذفت بعد التحليل، الباك إند يرجع `evidence_available: false`. لذلك التقرير يظل متاحا، لكن زر Evidence يظل مقفولا.

أقرب سبب مشتبه به: Zeek تم طلبه، لكن لم يتم العثور على ملفات Zeek المطلوبة داخل مسار الأدلة المسجل للـ job. نحتاج فحص `state.json` و `evidence_dir` للـ job الحقيقي لتأكيد السبب النهائي.
