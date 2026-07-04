# PCAP Docker Zeek Support Report

## A. Exact root cause

The backend container stores uploaded PCAP files with Linux paths such as:

```text
/app/Backend/pcap_runs/<file>.pcap
```

Before this change, `Backend/pcap_engine/zeek_runner.py` always treated PCAP paths as Windows paths and forced them through the WSL converter. A Linux/container path was rejected with:

```text
Zeek requires a Windows absolute path for pcap_path
```

## B. Files changed

- `Backend/pcap_engine/zeek_runner.py`
- `Backend/tests/test_zeek_runner.py`
- `Backend/tests/test_pcap_route_contracts.py`
- `Dockerfile`

Note: the repository also has earlier uncommitted PCAP evidence-export fixes in `Backend/app.py`, `Backend/pcap_engine/jobs.py`, and `PcapAnalyzerPage.tsx`.

## C. Dockerfile changes

Changed:

```dockerfile
ZEEK_BIN=zeek
```

I attempted to add `zeek` to the backend image with apt, but Docker build failed because the current Debian sources for `python:3.11-slim` do not provide a `zeek` installation candidate:

```text
E: Package 'zeek' has no installation candidate
```

I did not add an external Zeek repository or change the base image because that would be a riskier Docker supply-chain/base-image change. The backend image remains buildable and configurable with `ZEEK_BIN`.

## D. `zeek_runner.py` behavior before

- Always expected Windows absolute paths like `E:\...\file.pcap`.
- Converted Windows paths to WSL paths.
- Always ran:

```text
wsl bash -lc 'cd "<wsl_output>" && /usr/local/zeek/bin/zeek -C -r "<wsl_path>" LogAscii::use_json=T'
```

- Rejected Linux paths like `/app/Backend/pcap_runs/file.pcap`.

## E. `zeek_runner.py` behavior after

- Windows absolute paths still use the existing WSL behavior.
- Linux absolute paths run Zeek directly.
- Relative paths are rejected.
- `run_zeek` still raises on Zeek failure, and `run_pcap_pipeline` still catches that failure so base PCAP analysis can complete.

## F. How Linux/container paths are handled

For a Linux path:

```text
/app/Backend/pcap_runs/sample.pcap
```

the runner builds:

```text
zeek -C -r /app/Backend/pcap_runs/sample.pcap LogAscii::use_json=T
```

and executes it with `cwd` set to the Zeek output folder, so generated logs are written to `evidence_dir`.

The Linux Zeek binary is resolved in this order:

1. `ZEEK_BIN`
2. `command -v zeek`
3. `/usr/local/zeek/bin/zeek`
4. fallback command name `zeek`

## G. How Windows/WSL paths are preserved

For a Windows path:

```text
E:\GRADUATION_PROJECT\pcap_runs\sample.pcap
```

the runner still builds a WSL command and converts paths to:

```text
/mnt/e/GRADUATION_PROJECT/pcap_runs/sample.pcap
```

The existing Windows/WSL behavior was not removed.

## H. Tests run and results

Passed:

```powershell
python Backend\tests\test_zeek_runner.py
python Backend\tests\test_pcap_route_contracts.py
python Backend\tests\test_pcap_artifact_protection.py
python Backend\tests\test_pcap_summary_evidence_merge_regression.py
python -m py_compile Backend\app.py Backend\pcap_engine\zeek_runner.py Backend\pcap_engine\jobs.py Backend\tests\test_zeek_runner.py Backend\tests\test_pcap_route_contracts.py
```

Added tests verify:

- Linux/container paths use direct Zeek command, not WSL.
- Windows paths still use WSL.
- Relative paths are rejected.
- Zeek command failure surfaces from `run_zeek`.
- Zeek failure does not fail the base PCAP pipeline.
- Evidence availability still requires recognized logs.
- Evidence export path safety remains enforced by the earlier route contract tests.

## I. Docker build result

First Docker build attempt with `apt-get install zeek` failed:

```text
Package zeek is not available
E: Package 'zeek' has no installation candidate
```

After removing the unavailable package and keeping `ZEEK_BIN=zeek`, backend build passed:

```text
Image sentinel-ai-backend:local Built
```

Backend startup check passed:

```text
docker compose up -d backend
```

The container has the updated Linux command builder:

```text
(['zeek', '-C', '-r', '/app/Backend/pcap_runs/sample.pcap', 'LogAscii::use_json=T'], '/app/Backend/pcap_runs/out', 'linux')
```

Current limitation confirmed: `command -v zeek` inside the rebuilt backend container returned no path, so Zeek is not installed in the image yet.

## J. Manual verification steps from UI

1. Install or provide a Zeek binary inside the backend container.
2. Ensure `ZEEK_BIN` points to that binary if it is not on `PATH`.
3. Rebuild and restart backend:

```powershell
docker compose build backend
docker compose up -d backend
```

4. Upload a PCAP from the UI.
5. Keep `Include Zeek Evidence` selected.
6. Wait for the job to complete.
7. If Zeek creates `conn.log`, `dns.log`, `http.log`, or `ssl.log` under the job `evidence_dir`, the Evidence button should enable.
8. Download Evidence and confirm the ZIP contains `zeek/conn.log` or other recognized logs.

## K. Remaining limitations

- The backend image does not currently include Zeek because Debian `python:3.11-slim` apt sources did not provide a `zeek` package.
- Linux/container execution support is implemented, but evidence generation in Docker requires a Zeek binary to exist in the backend container.
- I did not add an external Zeek repository or switch base images because that is a higher-risk packaging decision.
- If Zeek is missing or fails, the base report still completes and Zeek diagnostics show failure/no evidence.

## L. Rollback plan

To roll back this Docker/container support change:

1. Revert `Backend/pcap_engine/zeek_runner.py`.
2. Remove `Backend/tests/test_zeek_runner.py`.
3. Revert the added Zeek failure pipeline test in `Backend/tests/test_pcap_route_contracts.py`.
4. Remove `ZEEK_BIN=zeek` from `Dockerfile`.
5. Rebuild backend:

```powershell
docker compose build backend
docker compose up -d backend
```
