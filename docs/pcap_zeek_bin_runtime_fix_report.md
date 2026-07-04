# PCAP Zeek Binary Runtime Fix Report

## A. Exact root cause

The backend container had Zeek installed and working at:

```text
/usr/local/zeek/bin/zeek
```

But the runtime environment was configured with:

```text
ZEEK_BIN=zeek
```

In the running backend container, `/usr/local/zeek/bin` was not present in the runtime `PATH`, so resolving `zeek` by name failed even though the absolute binary path worked.

## B. File changed

Changed:

- `Dockerfile`
- `docker-compose.yml`

No backend application logic, frontend code, database code, or `zeek_runner.py` was changed.

`Dockerfile` now sets the image default to the absolute Zeek binary path.

`docker-compose.yml` also sets the backend runtime environment to the same absolute path so recreating the container applies the fix even when a rebuild is blocked by dependency download/network issues.

## C. Old `ZEEK_BIN` value

```text
zeek
```

## D. New `ZEEK_BIN` value

```text
/usr/local/zeek/bin/zeek
```

## E. Verification output from inside backend container

Recreated backend:

```powershell
docker compose up -d --force-recreate backend
```

Result:

```text
Container final-backend-1 Recreated
Container final-backend-1 Started
```

Runtime Zeek verification:

```powershell
docker compose exec backend sh -lc 'echo "ZEEK_BIN=$ZEEK_BIN"; "$ZEEK_BIN" --version'
```

Output:

```text
ZEEK_BIN=/usr/local/zeek/bin/zeek
/usr/local/zeek/bin/zeek version 8.1.2
```

Binary existence verification:

```powershell
docker compose exec backend sh -lc 'ls -l /usr/local/zeek/bin/zeek'
```

Output:

```text
-rwxr-xr-x 1 root root 28617712 Apr 20 16:07 /usr/local/zeek/bin/zeek
```

Recognized Zeek logs discovery:

```powershell
docker compose exec backend sh -lc 'find /app/Backend/pcap_runs -name conn.log -o -name dns.log -o -name http.log -o -name ssl.log | tail -20'
```

Output:

```text
/app/Backend/pcap_runs/zeek_smoke_out/conn.log
/app/Backend/pcap_runs/16152146-907e-465d-98a2-e10b68ab04d2/conn.log
/app/Backend/pcap_runs/16152146-907e-465d-98a2-e10b68ab04d2/dns.log
/app/Backend/pcap_runs/16152146-907e-465d-98a2-e10b68ab04d2/ssl.log
/app/Backend/pcap_runs/c9601e22-8644-49fb-ad42-d21d6d3e95dd/conn.log
/app/Backend/pcap_runs/c9601e22-8644-49fb-ad42-d21d6d3e95dd/dns.log
/app/Backend/pcap_runs/c9601e22-8644-49fb-ad42-d21d6d3e95dd/http.log
/app/Backend/pcap_runs/c9601e22-8644-49fb-ad42-d21d6d3e95dd/ssl.log
```

Backend service status:

```text
final-backend-1   sentinel-ai-backend:local   Up
```

Build note:

`docker compose build backend` was attempted, but the build failed at the existing `pip install` layer because PyPI requests hit SSL EOF errors. The Zeek build-stage verification still passed before that failure:

```text
/usr/local/zeek/bin/zeek
zeek version 8.1.2
```

The runtime fix was then applied by recreating the backend container with the corrected `docker-compose.yml` environment value.

## F. Tests run and results

Passed:

```powershell
python Backend\tests\test_zeek_runner.py
```

Result:

```text
Ran 4 tests in 0.008s
OK
```

Passed:

```powershell
python Backend\tests\test_pcap_route_contracts.py
```

Result:

```text
Ran 6 tests in 0.827s
OK
```

Failed:

```powershell
python Backend\tests\test_pcap_artifact_protection.py
```

Result:

```text
Ran 3 tests in 0.067s
FAILED (errors=1)
```

Failure:

```text
FileNotFoundError: [Errno 2] No such file or directory:
Backend\pcap_runs\_jobs\4d06651c-27d1-4880-b06d-97ce998fceb9\report.json
```

Passed:

```powershell
python Backend\tests\test_pcap_summary_evidence_merge_regression.py
```

Result:

```text
Ran 1 test in 0.052s
OK
```

Passed:

```powershell
python -m py_compile Backend\app.py Backend\pcap_engine\zeek_runner.py Backend\pcap_engine\jobs.py
```

Result: no output, exit code `0`.

## G. UI verification result

Not completed from the UI.

The frontend and nginx services were running, but the in-app browser was unavailable in this Codex session, so I could not perform a fresh authenticated UI PCAP upload with Include Zeek Evidence enabled.

Container-side runtime verification passed, and recognized Zeek logs were present under `/app/Backend/pcap_runs`.

## H. Rollback plan

To roll back this runtime path fix:

1. In `Dockerfile`, change:

```dockerfile
ZEEK_BIN=/usr/local/zeek/bin/zeek
```

back to:

```dockerfile
ZEEK_BIN=zeek
```

2. In `docker-compose.yml`, remove:

```yaml
ZEEK_BIN: /usr/local/zeek/bin/zeek
```

3. Recreate backend:

```powershell
docker compose up -d --force-recreate backend
```
