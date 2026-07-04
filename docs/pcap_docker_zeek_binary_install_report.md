# PCAP Docker Zeek Binary Install Report

## A. What was missing

The backend image had Linux/container path support in `zeek_runner.py`, but the container did not actually contain a `zeek` binary.

Before this fix:

```sh
command -v zeek
```

returned nothing inside the backend container.

## B. Exact Dockerfile changes

The backend `Dockerfile` now uses the official Zeek image as a build stage:

```dockerfile
FROM zeek/zeek:8.1 AS zeek-runtime
FROM python:3.11-slim
```

It copies the Zeek installation into the backend image:

```dockerfile
COPY --from=zeek-runtime /usr/local/zeek /usr/local/zeek
```

It exposes Zeek through environment settings:

```dockerfile
ZEEK_BIN=zeek
PATH="/usr/local/zeek/bin:${PATH}"
LD_LIBRARY_PATH="/usr/local/zeek/lib:${LD_LIBRARY_PATH}"
```

It installs the minimal runtime libraries needed for the copied Zeek binary:

```dockerfile
libicu76
libnode115
libnorm1t64
libpgm-5.3-0t64
libsodium23
libzmq5
```

It verifies Zeek during image build:

```dockerfile
RUN command -v zeek && zeek --version
```

## C. How Zeek was installed/provided

Zeek is provided by copying `/usr/local/zeek` from the official `zeek/zeek:8.1` Docker image into the backend image.

I chose this over guessing an OBS/apt repository because the default Debian package sources for `python:3.11-slim` do not provide a `zeek` package candidate. The official Zeek documentation describes Zeek Docker images as Debian-based images with a complete Zeek installation.

Sources:

- Zeek install docs: https://docs.zeek.org/en/master/install.html
- Official Zeek package page: https://software.opensuse.org/download/package?package=zeek&project=security%3Azeek

## D. `zeek --version` output inside backend container

Verified:

```text
/usr/local/zeek/bin/zeek
zeek version 8.1.2
```

Also verified by absolute path:

```text
/usr/local/zeek/bin/zeek version 8.1.2
```

## E. Docker build result

Passed:

```powershell
docker compose build backend
```

The build completed with:

```text
Image sentinel-ai-backend:local Built
```

Then backend startup passed:

```powershell
docker compose up -d backend
```

Backend service state:

```text
final-backend-1   sentinel-ai-backend:local   Up
```

## F. UI verification result

I did not complete an authenticated UI upload from this environment because no UI login/session and real PCAP upload flow were provided in this turn.

Container-side Zeek generation was verified with a tiny synthetic PCAP in the same backend path layout:

```text
/app/Backend/pcap_runs/zeek_smoke_udp.pcap
```

Zeek generated:

```text
/app/Backend/pcap_runs/zeek_smoke_out/conn.log
```

The requested find command now returns:

```text
/app/Backend/pcap_runs/zeek_smoke_out/conn.log
```

## G. Whether Evidence button became enabled

Not verified from the UI in this run.

The backend prerequisites are now satisfied:

- `zeek` exists inside the backend container.
- `zeek --version` works.
- Zeek can generate `conn.log` under `/app/Backend/pcap_runs`.
- Existing backend logic keeps Evidence enabled only when recognized logs exist.

For a new UI PCAP job, the Evidence button should become enabled if Zeek produces at least one recognized log under the job `evidence_dir`, such as `conn.log`.

## H. Remaining limitation

- UI upload verification still needs to be performed with an authenticated browser session.
- The smoke test created a small synthetic PCAP and Zeek output folder under the Docker `backend-pcap-runs` volume.
- Zeek remains optional. If Zeek fails for a specific PCAP, base PCAP analysis should still complete and the Evidence button should remain disabled with the Zeek reason.

## I. Rollback plan

To roll back the Docker Zeek binary installation:

1. Remove the `zeek/zeek:8.1 AS zeek-runtime` stage from `Dockerfile`.
2. Remove the Zeek runtime packages:
   - `libicu76`
   - `libnode115`
   - `libnorm1t64`
   - `libpgm-5.3-0t64`
   - `libsodium23`
   - `libzmq5`
3. Remove:

```dockerfile
COPY --from=zeek-runtime /usr/local/zeek /usr/local/zeek
RUN command -v zeek && zeek --version
```

4. Rebuild and restart backend:

```powershell
docker compose build backend
docker compose up -d backend
```
