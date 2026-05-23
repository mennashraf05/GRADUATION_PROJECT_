# Sentinel AI Local WAF

## Architecture

Local API traffic can be routed through an Nginx reverse proxy with ModSecurity:

```text
Browser / Frontend
  -> https://localhost:8081
  -> Nginx WAF + ModSecurity
  -> https://localhost:5000 Flask backend
```

The frontend dev server remains available at `https://localhost:5173`. The WAF endpoint is intended for local API security testing and defense-in-depth validation.

## Protected Attack Classes

| Rule ID | Protection | Behavior |
| --- | --- | --- |
| `1001` | SQL injection on login endpoints | Blocks common login SQLi payloads such as `OR 1=1`, `UNION SELECT`, SQL comments, `sleep()`, `benchmark()`, and `information_schema`. |
| `1002` | Cross-site scripting | Blocks common XSS markers such as `<script`, `javascript:`, event handlers, `document.cookie`, `srcdoc=`, and `iframe`. |
| `1003` | Path traversal | Blocks traversal payloads on download/report/export endpoints, including `../`, encoded traversal, `/etc/passwd`, `windows/system32`, and `boot.ini`. |
| `1004` | Suspicious CORS origins | Blocks sensitive account/profile requests with an `Origin` header other than `https://localhost:5173`. |
| `1007` | Login brute force | Blocks excessive login attempts with `429 Too Many Requests`. Nginx `limit_req` is the primary local throttle. |
| `1008` | Suspicious profile ID manipulation | Blocks direct `id` parameters on profile endpoints as demo-level IDOR defense-in-depth. |

Blocked WAF requests return generic `403 Forbidden` responses, except brute force throttling which returns `429 Too Many Requests`.

## Run With Docker Compose

Start the backend and WAF:

```powershell
docker compose up backend nginx-waf
```

Then send API requests to:

```text
https://localhost:8081
```

The WAF proxies to:

```text
https://localhost:5000
```

The Docker service mounts these paths read-only:

```text
waf/nginx.docker.conf -> /etc/nginx/nginx.conf
waf/modsecurity -> /etc/nginx/modsecurity
certs -> /etc/nginx/certs
```

Certificate files are mounted at runtime and are not copied into container images.

## Native Nginx Option

If Docker is unavailable, install Nginx with the ModSecurity module and load `waf/nginx.conf`. That config expects local certificates at:

```text
/etc/nginx/certs/localhost.pem
/etc/nginx/certs/localhost-key.pem
```

Adjust the certificate and `modsecurity_rules_file` paths if your native Nginx installation uses a different layout.

## Verification Commands

SQL injection should be blocked with `403`:

```powershell
curl.exe -k -i -X POST https://localhost:8081/api/auth/login -H "Content-Type: application/json" --data "{\"email\":\"' OR '1'='1' --\",\"password\":\"x\"}"
```

XSS should be blocked with `403`:

```powershell
curl.exe -k -i -X POST https://localhost:8081/feedback -H "Content-Type: application/json" --data "{\"message\":\"<script>alert(1)</script>\"}"
```

Path traversal should be blocked with `403`:

```powershell
curl.exe -k -i "https://localhost:8081/download?file=../../../../etc/passwd"
```

Suspicious CORS origin should be blocked with `403`:

```powershell
curl.exe -k -i https://localhost:8081/api/auth/me -H "Origin: http://localhost:4000"
```

Allowed local frontend origin should reach the backend, usually returning backend auth status rather than a WAF `403`:

```powershell
curl.exe -k -i https://localhost:8081/api/auth/me -H "Origin: https://localhost:5173"
```

Suspicious profile ID manipulation should be blocked with `403`:

```powershell
curl.exe -k -i "https://localhost:8081/api/profile?id=102"
```

Repeated login attempts should eventually return `429`:

```powershell
1..12 | ForEach-Object { curl.exe -k -s -o NUL -w "try=$_ status=%{http_code}`n" -X POST https://localhost:8081/api/auth/login -H "Content-Type: application/json" --data "{\"email\":\"bad@example.com\",\"password\":\"bad\"}" }
```

## Legitimate Traffic Checklist

- Login page loads from the frontend.
- Normal login requests reach the backend through `https://localhost:8081`.
- Dashboard API calls reach the backend for allowed origins.
- PCAP upload, result, and export still work through the backend.
- Identity scan still works.
- File Vault safe uploads still work.

## Limitations

- The WAF is defense-in-depth and does not replace secure backend code.
- Real IDOR protection must remain enforced by backend authorization and ownership checks.
- CORS must also remain correctly configured in the backend.
- Brute force controls in the WAF complement, but do not replace, Flask rate limiting.
- ModSecurity signatures should be tuned with application traffic before production use.
