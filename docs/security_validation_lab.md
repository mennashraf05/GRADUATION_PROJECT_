# Security Validation Lab

## Purpose

Security Validation Lab is an admin-only Sentinel AI page for safely demonstrating that local security controls are working. It runs predefined local simulations against the WAF and returns sanitized pass/fail results to the admin dashboard.

## Access

The lab is available only inside the Admin Console. Backend APIs are protected by the existing admin authentication decorator and require a valid admin token.

## Architecture

```text
Admin Frontend Page
  -> Backend Admin API
  -> predefined local request to WAF_BASE_URL
  -> Nginx WAF + ModSecurity
  -> Flask backend when allowed
```

Default local WAF endpoint:

```text
WAF_BASE_URL=https://localhost:8081
```

Docker Compose uses the service address:

```text
WAF_BASE_URL=https://nginx-waf:8081
```

## Predefined Tests

| Test ID | Attack Name | Target | Expected | Control |
| --- | --- | --- | --- | --- |
| `sqli_login` | SQL Injection | `/api/auth/login` | `403` | WAF Rule 1001 |
| `xss_contact` | Cross-Site Scripting XSS | `/api/contact/support` | `403` | WAF Rule 1002 |
| `path_traversal` | Path Traversal | `/download?file=../../../../etc/passwd` | `403` | WAF Rule 1003 |
| `cors_bad_origin` | CORS Misconfiguration | `/api/auth/me` | `403` | WAF Rule 1004 |
| `cors_allowed_origin` | Allowed CORS Origin | `/api/auth/me` | `401` | WAF allow + backend authentication |
| `idor_profile` | IDOR Pattern | `/api/profile?id=102` | `403` | WAF Rule 1008 |
| `brute_force_login` | Brute Force Login | `/api/auth/login` | `429` | WAF / backend rate limiting |

## Safety Restrictions

- The frontend can only send a predefined `test_id` or `run_all=true`.
- The frontend cannot send custom URLs.
- The frontend cannot send custom payloads.
- The backend uses an allowlist of local tests only.
- Results do not expose raw payloads, tokens, cookies, stack traces, filesystem paths, WAF logs, or internal exceptions.

## Expected Results

For a healthy local WAF setup:

- SQL Injection returns `403`.
- XSS returns `403`.
- Path Traversal returns `403`.
- Bad CORS Origin returns `403`.
- Allowed CORS Origin reaches backend auth and returns `401`.
- IDOR Pattern returns `403`.
- Brute Force returns `429` after repeated attempts.

## Limitations

- This is not a general attack tool.
- The WAF is defense-in-depth and does not replace secure coding.
- Backend validation and authorization remain required.
- IDOR protection must still be enforced by backend ownership checks.
- Local test results depend on the WAF service being reachable from the backend process.
