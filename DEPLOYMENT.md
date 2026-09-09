# SecureLens Deployment

SecureLens includes a production-like Docker Compose stack containing:

- A React production build served by Nginx
- A private FastAPI backend service
- A same-origin `/api` reverse proxy
- Per-IP rate limiting on `POST /upload`
- Container health checks
- Environment-controlled CORS and API documentation
- An Nginx request-body ceiling just above the default upload size, so unvalidated bodies never buffer to the backend
- A wall-clock budget on analysis so a request cannot outlive the reverse proxy's read timeout
- Container resource limits (memory, PIDs, CPU) and dropped Linux capabilities
- Browser security headers
- A non-root backend container
- Automated full-stack container smoke tests

## Start the Stack

Optionally create a local Compose environment file:

```powershell
Copy-Item .env.compose.example .env
```

Build and start:

```powershell
docker compose up --build -d
```

Open:

```text
http://127.0.0.1:8080
```

Validate the API:

```powershell
curl.exe http://127.0.0.1:8080/api/health

curl.exe -F "file=@examples/sample-security.log" `
  http://127.0.0.1:8080/api/upload
```

View services and logs:

```powershell
docker compose ps
docker compose logs
```

Stop the stack:

```powershell
docker compose down
```

## Production Environment

The backend uses these production settings in Compose:

```env
APP_ENV=production
API_DOCS_ENABLED=false
CORS_ORIGINS=
```

CORS can stay empty because the Nginx frontend proxies `/api` on the same browser origin.

When deploying the frontend and backend on different origins, set `CORS_ORIGINS` to an explicit comma-separated list. Do not use `*` for a public deployment.

## Upload Size

The backend is the single source of truth for the upload size limit:
`MAX_FILE_SIZE_MB` (default 5, range 1–100). The default is deliberately
low: the deterministic analyzer has quadratic worst-case cost, and a
detection-dense log near 25 MB can occupy a worker for minutes. A 5 MB
detection-dense log analyzes in about 10 seconds; the
`ANALYSIS_TIME_BUDGET_SECONDS` ceiling (see below) backstops the rest.

Starlette's multipart parser buffers the entire request body — spooling to
the backend container's `/tmp` — *before* the handler's streaming size
check runs. To keep an unvalidated body from ever reaching that spool,
Nginx's `client_max_body_size` in `frontend/nginx.conf` is set to `8m`:
just above the 5 MB default plus multipart framing. Uploads up to ~7 MB
still reach the backend and get its JSON size error; larger ones are cut
off at Nginx with a 413. The backend container also mounts `/tmp` as a
`tmpfs` capped at `size=16m` (see `compose.yaml`) so the spool has a hard
ceiling regardless of Nginx.

**If you raise `MAX_FILE_SIZE_MB` above ~7**, an upload between the new
limit and the old one is rejected by Nginx with its stock 413 HTML page
instead of the backend's JSON error, and an upload larger than `8m` never
reaches the backend at all. To support a higher limit, also:

1. raise `client_max_body_size` in `frontend/nginx.conf` to about
   `MAX_FILE_SIZE_MB + 3m`,
2. raise the backend `tmpfs` `size=` in `compose.yaml` past the new
   maximum,
3. rebuild the frontend image (`docker compose build frontend`) — the
   config is baked in at build time, and
4. confirm a worst-case log of the new size still analyzes within
   `ANALYSIS_TIME_BUDGET_SECONDS`, or raise that too (keeping it below the
   reverse proxy's read timeout).

## Analysis Time Budget

`analyze_log()` runs under a wall-clock ceiling, `ANALYSIS_TIME_BUDGET_SECONDS`
(default 45). The analyzer checks the deadline inside its scan loops and,
if the budget is exceeded, the request returns HTTP 413 with a message
asking for a smaller or less repetitive log rather than letting the worker
keep burning CPU behind a connection the reverse proxy has already timed
out. Keep the budget below Nginx's `proxy_read_timeout` (default 60s).
The underlying quadratic cost is tracked for a proper fix alongside the
normalized-event-schema refactor.

## Upload Rate Limiting

The backend applies a per-IP fixed-window limit to `POST /upload`:

```env
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MAX_REQUESTS=10
RATE_LIMIT_WINDOW_SECONDS=60
TRUST_PROXY_HEADERS=true
```

The Compose stack sets `TRUST_PROXY_HEADERS=true` so the backend reads the
client address from the `X-Real-IP` header that Nginx sets. Enable that flag
only when the backend is reachable exclusively through a trusted proxy; on a
directly exposed backend a client could forge the header.

The limiter keeps counters in process memory, which is sufficient for the
single-worker container in this stack. Running multiple backend workers or
replicas would give each its own counters; that needs a shared store and is
out of scope here.

For defense in depth you can also cap requests at the edge in
`frontend/nginx.conf`, which bounds abuse before it reaches the backend:

```nginx
# http context
limit_req_zone $binary_remote_addr zone=upload:10m rate=10r/m;

# inside location /api/
limit_req zone=upload burst=5 nodelay;
```

## Optional AI Summary

Set these values in the root `.env` file:

```env
AI_SUMMARY_ENABLED=true
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-5-mini
```

Never commit the `.env` file or a real API key.

## Public Deployment Notes

The included Compose stack is production-like, but a public deployment still needs:

- TLS termination
- A real domain
- Managed secrets
- Image update and vulnerability management
- Centralized logs and metrics
- Rate limiting or upstream abuse protection
- Backup and incident-response procedures
