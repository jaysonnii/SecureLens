# SecureLens Deployment

SecureLens includes a production-like Docker Compose stack containing:

- A React production build served by Nginx
- A private FastAPI backend service
- A same-origin `/api` reverse proxy
- Per-IP rate limiting on `POST /upload`
- Container health checks
- Environment-controlled CORS and API documentation
- An Nginx request-body ceiling above the backend's maximum, so the app returns the size error
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
`MAX_FILE_SIZE_MB` (default 25, range 1–100). Nginx's `client_max_body_size`
in `frontend/nginx.conf` is fixed at `110m` — above the 100 MB backend
maximum plus multipart overhead — so an oversized upload is always rejected
by the backend with its JSON error, never by a raw Nginx 413. Changing
`MAX_FILE_SIZE_MB` needs no matching Nginx change as long as it stays within
the supported range.

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
