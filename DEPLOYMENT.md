# SecureLens Deployment

SecureLens includes a production-like Docker Compose stack containing:

- A React production build served by Nginx
- A private FastAPI backend service
- A same-origin `/api` reverse proxy
- Container health checks
- Environment-controlled CORS and API documentation
- A 6 MB Nginx request-body limit
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
