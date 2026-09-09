# SecureLens

AI-assisted security log analysis. Upload a log → deterministic findings, evidence, 0–100 risk score, MITRE ATT&CK mappings, recommended actions. Portfolio project demonstrating cybersecurity + software engineering.

Read `README.md` for architecture, stack, and setup. This file covers what the code doesn't say.

## Invariants — do not break these

**The detection engine finds evidence. AI explains evidence.** AI never invents findings and never substitutes for the deterministic analyzer. If a feature would let AI output influence what counts as a finding, it's wrong.

**Raw log content never reaches the AI.** Only a restricted representation of deterministic findings goes to the OpenAI Responses API. Raw evidence lines and uploaded log content are excluded from prompts. Response storage stays disabled. Failure logs must exclude API keys, prompts, raw log content, and exception messages. This is the constraint most likely to break accidentally — check any AI-adjacent change against it.

**AI stays optional and off by default.** `AI_SUMMARY_ENABLED=false`. The local summary is always available. AI failure or empty response falls back to the local summary, never an error to the user.

**Every conclusion traces to evidence.** Findings link to source lines. Risk scores show their arithmetic (per-finding points, reason, pre-cap total, post-cap total). Future correlations must explain *why* events were grouped, not just that they were.

**Upload validation is a security boundary.** UTF-8 required; size cap of `MAX_FILE_SIZE_MB` (default 5, configurable 1–100) enforced by the backend; bounded 64 KB chunk reads; rejection after the first byte past the limit; extension allowlist. Don't relax these for feature convenience — see the EVTX note below.

The 5 MB default is a deploy constraint, not an arbitrary choice: the analyzer's worst case is quadratic (`_find_login_sequence`, plus repeated full-file passes in `_find_matches`), so a detection-dense log near the old 25 MB cap ran ~200s and 504'd behind nginx while the worker kept burning CPU. A 5 MB dense log runs ~10s. `analyze_log()` also enforces `ANALYSIS_TIME_BUDGET_SECONDS` (default 45, must stay under nginx's 60s `proxy_read_timeout`): over budget it raises `AnalysisTimeout` and the endpoint returns 413. Don't raise `MAX_FILE_SIZE_MB` without re-measuring a worst-case log of that size.

Starlette buffers the whole multipart body (spooling to the backend's `/tmp`) before the size check runs, so the Compose stack has two guards in front of it: Nginx `client_max_body_size 8m` (just above the 5 MB default), and `/tmp` mounted `tmpfs,size=16m`. Consequence: raising `MAX_FILE_SIZE_MB` above ~7 means Nginx returns a stock 413 before the backend sees the request — raise `client_max_body_size` and the tmpfs `size=` to match and rebuild the frontend image. See DEPLOYMENT.md "Upload Size".

## Conventions

- Windows development. Test commands invoke the venv interpreter directly rather than activating: `.\backend\venv\Scripts\python.exe -m pytest`, `npm.cmd --prefix frontend run test`.
- Before any commit: backend pytest, frontend test, lint, and production build all pass. GitHub Actions enforces this on pushes and PRs to `main`.
- Never commit a real API key.
- IBM Plex Sans for interface text, IBM Plex Mono for technical content (log lines, IPs, event IDs, commands).

## Current priority

**Deploy a public demo.** Everything else is secondary. The project is documented and CI-covered but nobody can see it run without cloning the repo — that gap is what's blocking the work from paying off.

Before going live:
1. ~~Rate-limit `POST /upload`.~~ Done — per-IP fixed-window limiter in `app/services/rate_limiter.py`, wired as a route dependency returning 429. Compose sets `TRUST_PROXY_HEADERS=true` for the `X-Real-IP` from nginx.
2. Deploy with `AI_SUMMARY_ENABLED=false` — an anonymous public endpoint shouldn't spend the OpenAI key.
3. Production CORS, production API URL in the frontend, confirm the key never reaches the client.

No auth and no stored history are *security properties* for a public demo, not just limitations. Nothing persists, so there's nothing to leak. Frame them that way.

## Open decisions

**EVTX vs. the UTF-8 gate.** Planned Windows EVTX support collides with the UTF-8 upload requirement — raw `.evtx` is binary and the current validator rejects it. Preferred resolution: support EVTX *exports* (`Get-WinEvent | Export-Csv`, EVTX-to-XML, Event Viewer CSV) rather than weakening the gate. Decide before writing parser code.

**Normalize before multi-file.** The roadmap orders multi-upload → parse formats → extract entities → normalize → correlate. That's UI-first and builds three milestones on the current line-matching analyzer, then rewrites them. Invert: refactor to parse → normalize → detect on single files first, with the existing test suite as the safety net and no user-visible change. Multi-file then becomes concatenating normalized events; correlation becomes a function over that list.

**Timestamps are the hard part.** Correlation windows ("same user within six minutes") are meaningless unless timestamps from different sources are comparable. Mixed timezones, absent timezones, epoch values, local time with no offset. Store both the original string and a parsed UTC value, and flag events where a timezone was assumed rather than read. Surface that assumption in the correlation explanation.

**Correlations are objects, not strings.** Rule ID, matched entities, time delta, contributing events. They need to be testable and to survive into the planned PDF report — a sentence built at render time does neither.

## Out of scope — do not build

Every log format. A full SIEM. Real-time ingestion. Endpoint agents. Automated incident response. Team permissions. Billing. Mobile apps. Large-scale cloud infrastructure.

The next real milestone is proving that several scattered logs can become one understandable incident story. Suggestions that expand surface area instead of advancing that should be pushed back on.
