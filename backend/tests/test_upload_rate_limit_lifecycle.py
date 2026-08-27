"""Empirical check: does the rate-limit dependency run before FastAPI
parses the multipart body?

If a rate-limited client's request is rejected without the ASGI
``receive`` callable ever being awaited, the body was never pulled off
the wire and the limit does its job. If ``receive`` is awaited before
the 429, the client uploads its whole payload first and the limit is
mostly cosmetic.
"""

import asyncio

import app.rate_limit as rate_limit
from app.main import create_app


BOUNDARY = "----lifecycleprobe"

MULTIPART_BODY = (
    f"--{BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="file"; '
    'filename="probe.log"\r\n'
    "Content-Type: text/plain\r\n\r\n"
    "failed login for administrator\r\n"
    f"--{BOUNDARY}--\r\n"
).encode()


def _run_upload_request():
    app = create_app()

    state = {"receive_awaited": False}

    async def receive():
        state["receive_awaited"] = True
        return {
            "type": "http.request",
            "body": MULTIPART_BODY,
            "more_body": False,
        }

    sent = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/upload",
        "raw_path": b"/upload",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"testserver"),
            (
                b"content-type",
                f"multipart/form-data; boundary={BOUNDARY}".encode(),
            ),
            (b"content-length", str(len(MULTIPART_BODY)).encode()),
        ],
        "client": ("ratelimited-client", 54321),
        "server": ("testserver", 80),
    }

    asyncio.run(app(scope, receive, send))

    start = next(
        m for m in sent if m["type"] == "http.response.start"
    )
    return start["status"], state["receive_awaited"]


def test_rate_limited_upload_is_rejected_before_the_body_is_read(
    monkeypatch,
):
    monkeypatch.setattr(rate_limit, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(rate_limit, "RATE_LIMIT_MAX_REQUESTS", 1)
    monkeypatch.setattr(rate_limit, "RATE_LIMIT_WINDOW_SECONDS", 60)
    monkeypatch.setattr(rate_limit, "TRUST_PROXY_HEADERS", False)
    rate_limit.reset_rate_limiter()

    # Use up the one allowed request for this client key.
    rate_limit.rate_limiter.check("ratelimited-client")

    status, receive_awaited = _run_upload_request()

    assert status == 429
    assert receive_awaited is False, (
        "multipart body was pulled off the wire before the "
        "rate-limit check rejected the request"
    )
