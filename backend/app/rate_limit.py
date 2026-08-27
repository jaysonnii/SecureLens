"""ASGI wiring for the per-IP upload rate limit.

The limit is enforced in middleware rather than as a route dependency:
FastAPI parses the multipart body at the top of the request handler,
before dependencies run, so a dependency-based check only fires after a
flooding client has already uploaded its whole payload. Middleware runs
outside routing, so rejecting here keeps that payload off the wire.
"""

import json

from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import (
    RATE_LIMIT_ENABLED,
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    TRUST_PROXY_HEADERS,
)
from app.services.rate_limiter import (
    InMemoryRateLimiter,
    RateLimitExceeded,
)


RATE_LIMITED_PATHS = frozenset({"/upload"})

rate_limiter = InMemoryRateLimiter(
    max_requests=RATE_LIMIT_MAX_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)


def reset_rate_limiter() -> None:
    """Rebuild the limiter from the current module-level settings.

    Used by tests that override the rate-limit configuration.
    """

    global rate_limiter

    rate_limiter = InMemoryRateLimiter(
        max_requests=RATE_LIMIT_MAX_REQUESTS,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    )


def client_key(request: Request) -> str:
    if TRUST_PROXY_HEADERS:
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

    if request.client is not None:
        return request.client.host

    return "unknown"


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] == "http" and _should_check(scope):
            request = Request(scope)
            try:
                rate_limiter.check(client_key(request))
            except RateLimitExceeded as error:
                await _send_429(send, error.retry_after)
                return

        await self._app(scope, receive, send)


def _should_check(scope: Scope) -> bool:
    if not RATE_LIMIT_ENABLED:
        return False

    if scope.get("method") != "POST":
        return False

    path = scope["path"].rstrip("/") or "/"
    return path in RATE_LIMITED_PATHS


async def _send_429(send: Send, retry_after: int) -> None:
    body = json.dumps(
        {
            "detail": (
                "Rate limit exceeded. Try again in "
                f"{retry_after} seconds."
            )
        }
    ).encode()

    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"retry-after", str(retry_after).encode()),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
        }
    )
