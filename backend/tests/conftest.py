import pytest

import app.routers.uploads as uploads


@pytest.fixture(autouse=True)
def disable_rate_limiting_by_default(monkeypatch):
    """Keep the per-IP upload limiter out of unrelated tests.

    The limiter is a process-wide singleton, so without this every
    test that posts to /upload would share one window. Tests that
    exercise the limiter re-enable it explicitly.
    """

    monkeypatch.setattr(uploads, "RATE_LIMIT_ENABLED", False)
    uploads.reset_rate_limiter()
    yield
    uploads.reset_rate_limiter()
