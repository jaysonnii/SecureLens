import pytest

import app.rate_limit as rate_limit


@pytest.fixture(autouse=True)
def disable_rate_limiting_by_default(monkeypatch):
    """Keep the per-IP upload limiter out of unrelated tests.

    The limiter is a process-wide singleton, so without this every
    test that posts to /upload would share one window. Tests that
    exercise the limiter re-enable it explicitly.
    """

    monkeypatch.setattr(rate_limit, "RATE_LIMIT_ENABLED", False)
    rate_limit.reset_rate_limiter()
    yield
    rate_limit.reset_rate_limiter()
