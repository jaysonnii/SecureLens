import pytest

from app.services.rate_limiter import (
    InMemoryRateLimiter,
    RateLimitExceeded,
)


class FakeClock:
    def __init__(self, now: float = 0.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_allows_requests_up_to_the_limit_within_a_window():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(
        max_requests=3,
        window_seconds=60,
        time_fn=clock,
    )

    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")


def test_blocks_the_request_past_the_limit_with_retry_after():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(
        max_requests=2,
        window_seconds=60,
        time_fn=clock,
    )

    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")
    clock.advance(15)

    with pytest.raises(RateLimitExceeded) as error:
        limiter.check("1.2.3.4")

    assert error.value.retry_after == 46


def test_window_resets_after_it_elapses():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(
        max_requests=1,
        window_seconds=60,
        time_fn=clock,
    )

    limiter.check("1.2.3.4")
    clock.advance(60)

    limiter.check("1.2.3.4")


def test_limits_each_key_independently():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(
        max_requests=1,
        window_seconds=60,
        time_fn=clock,
    )

    limiter.check("1.1.1.1")
    limiter.check("2.2.2.2")

    with pytest.raises(RateLimitExceeded):
        limiter.check("1.1.1.1")


def test_prune_drops_only_elapsed_windows():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(
        max_requests=5,
        window_seconds=60,
        time_fn=clock,
    )

    limiter.check("old")
    clock.advance(30)
    limiter.check("fresh")
    clock.advance(31)

    limiter.prune()

    assert limiter.tracked_keys() == {"fresh"}
