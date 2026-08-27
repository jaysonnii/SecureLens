import time
from typing import Callable


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int):
        super().__init__(
            "Rate limit exceeded."
        )
        self.retry_after = retry_after


class InMemoryRateLimiter:
    """Fixed-window per-key request limiter.

    Keeps one (window_start, count) pair per key in a plain dict.
    Suitable for a single-process deployment; scaling to multiple
    workers or replicas needs a shared store.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        time_fn: Callable[[], float] = time.monotonic,
    ):
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._time_fn = time_fn
        self._windows: dict[str, tuple[float, int]] = {}

    def tracked_keys(self) -> set[str]:
        return set(self._windows)

    def prune(self) -> None:
        now = self._time_fn()
        self._windows = {
            key: window
            for key, window in self._windows.items()
            if now - window[0] < self._window_seconds
        }

    def check(self, key: str) -> None:
        self.prune()
        now = self._time_fn()
        window_start, count = self._windows.get(
            key,
            (now, 0),
        )

        if now - window_start >= self._window_seconds:
            window_start, count = now, 0

        if count >= self._max_requests:
            retry_after = int(
                self._window_seconds
                - (now - window_start)
            ) + 1
            raise RateLimitExceeded(retry_after)

        self._windows[key] = (window_start, count + 1)
