from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque

from starlette.responses import Response


CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    )
)


class LoginRateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int, block_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        attempts = self._attempts[key]
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if not attempts:
            self._attempts.pop(key, None)

    def check(self, key: str, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            blocked_until = self._blocked_until.get(key, 0.0)
            if blocked_until > current:
                return max(1, math.ceil(blocked_until - current))
            self._blocked_until.pop(key, None)
            self._prune(key, current)
            return 0

    def record_failure(self, key: str, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._prune(key, current)
            attempts = self._attempts[key]
            attempts.append(current)
            if len(attempts) < self.max_attempts:
                return 0
            self._blocked_until[key] = current + self.block_seconds
            attempts.clear()
            return self.block_seconds

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
            self._blocked_until.pop(key, None)


def apply_security_headers(response: Response, *, sensitive: bool) -> Response:
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    if sensitive:
        response.headers["Cache-Control"] = "no-store"
        response.headers.setdefault("Pragma", "no-cache")
    return response
