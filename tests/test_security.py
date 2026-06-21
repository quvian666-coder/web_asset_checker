from __future__ import annotations

import unittest

from webapp.security import LoginRateLimiter


class LoginRateLimiterTests(unittest.TestCase):
    def test_blocks_after_threshold_and_resets(self) -> None:
        limiter = LoginRateLimiter(max_attempts=2, window_seconds=60, block_seconds=120)
        self.assertEqual(limiter.record_failure("ip:user", now=10), 0)
        self.assertEqual(limiter.record_failure("ip:user", now=11), 120)
        self.assertEqual(limiter.check("ip:user", now=12), 119)
        limiter.reset("ip:user")
        self.assertEqual(limiter.check("ip:user", now=12), 0)

    def test_old_failures_leave_window(self) -> None:
        limiter = LoginRateLimiter(max_attempts=2, window_seconds=10, block_seconds=30)
        limiter.record_failure("ip:user", now=1)
        self.assertEqual(limiter.record_failure("ip:user", now=12), 0)


if __name__ == "__main__":
    unittest.main()
