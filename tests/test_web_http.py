from __future__ import annotations

import re
import unittest

from fastapi.testclient import TestClient

import webapp.app as app_module
from webapp.security import LoginRateLimiter


class FakeDatabase:
    def initialize(self) -> None:
        pass

    def dashboard_stats(self) -> dict[str, int]:
        return {key: 0 for key in ("tasks", "running", "assets", "findings", "p1", "p2", "roots", "subdomains")}

    def list_tasks(self, limit: int = 50):
        return []

    def list_assets(self, task_id=None, limit: int = 500):
        return []

    def list_findings(self, task_id=None, limit: int = 500):
        return []

    def list_finding_cases(self, task_id=None, limit: int = 500):
        return []

    def get_task(self, task_id: str):
        return None

    def get_events(self, task_id: str, after_id: int = 0, limit: int = 500):
        return []


class WebHttpTests(unittest.TestCase):
    def test_login_and_dashboard_render(self) -> None:
        original_database = app_module.database
        app_module.database = FakeDatabase()
        try:
            with TestClient(app_module.app) as client:
                login = client.get("/login")
                self.assertEqual(login.status_code, 200)
                self.assertIn("登录控制台", login.text)
                self.assertIn("frame-ancestors 'none'", login.headers["Content-Security-Policy"])
                self.assertEqual(login.headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(login.headers["Cache-Control"], "no-store")
                token_match = re.search(r'name="csrf_token" value="([^"]+)"', login.text)
                self.assertIsNotNone(token_match)
                response = client.post(
                    "/login",
                    data={
                        "username": app_module.settings.username,
                        "password": app_module.settings.password,
                        "csrf_token": token_match.group(1),
                        "next": "/",
                    },
                    follow_redirects=True,
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn("完整资产发现与敏感入口检测", response.text)
        finally:
            app_module.database = original_database

    def test_login_is_rate_limited(self) -> None:
        original_database = app_module.database
        original_limiter = app_module.login_limiter
        app_module.database = FakeDatabase()
        app_module.login_limiter = LoginRateLimiter(2, 300, 900)
        try:
            with TestClient(app_module.app) as client:
                login = client.get("/login")
                token = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
                payload = {
                    "username": app_module.settings.username,
                    "password": "definitely-wrong",
                    "csrf_token": token,
                    "next": "/",
                }
                self.assertEqual(client.post("/login", data=payload).status_code, 400)
                blocked = client.post("/login", data=payload)
                self.assertEqual(blocked.status_code, 429)
                self.assertEqual(blocked.headers["Retry-After"], "900")
        finally:
            app_module.login_limiter = original_limiter
            app_module.database = original_database


if __name__ == "__main__":
    unittest.main()
