from __future__ import annotations

import socket
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx

from main import (
    BoundedHttpClient,
    FindingState,
    ProbeResponse,
    ScanOptions,
    probe_sensitive_path,
    scan_target,
)
from webapp.scope import ScopeGuard, ScopePolicy, ScopeViolation


def policy(**overrides):
    payload = {
        "allowed_domains": ["example.com"],
        "exact_hosts": [],
        "allowed_cidrs": [],
        "allowed_ports": [80, 443],
        "allowed_schemes": ["http", "https"],
        "excluded_domains": [],
        "excluded_cidrs": [],
        "excluded_ports": [],
        "valid_until": None,
    }
    payload.update(overrides)
    return ScopePolicy.from_dict(payload)


class ScopePolicyTests(unittest.TestCase):
    def test_rejects_loopback_link_local_and_metadata(self) -> None:
        item = policy(exact_hosts=["127.0.0.1", "169.254.169.254", "::1"])
        for address in ("127.0.0.1", "169.254.1.2", "169.254.169.254", "::1", "fe80::1"):
            with self.subTest(address=address), self.assertRaises(ScopeViolation):
                item.validate_ip(address)

    def test_private_ip_requires_explicit_allowed_cidr(self) -> None:
        with self.assertRaisesRegex(ScopeViolation, "CIDR"):
            policy().validate_ip("10.2.3.4")
        self.assertEqual(
            str(policy(allowed_cidrs=["10.2.0.0/16"]).validate_ip("10.2.3.4")),
            "10.2.3.4",
        )

    def test_exclusion_wins_over_allow_rule(self) -> None:
        item = policy(excluded_domains=["admin.example.com"], excluded_cidrs=["93.184.216.0/24"])
        with self.assertRaisesRegex(ScopeViolation, "排除域名"):
            item.validate_url_shape("https://admin.example.com/")
        with self.assertRaisesRegex(ScopeViolation, "排除 CIDR"):
            item.validate_ip("93.184.216.34")

    def test_rejects_disallowed_scheme_and_port(self) -> None:
        item = policy(allowed_schemes=["https"], allowed_ports=[443], excluded_ports=[8443])
        with self.assertRaisesRegex(ScopeViolation, "协议"):
            item.validate_url_shape("http://example.com/")
        with self.assertRaisesRegex(ScopeViolation, "端口"):
            item.validate_url_shape("https://example.com:444/")

    def test_rejects_expired_authorization(self) -> None:
        expired = datetime.now(timezone.utc) - timedelta(seconds=1)
        with self.assertRaisesRegex(ScopeViolation, "过期"):
            policy(valid_until=expired.isoformat())

    def test_manual_host_is_exact_when_no_root_domain_exists(self) -> None:
        item = policy(allowed_domains=[], exact_hosts=["app.example.com"])
        item.validate_url_shape("https://app.example.com/login")
        with self.assertRaises(ScopeViolation):
            item.validate_url_shape("https://sub.app.example.com/login")


class ScopeGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_when_any_dns_address_is_private(self) -> None:
        rows = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=rows):
            with self.assertRaisesRegex(ScopeViolation, "私网"):
                await ScopeGuard(policy()).validate_target("https://example.com/")

    async def test_allows_explicit_private_cidr(self) -> None:
        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))]
        with patch("socket.getaddrinfo", return_value=rows):
            target = await ScopeGuard(policy(allowed_cidrs=["10.0.0.0/24"])).validate_target(
                "https://example.com/"
            )
        self.assertEqual(target.addresses, ("10.0.0.8",))

    async def test_dns_failure_has_stable_error_code(self) -> None:
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("missing")):
            with self.assertRaises(ScopeViolation) as raised:
                await ScopeGuard(policy()).validate_target("https://example.com/")
        self.assertEqual(raised.exception.code, "SCOPE_DNS_FAILED")


class RedirectScopeTests(unittest.IsolatedAsyncioTestCase):
    def options(self) -> ScanOptions:
        return ScanOptions(2, 1, 2, 0, True)

    async def test_redirect_to_loopback_is_blocked_before_second_request(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(302, headers={"Location": "http://127.0.0.1/metadata"})

        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        item = policy(exact_hosts=["127.0.0.1"])
        with patch("socket.getaddrinfo", return_value=rows):
            async with BoundedHttpClient(
                self.options(), ScopeGuard(item), transport=httpx.MockTransport(handler)
            ) as client:
                with self.assertRaises(ScopeViolation) as raised:
                    await client.fetch("https://example.com/", follow_redirects=True)
        self.assertEqual(raised.exception.code, "SCOPE_IP_DENIED")
        self.assertEqual(calls, ["https://example.com/"])

    async def test_redirect_to_excluded_domain_is_blocked(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "https://blocked.example.com/"})

        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        item = policy(excluded_domains=["blocked.example.com"])
        with patch("socket.getaddrinfo", return_value=rows):
            async with BoundedHttpClient(
                self.options(), ScopeGuard(item), transport=httpx.MockTransport(handler)
            ) as client:
                with self.assertRaises(ScopeViolation) as raised:
                    await client.fetch("https://example.com/", follow_redirects=True)
        self.assertEqual(raised.exception.code, "SCOPE_DOMAIN_EXCLUDED")

    async def test_relative_redirect_is_followed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/start":
                return httpx.Response(302, headers={"Location": "/final"})
            return httpx.Response(200, content=b"ok")

        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=rows):
            async with BoundedHttpClient(
                self.options(), ScopeGuard(policy()), transport=httpx.MockTransport(handler)
            ) as client:
                response = await client.fetch("https://example.com/start", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.final_url, "https://example.com/final")
        self.assertEqual(response.redirect_count, 1)


class SensitivePathClassificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_skips_paths_when_soft404_baseline_is_unavailable(self) -> None:
        class FakeClient:
            async def fetch(self, url: str, **_: object) -> ProbeResponse:
                if "web-asset-check-" in url:
                    return ProbeResponse(requested_url=url, error="timeout")
                if url.endswith("/.git/config"):
                    return ProbeResponse(
                        requested_url=url,
                        final_url=url,
                        status_code=203,
                        body=b"<title>security alert</title>",
                        response_length=29,
                    )
                return ProbeResponse(
                    requested_url=url,
                    final_url=url,
                    status_code=200,
                    body=b"home",
                    response_length=4,
                )

        result = await scan_target(
            FakeClient(),  # type: ignore[arg-type]
            "https://example.com",
            ("https://example.com",),
            ["/.git/config"],
        )

        self.assertEqual(result.findings, [])
        self.assertIn("软 404 基线不可用", result.error)

    async def test_git_config_requires_git_content_signature(self) -> None:
        class FakeClient:
            async def fetch(self, url: str, **_: object) -> ProbeResponse:
                return ProbeResponse(
                    requested_url=url,
                    final_url=url,
                    status_code=203,
                    headers={"Content-Type": "text/html; charset=UTF-8"},
                    body=b"<html><title>security alert</title></html>",
                    response_length=41,
                )

        baseline = ProbeResponse(
            requested_url="https://example.com/missing",
            final_url="https://example.com/missing",
            status_code=404,
            body=b"not found",
            response_length=9,
        )
        finding = await probe_sensitive_path(
            FakeClient(),  # type: ignore[arg-type]
            "https://example.com",
            "/.git/config",
            [baseline],
        )

        self.assertEqual(finding.state, FindingState.ERROR)
        self.assertIn("Git 配置特征", finding.error)

    async def test_git_config_accepts_real_git_content_signature(self) -> None:
        class FakeClient:
            async def fetch(self, url: str, **_: object) -> ProbeResponse:
                body = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                return ProbeResponse(
                    requested_url=url,
                    final_url=url,
                    status_code=200,
                    headers={"Content-Type": "text/plain"},
                    body=body,
                    response_length=len(body),
                )

        baseline = ProbeResponse(
            requested_url="https://example.com/missing",
            final_url="https://example.com/missing",
            status_code=404,
            body=b"not found",
            response_length=9,
        )
        finding = await probe_sensitive_path(
            FakeClient(),  # type: ignore[arg-type]
            "https://example.com",
            "/.git/config",
            [baseline],
        )

        self.assertEqual(finding.state, FindingState.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
