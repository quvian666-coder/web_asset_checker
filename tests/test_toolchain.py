from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from webapp.app import NucleiRequest
from webapp.toolchain import (
    build_nuclei_command,
    discovery_rows_to_assets,
    load_nuclei_routes,
    merge_assets,
    merge_findings,
    parse_dnsx_jsonl,
    parse_nuclei_jsonl,
    parse_subfinder_jsonl,
    resolve_discovery_config,
    select_nuclei_templates,
)


def sample_asset(url: str, source: str) -> dict[str, object]:
    return {
        "root_domain": "example.com",
        "subdomain": "api.example.com",
        "url": url,
        "ip": "93.184.216.34",
        "port": "443",
        "status_code": "",
        "title": "",
        "banner": "",
        "server": "",
        "cdn": "",
        "source": source,
    }


class DiscoveryPresetTests(unittest.TestCase):
    def test_comprehensive_keeps_oneforall_and_enables_pd_chain(self) -> None:
        resolved = resolve_discovery_config("comprehensive", {}, {}, {})
        self.assertTrue(resolved.oneforall_enabled)
        self.assertTrue(resolved.subfinder_enabled)
        self.assertTrue(resolved.dnsx_enabled)

    def test_presets_and_custom_have_stable_meaning(self) -> None:
        quick = resolve_discovery_config("quick", {}, {}, {})
        legacy = resolve_discovery_config("legacy", {}, {}, {})
        custom = resolve_discovery_config(
            "custom",
            {"enabled": False},
            {"enabled": True},
            {"enabled": False},
        )
        self.assertEqual(
            (quick.oneforall_enabled, quick.subfinder_enabled, quick.dnsx_enabled),
            (False, True, True),
        )
        self.assertEqual(
            (legacy.oneforall_enabled, legacy.subfinder_enabled, legacy.dnsx_enabled),
            (True, False, False),
        )
        self.assertEqual(
            (custom.oneforall_enabled, custom.subfinder_enabled, custom.dnsx_enabled),
            (False, True, False),
        )

    def test_nuclei_defaults_are_bounded(self) -> None:
        request = NucleiRequest()
        self.assertFalse(request.enabled)
        self.assertEqual(request.rate_limit, 2)
        self.assertEqual(request.concurrency, 2)


class DiscoveryParserTests(unittest.TestCase):
    def test_subfinder_jsonl_keeps_sources_and_scope_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subfinder.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "host": "api.example.com",
                        "sources": ["crtsh", "hackertarget"],
                    }
                )
                + "\n"
                + json.dumps({"host": "example.com.attacker.test", "source": "crtsh"})
                + "\n",
                encoding="utf-8",
            )
            rows = parse_subfinder_jsonl(path, ["example.com"])
        self.assertEqual(
            rows,
            [
                {
                    "host": "api.example.com",
                    "root_domain": "example.com",
                    "sources": ["crtsh", "hackertarget"],
                }
            ],
        )

    def test_dnsx_jsonl_builds_only_authorized_scheme_port_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dnsx.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "host": "api.example.com",
                        "a": ["93.184.216.34"],
                        "aaaa": ["2001:db8::1"],
                        "cname": ["edge.example.net"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            rows = parse_dnsx_jsonl(
                path,
                ["example.com"],
                allowed_schemes={"https"},
                allowed_ports={443, 8443},
                sources_by_host={"api.example.com": ["Subfinder:crtsh", "OneForAll"]},
            )
        self.assertEqual(
            {row["url"] for row in rows},
            {"https://api.example.com", "https://api.example.com:8443"},
        )
        self.assertEqual(rows[0]["ip"], "93.184.216.34,2001:db8::1")
        self.assertEqual(rows[0]["source"], "OneForAll,Subfinder:crtsh,dnsx")

    def test_merge_assets_combines_sources_and_ip_addresses(self) -> None:
        first = sample_asset("https://api.example.com", "OneForAll")
        second = sample_asset("https://api.example.com/", "Subfinder+dnsx")
        second["ip"] = "2001:db8::1"
        rows = merge_assets([first, second])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "OneForAll,Subfinder+dnsx")
        self.assertEqual(rows[0]["ip"], "93.184.216.34,2001:db8::1")

    def test_subfinder_can_feed_scope_candidates_without_dnsx(self) -> None:
        rows = discovery_rows_to_assets(
            [
                {
                    "host": "api.example.com",
                    "root_domain": "example.com",
                    "sources": ["crtsh"],
                }
            ],
            allowed_schemes={"http", "https"},
            allowed_ports={80, 443},
        )
        self.assertEqual(
            {row["url"] for row in rows},
            {"http://api.example.com", "https://api.example.com"},
        )
        self.assertEqual(rows[0]["source"], "Subfinder:crtsh")


class NucleiAdapterTests(unittest.TestCase):
    def test_command_is_exact_allowlisted_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = build_nuclei_command(
                "nuclei",
                root / "urls.txt",
                root / "out.jsonl",
                [root / "git-config.yaml", root / "swagger-api.yaml"],
                rate_limit=2,
                concurrency=2,
            )
        self.assertIn("-disable-unsigned-templates", command)
        self.assertIn("-disable-redirects", command)
        self.assertIn("-restrict-local-network-access", command)
        self.assertEqual(command[command.index("-rate-limit") + 1], "2")
        self.assertEqual(command[command.index("-concurrency") + 1], "2")
        self.assertEqual(
            command[command.index("-exclude-tags") + 1],
            "dos,brute-force,intrusive,fuzz,oast",
        )
        self.assertEqual(command.count("-t"), 2)

    def test_jsonl_maps_high_severity_to_existing_finding_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nuclei.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "template-id": "git-config",
                        "matcher-name": "git-config",
                        "host": "https://api.example.com",
                        "matched-at": "https://api.example.com/.git/config",
                        "timestamp": "2026-09-13T12:00:00+08:00",
                        "info": {
                            "name": "Git Config Exposure",
                            "severity": "high",
                            "tags": ["exposure", "git"],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            rows = parse_nuclei_jsonl(
                path,
                {
                    "https://api.example.com": sample_asset(
                        "https://api.example.com", "OneForAll"
                    )
                },
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["priority"], "P1")
        self.assertEqual(rows[0]["category"], "NUCLEI")
        self.assertEqual(rows[0]["endpoint_url"], "https://api.example.com/.git/config")
        self.assertIn("git-config", rows[0]["next_check"])

    def test_allowlist_rejects_traversal_and_routes_only_from_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            templates = root / "templates"
            templates.mkdir()
            git_template = templates / "git-config.yaml"
            jenkins_template = templates / "jenkins.yaml"
            git_template.write_text("id: git-config\n", encoding="utf-8")
            jenkins_template.write_text("id: jenkins\n", encoding="utf-8")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(
                "git,.git,source_control|git-config.yaml\n"
                "jenkins|jenkins.yaml\n",
                encoding="utf-8",
            )
            routes = load_nuclei_routes(allowlist, templates)
            selected = select_nuclei_templates(routes, "SOURCE_CONTROL /.git/config")
            self.assertEqual(selected, [git_template.resolve()])

            allowlist.write_text("git|../outside.yaml\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "越界"):
                load_nuclei_routes(allowlist, templates)

    def test_nuclei_confirmation_merges_with_existing_endpoint(self) -> None:
        checker = {
            "endpoint_url": "https://api.example.com/.git/config",
            "priority": "P1",
            "confidence": "MEDIUM",
            "next_check": "人工确认响应内容",
            "category": "SOURCE_CONTROL",
        }
        nuclei = {
            "endpoint_url": "https://api.example.com/.git/config",
            "priority": "P2",
            "confidence": "HIGH",
            "next_check": "Nuclei 模板 git-config 命中",
            "category": "NUCLEI",
        }
        rows = merge_findings([checker], [nuclei])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["priority"], "P1")
        self.assertEqual(rows[0]["confidence"], "HIGH")
        self.assertIn("Nuclei 模板 git-config 命中", rows[0]["next_check"])
        self.assertEqual(rows[0]["category"], "SOURCE_CONTROL")


if __name__ == "__main__":
    unittest.main()
