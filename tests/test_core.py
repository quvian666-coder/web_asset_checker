from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from webapp.app import TaskRequest, app, settings, templates
from webapp.classifier import PathRule, classify_result, load_rules, save_rules
from webapp.database import Database
from webapp.runner import find_root_domain, parse_oneforall_results, validate_domains


class DomainTests(unittest.TestCase):
    def test_validate_domains_deduplicates_and_rejects_urls(self) -> None:
        self.assertEqual(validate_domains(["Example.com", "example.com."]), ["example.com"])
        with self.assertRaises(ValueError):
            validate_domains(["https://example.com"])

    def test_find_root_domain_respects_label_boundary(self) -> None:
        self.assertEqual(find_root_domain("api.dev.example.com", ["example.com"]), "example.com")
        self.assertIsNone(find_root_domain("fakeexample.com", ["example.com"]))


class OneForAllParserTests(unittest.TestCase):
    def test_parser_filters_scope_failed_requests_and_duplicates(self) -> None:
        payload = [
            {
                "subdomain": "api.example.com",
                "url": "https://api.example.com",
                "request": 1,
                "status": 200,
                "title": "Example API",
                "port": 443,
            },
            {
                "subdomain": "api.example.com",
                "url": "https://api.example.com",
                "request": 1,
            },
            {
                "subdomain": "down.example.com",
                "url": "https://down.example.com",
                "request": 0,
            },
            {
                "subdomain": "example.com.attacker.test",
                "url": "https://example.com.attacker.test",
                "request": 1,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            result_file = Path(directory) / "example.com.json"
            result_file.write_text(json.dumps(payload), encoding="utf-8")
            assets = parse_oneforall_results(Path(directory), ["example.com"])
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["url"], "https://api.example.com")
        self.assertEqual(assets[0]["root_domain"], "example.com")


class ClassificationTests(unittest.TestCase):
    def test_accessible_keyword_match_is_high_confidence(self) -> None:
        rule = PathRule("/login", "LOGIN", "登录入口", ("login", "登录"))
        result = classify_result(rule, state="CONFIRMED", status_code=200, title="用户登录")
        self.assertEqual(result["access_state"], "ACCESSIBLE")
        self.assertEqual(result["confidence"], "HIGH")
        self.assertEqual(result["priority"], "P2")

    def test_sensitive_file_accessible_is_p1(self) -> None:
        rule = PathRule("/.git/config", "SOURCE_CONTROL", "Git 配置文件")
        result = classify_result(rule, state="CONFIRMED", status_code=200, title="")
        self.assertEqual(result["priority"], "P1")

    def test_current_rules_file_is_structured(self) -> None:
        rules = load_rules(settings.paths_file)
        self.assertGreaterEqual(len(rules), 15)
        self.assertIn("LOGIN", {rule.category for rule in rules})

    def test_disabled_rule_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.txt"
            save_rules(path, [PathRule("/disabled", "UNKNOWN", "禁用规则", (), False)])
            rules = load_rules(path)
        self.assertEqual(len(rules), 1)
        self.assertFalse(rules[0].enabled)

    def test_plain_paths_are_normalized_and_automatically_classified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.txt"
            path.write_text(
                "# 一行一个路径\n"
                "signin\n"
                "/v3/api-docs\n"
                "/internal/status\n",
                encoding="utf-8",
            )
            rules = {rule.path: rule for rule in load_rules(path)}

        self.assertEqual(rules["/signin"].category, "LOGIN")
        self.assertEqual(rules["/v3/api-docs"].category, "API_DOCS")
        self.assertEqual(rules["/internal/status"].category, "CUSTOM")
        self.assertEqual(rules["/internal/status"].function, "自定义敏感路径")

    def test_structured_rule_overrides_automatic_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.txt"
            path.write_text(
                "/signin|ADMIN|指定管理入口|control panel|1\n",
                encoding="utf-8",
            )
            rule = load_rules(path)[0]

        self.assertEqual(rule.category, "ADMIN")
        self.assertEqual(rule.function, "指定管理入口")
        self.assertEqual(rule.keywords, ("control panel",))


class WebAppShapeTests(unittest.TestCase):
    def test_all_templates_compile(self) -> None:
        for template_name in templates.env.list_templates():
            templates.get_template(template_name)

    def test_api_routes_exist(self) -> None:
        paths = {route.path for route in app.routes}
        self.assertIn("/api/tasks", paths)
        self.assertIn("/api/tasks/{task_id}/events", paths)
        self.assertIn("/api/rules", paths)

    def test_task_request_validates_parameter_ranges(self) -> None:
        request = TaskRequest(
            name="test",
            domains=["example.com"],
            authorization_confirmed=True,
        )
        self.assertEqual(request.checker.concurrency, 10)
        self.assertEqual(request.oneforall.port, "small")

    def test_mysql_database_name_is_restricted(self) -> None:
        with self.assertRaises(ValueError):
            Database(host="127.0.0.1", port=3306, user="u", password="p", database="bad-name")


if __name__ == "__main__":
    unittest.main()
