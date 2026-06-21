from __future__ import annotations

import asyncio
import csv
import json
import os
import re
import signal
import uuid
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from main import (
    BoundedHttpClient,
    FindingState,
    ScanOptions,
    join_root_path,
    origin_from_url,
    scan_target,
)

from .classifier import classify_result, load_rules, rule_map
from .config import AppSettings
from .database import Database, now_sql
from .scope import ScopeGuard, ScopePolicy, ScopeViolation


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def validate_domains(values: list[str]) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = raw.strip().lower().rstrip(".")
        if not value or value.startswith("#"):
            continue
        if not DOMAIN_RE.fullmatch(value):
            raise ValueError(f"非法主域名：{raw}")
        if value not in seen:
            seen.add(value)
            domains.append(value)
    return domains


def find_root_domain(subdomain: str, roots: list[str]) -> str | None:
    subdomain = subdomain.lower().rstrip(".")
    matches = [root for root in roots if subdomain == root or subdomain.endswith(f".{root}")]
    return max(matches, key=len) if matches else None


def _truthy(value: Any) -> bool:
    return value in {1, True, "1", "true", "True", "yes", "YES"}


def parse_oneforall_results(
    result_dir: Path,
    roots: list[str],
    *,
    allowed_schemes: set[str] | frozenset[str] | None = None,
    allowed_ports: set[int] | frozenset[int] | None = None,
) -> list[dict[str, Any]]:
    assets: dict[str, dict[str, Any]] = {}
    schemes = set(allowed_schemes or {"http", "https"})
    ports = set(allowed_ports or {80, 443})
    for json_file in sorted(result_dir.rglob("*.json")):
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8-sig", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            rows = payload.get("data") or payload.get("results") or [payload]
        else:
            rows = payload
        if not isinstance(rows, list):
            continue

        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            subdomain = str(row.get("subdomain") or urlsplit(url).hostname or "").lower().rstrip(".")
            root = find_root_domain(subdomain, roots)
            if not root:
                continue
            urls: list[str] = []
            if url.startswith(("http://", "https://")):
                request_state = row.get("request")
                if request_state is not None and not _truthy(request_state):
                    continue
                urls.append(url.rstrip("/"))
            else:
                host = f"[{subdomain}]" if ":" in subdomain else subdomain
                for port in sorted(ports):
                    for scheme in sorted(schemes):
                        if port == 80 and scheme != "http":
                            continue
                        if port == 443 and scheme != "https":
                            continue
                        default_port = 443 if scheme == "https" else 80
                        suffix = "" if port == default_port else f":{port}"
                        urls.append(f"{scheme}://{host}{suffix}")
            for candidate_url in urls:
                if candidate_url in assets:
                    continue
                parsed = urlsplit(candidate_url)
                assets[candidate_url] = {
                    "root_domain": root,
                    "subdomain": subdomain,
                    "url": candidate_url,
                    "ip": str(row.get("ip") or ""),
                    "port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
                    "status_code": str(row.get("status") or ""),
                    "title": str(row.get("title") or ""),
                    "banner": str(row.get("banner") or ""),
                    "server": "",
                    "cdn": str(row.get("cdn") or ""),
                    "source": str(row.get("module") or row.get("source") or "OneForAll"),
                }
    return list(assets.values())


def manual_assets(urls: list[str], roots: list[str]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in urls:
        url = raw.strip().rstrip("/")
        if not url:
            continue
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"非法 URL：{raw}")
        root = find_root_domain(parsed.hostname, roots) if roots else parsed.hostname
        if roots and not root:
            raise ValueError(f"URL 超出主域名范围：{raw}")
        if url in seen:
            continue
        seen.add(url)
        assets.append(
            {
                "root_domain": root or parsed.hostname,
                "subdomain": parsed.hostname,
                "url": url,
                "ip": "",
                "port": str(parsed.port or ""),
                "status_code": "",
                "title": "",
                "banner": "",
                "server": "",
                "cdn": "",
                "source": "Manual",
            }
        )
    return assets


def build_scope_policy(config: dict[str, Any]) -> ScopePolicy:
    roots = validate_domains(config.get("domains", []))
    manual_urls = [str(item).strip() for item in config.get("manual_urls", []) if str(item).strip()]
    exact_hosts: set[str] = set()
    for raw in manual_urls:
        value = raw if "://" in raw else f"https://{raw}"
        parsed = urlsplit(value)
        if not parsed.hostname:
            raise ValueError(f"非法 URL：{raw}")
        if roots and find_root_domain(parsed.hostname, roots) is None:
            raise ValueError(f"URL 超出主域名范围：{raw}")
        if not roots:
            exact_hosts.add(parsed.hostname)
    requested = dict(config.get("scope", {}))
    requested.update(
        {
            "allowed_domains": roots,
            "exact_hosts": sorted(exact_hosts),
        }
    )
    return ScopePolicy.from_dict(requested)


def write_assets_csv(path: Path, assets: list[dict[str, Any]]) -> None:
    fields = [
        "RootDomain",
        "Subdomain",
        "URL",
        "IP",
        "Port",
        "StatusCode",
        "Title",
        "Banner",
        "Server",
        "CDN",
        "Source",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in assets:
            writer.writerow(
                {
                    "RootDomain": item.get("root_domain", ""),
                    "Subdomain": item.get("subdomain", ""),
                    "URL": item.get("url", ""),
                    "IP": item.get("ip", ""),
                    "Port": item.get("port", ""),
                    "StatusCode": item.get("status_code", ""),
                    "Title": item.get("title", ""),
                    "Banner": item.get("banner", ""),
                    "Server": item.get("server", ""),
                    "CDN": item.get("cdn", ""),
                    "Source": item.get("source", ""),
                }
            )


def write_findings_csv(path: Path, findings: list[dict[str, Any]]) -> None:
    fields = [
        "RootDomain",
        "Subdomain",
        "BaseURL",
        "EndpointURL",
        "Function",
        "Category",
        "StatusCode",
        "AccessState",
        "Confidence",
        "ReviewPriority",
        "Title",
        "Server",
        "X-Powered-By",
        "ContentType",
        "ResponseLength",
        "RedirectURL",
        "Similarity",
        "NextCheck",
        "ScanTime",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in findings:
            writer.writerow(
                {
                    "RootDomain": item["root_domain"],
                    "Subdomain": item["subdomain"],
                    "BaseURL": item["base_url"],
                    "EndpointURL": item["endpoint_url"],
                    "Function": item["function"],
                    "Category": item["category"],
                    "StatusCode": item.get("status_code", ""),
                    "AccessState": item["access_state"],
                    "Confidence": item["confidence"],
                    "ReviewPriority": item["priority"],
                    "Title": item.get("title", ""),
                    "Server": item.get("server", ""),
                    "X-Powered-By": item.get("x_powered_by", ""),
                    "ContentType": item.get("content_type", ""),
                    "ResponseLength": item.get("response_length", 0),
                    "RedirectURL": item.get("redirect_url", ""),
                    "Similarity": item.get("similarity", 0),
                    "NextCheck": item["next_check"],
                    "ScanTime": item["scan_time"],
                }
            )


class TaskManager:
    def __init__(self, settings: AppSettings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self.tasks: dict[str, asyncio.Task[None]] = {}
        self.processes: dict[str, asyncio.subprocess.Process] = {}
        self.worker_semaphore = asyncio.Semaphore(1)

    def create(self, name: str, config: dict[str, Any]) -> str:
        scope_policy = build_scope_policy(config)
        config["scope_snapshot"] = scope_policy.to_dict()
        task_id = uuid.uuid4().hex
        self.database.create_task(task_id, name, config)
        self.tasks[task_id] = asyncio.create_task(self._run(task_id, config))
        return task_id

    def clone(self, source_task_id: str, mode: str = "full") -> str:
        source = self.database.get_task(source_task_id)
        if source is None:
            raise ValueError("源任务不存在")
        if mode not in {"full", "retry", "checker_only"}:
            raise ValueError("不支持的任务复制模式")
        if mode == "retry" and source["status"] not in {"FAILED", "CANCELLED"}:
            raise ValueError("只有失败或已取消任务可以重试")
        config = deepcopy(source["config"])
        config.pop("scope_snapshot", None)
        suffix = {"full": "copy", "retry": "retry", "checker_only": "recheck"}[mode]
        name = f"{source['name']}-{suffix}"[:80]
        config["name"] = name
        config["source_task_id"] = source_task_id
        config["run_mode"] = mode
        if mode == "checker_only":
            assets = self.database.list_assets(source_task_id, 100000)
            urls = [item["url"] for item in assets if item.get("url")]
            if not urls:
                raise ValueError("源任务没有可复用的 Web 资产")
            config["manual_urls"] = urls
            config["max_assets"] = max(int(config.get("max_assets", 500)), len(urls))
            config.setdefault("oneforall", {})["enabled"] = False
            config.setdefault("checker", {})["enabled"] = True
        return self.create(name, config)

    async def cancel(self, task_id: str) -> bool:
        task = self.tasks.get(task_id)
        if task is None or task.done():
            return False
        record = self.database.get_task(task_id)
        task.cancel()
        process = self.processes.get(task_id)
        if process and process.returncode is None:
            await self._terminate_process(process)
        if record and record["status"] == "QUEUED":
            self._event(task_id, "WARN", "排队任务已被用户取消")
            self.database.update_task(
                task_id,
                status="CANCELLED",
                stage="已取消",
                error="用户取消任务",
                finished_at=now_sql(),
            )
        return True

    def _event(self, task_id: str, level: str, message: str) -> None:
        self.database.append_event(task_id, level, ANSI_RE.sub("", message).strip())

    def _progress(
        self,
        task_id: str,
        stage: str,
        progress: int,
        counts: dict[str, int] | None = None,
    ) -> None:
        fields: dict[str, Any] = {"stage": stage, "progress": max(0, min(progress, 100))}
        if counts is not None:
            fields["counts_json"] = json.dumps(counts, ensure_ascii=False)
        self.database.update_task(task_id, **fields)

    async def _run(self, task_id: str, config: dict[str, Any]) -> None:
        async with self.worker_semaphore:
            task_dir = self.settings.data_dir / "tasks" / task_id
            input_dir = task_dir / "input"
            ofa_dir = task_dir / "ofa_results"
            input_dir.mkdir(parents=True, exist_ok=True)
            ofa_dir.mkdir(parents=True, exist_ok=True)
            (task_dir / "config.json").write_text(
                json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            counts = {"roots": 0, "subdomains": 0, "assets": 0, "findings": 0, "p1": 0, "p2": 0}
            self.database.update_task(
                task_id,
                status="RUNNING",
                stage="准备任务",
                progress=1,
                started_at=now_sql(),
            )
            self._event(task_id, "INFO", "任务开始执行")

            try:
                roots = validate_domains(config.get("domains", []))
                manual_urls = [item.strip() for item in config.get("manual_urls", []) if item.strip()]
                if not roots and not manual_urls:
                    raise ValueError("至少需要一个主域名或手工 URL")
                counts["roots"] = len(roots)
                scope_policy = ScopePolicy.from_dict(config["scope_snapshot"])
                scope_guard = ScopeGuard(scope_policy)
                domains_path = input_dir / "domains.txt"
                domains_path.write_text("\n".join(roots) + "\n", encoding="utf-8")
                self._event(task_id, "INFO", f"读取主域名：{len(roots)}")
                self._progress(task_id, "读取目标", 5, counts)

                assets: list[dict[str, Any]] = []
                ofa_config = config.get("oneforall", {})
                if ofa_config.get("enabled", True) and roots:
                    await self._run_oneforall(task_id, domains_path, ofa_dir, ofa_config)
                    self._progress(task_id, "解析 OneForAll 结果", 30, counts)
                    assets.extend(
                        parse_oneforall_results(
                            ofa_dir,
                            roots,
                            allowed_schemes=scope_policy.allowed_schemes,
                            allowed_ports=scope_policy.allowed_ports,
                        )
                    )
                    self._event(task_id, "INFO", f"OneForAll 提取 Web URL：{len(assets)}")

                if manual_urls:
                    assets.extend(manual_assets(manual_urls, roots))

                deduped = {item["url"].rstrip("/"): item for item in assets}
                assets = list(deduped.values())
                scoped_assets: list[dict[str, Any]] = []
                for item in assets:
                    try:
                        target = await scope_guard.validate_target(item["url"])
                    except ScopeViolation as exc:
                        self._event(
                            task_id,
                            "WARN",
                            f"[{exc.code}] 已阻止越界目标：{item['url']}（{exc}）",
                        )
                        continue
                    item["url"] = target.url.rstrip("/")
                    item["ip"] = ",".join(target.addresses)
                    item["port"] = str(target.port)
                    scoped_assets.append(item)
                assets = scoped_assets
                max_assets = int(config.get("max_assets", 500))
                if len(assets) > max_assets:
                    raise RuntimeError(
                        f"发现 {len(assets)} 个资产，超过当前上限 {max_assets}，请调整范围或上限"
                    )
                if not assets:
                    raise RuntimeError("没有得到可用于 Web 检测的 URL")

                counts["subdomains"] = len({item["subdomain"] for item in assets})
                counts["assets"] = len(assets)
                urls_path = task_dir / "oneforall_urls.txt"
                urls_path.write_text(
                    "\n".join(item["url"] for item in assets) + "\n", encoding="utf-8"
                )
                write_assets_csv(task_dir / "assets.csv", assets)
                self.database.replace_assets(task_id, assets)
                self._event(task_id, "INFO", f"去重后 Web 资产：{len(assets)}")
                self._progress(task_id, "Web 资产已整理", 38, counts)

                checker_config = config.get("checker", {})
                findings: list[dict[str, Any]] = []
                if checker_config.get("enabled", True):
                    findings, live_urls = await self._run_checker(
                        task_id, assets, checker_config, counts, scope_policy
                    )
                    if ofa_config.get("enabled", True) and roots:
                        assets = [item for item in assets if item["url"].rstrip("/") in live_urls]
                        counts["assets"] = len(assets)
                        counts["subdomains"] = len({item["subdomain"] for item in assets})
                self.database.replace_findings(task_id, findings)
                self.database.replace_assets(task_id, assets)
                write_findings_csv(task_dir / "result.csv", findings)
                write_assets_csv(task_dir / "assets.csv", self.database.list_assets(task_id, 100000))

                counts["findings"] = len(findings)
                counts["p1"] = sum(item["priority"] == "P1" for item in findings)
                counts["p2"] = sum(item["priority"] == "P2" for item in findings)
                self._progress(task_id, "生成结果", 98, counts)
                self._event(task_id, "SUCCESS", f"扫描完成，敏感入口：{len(findings)}")
                self.database.update_task(
                    task_id,
                    status="SUCCESS",
                    stage="已完成",
                    progress=100,
                    counts_json=json.dumps(counts, ensure_ascii=False),
                    finished_at=now_sql(),
                )
            except asyncio.CancelledError:
                self._event(task_id, "WARN", "任务已被用户取消")
                self.database.update_task(
                    task_id,
                    status="CANCELLED",
                    stage="已取消",
                    error="用户取消任务",
                    finished_at=now_sql(),
                )
                raise
            except Exception as exc:
                self._event(task_id, "ERROR", f"任务失败：{type(exc).__name__}: {exc}")
                self.database.update_task(
                    task_id,
                    status="FAILED",
                    stage="执行失败",
                    error=f"{type(exc).__name__}: {exc}",
                    finished_at=now_sql(),
                )
            finally:
                self.processes.pop(task_id, None)

    async def _run_oneforall(
        self,
        task_id: str,
        domains_path: Path,
        output_dir: Path,
        config: dict[str, Any],
    ) -> None:
        script = self.settings.oneforall_dir / "oneforall.py"
        if not script.is_file():
            raise FileNotFoundError(f"OneForAll 入口不存在：{script}")
        if not self.settings.oneforall_python.is_file():
            raise FileNotFoundError(f"OneForAll Python 不存在：{self.settings.oneforall_python}")

        port = str(config.get("port", "small"))
        if port not in {"small", "medium"}:
            raise ValueError("OneForAll 端口组只允许 small 或 medium")
        command = [
            str(self.settings.oneforall_python),
            str(script),
            "--targets",
            str(domains_path),
            "--brute",
            str(bool(config.get("brute", False))),
            "--dns",
            str(bool(config.get("dns", True))),
            "--req",
            "False",
            "--port",
            port,
            "--alive",
            "False",
            "--fmt",
            "json",
            "--path",
            str(output_dir),
            "--takeover",
            "False",
            "run",
        ]
        self._event(
            task_id,
            "INFO",
            f"启动 OneForAll 域名发现，Web 请求由平台范围校验器执行；端口组：{port}",
        )
        self._progress(task_id, "OneForAll 资产发现", 10)
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=self.settings.oneforall_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=os.name != "nt",
        )
        self.processes[task_id] = process

        async def consume_output() -> int:
            assert process.stdout is not None
            while line := await process.stdout.readline():
                message = line.decode("utf-8", errors="replace").strip()
                if message:
                    self._event(task_id, "INFO", message)
            return await process.wait()

        try:
            return_code = await asyncio.wait_for(
                consume_output(), timeout=float(config.get("timeout", 1800))
            )
        except asyncio.TimeoutError as exc:
            await self._terminate_process(process)
            raise TimeoutError("OneForAll 运行超时") from exc
        if return_code != 0:
            raise RuntimeError(f"OneForAll 返回非零退出码：{return_code}")
        self._event(task_id, "SUCCESS", "OneForAll 执行完成")

    async def _run_checker(
        self,
        task_id: str,
        assets: list[dict[str, Any]],
        config: dict[str, Any],
        counts: dict[str, int],
        scope_policy: ScopePolicy,
    ) -> tuple[list[dict[str, Any]], set[str]]:
        rules = load_rules(self.settings.paths_file)
        rules_by_path = rule_map(rules)
        paths = list(rules_by_path)
        if not paths:
            raise RuntimeError("没有启用的敏感路径规则")

        options = ScanOptions(
            concurrency=int(config.get("concurrency", 10)),
            per_host=int(config.get("per_host", 2)),
            timeout=float(config.get("timeout", 8)),
            retries=int(config.get("retries", 1)),
            verify_tls=not bool(config.get("insecure", False)),
            soft404_threshold=float(config.get("soft404_threshold", 0.85)),
        )
        self._event(
            task_id,
            "INFO",
            f"开始敏感路径检测：{len(assets)} 个资产，{len(paths)} 条规则",
        )
        asset_by_url = {item["url"].rstrip("/"): item for item in assets}
        results = []

        async with BoundedHttpClient(options, ScopeGuard(scope_policy)) as client:
            pending = [
                asyncio.create_task(
                    scan_target(
                        client,
                        item["url"],
                        (item["url"],),
                        paths,
                        options.soft404_threshold,
                    )
                )
                for item in assets
            ]
            completed = 0
            for future in asyncio.as_completed(pending):
                result = await future
                results.append(result)
                completed += 1
                progress = 40 + int(completed / len(pending) * 52)
                self._progress(task_id, f"敏感路径检测 {completed}/{len(pending)}", progress, counts)

        actionable = {FindingState.CONFIRMED, FindingState.PROTECTED, FindingState.REDIRECTED}
        findings: list[dict[str, Any]] = []
        scan_time = datetime.now().astimezone().isoformat(timespec="seconds")

        for result in results:
            source_asset = asset_by_url.get(result.input_url.rstrip("/"), {})
            if result.error.startswith("[SCOPE_"):
                self._event(task_id, "WARN", f"范围校验阻止请求：{result.input_url} {result.error}")
            self.database.update_asset_probe(
                task_id,
                result.input_url.rstrip("/"),
                status_code=result.status_code,
                title=result.title,
                server=result.server,
            )
            if not result.alive:
                continue
            origin = origin_from_url(result.final_url or result.normalized_url)
            for finding in result.findings:
                if finding.state not in actionable:
                    continue
                rule = rules_by_path.get(finding.path)
                if rule is None:
                    continue
                classification = classify_result(
                    rule,
                    state=str(finding.state),
                    status_code=finding.status_code,
                    title=finding.title,
                )
                endpoint_url = join_root_path(origin, finding.path)
                findings.append(
                    {
                        "root_domain": source_asset.get("root_domain", ""),
                        "subdomain": source_asset.get(
                            "subdomain", urlsplit(result.input_url).hostname or ""
                        ),
                        "base_url": result.input_url,
                        "endpoint_url": endpoint_url,
                        **classification,
                        "status_code": finding.status_code,
                        "title": finding.title,
                        "server": finding.server,
                        "x_powered_by": finding.x_powered_by,
                        "content_type": finding.content_type,
                        "response_length": finding.response_length,
                        "redirect_url": finding.location,
                        "similarity": finding.similarity,
                        "scan_time": scan_time,
                    }
                )
        live_urls = {result.input_url.rstrip("/") for result in results if result.alive}
        return findings, live_urls

    async def _terminate_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
        else:
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            if os.name != "nt":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    return
            else:
                process.kill()
            await process.wait()
