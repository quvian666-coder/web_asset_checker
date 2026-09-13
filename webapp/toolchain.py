from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    oneforall_enabled: bool
    subfinder_enabled: bool
    dnsx_enabled: bool


@dataclass(frozen=True, slots=True)
class NucleiRoute:
    selectors: tuple[str, ...]
    template: Path


def resolve_discovery_config(
    preset: str,
    oneforall: dict[str, Any],
    subfinder: dict[str, Any],
    dnsx: dict[str, Any],
) -> DiscoveryConfig:
    presets = {
        "quick": DiscoveryConfig(False, True, True),
        "comprehensive": DiscoveryConfig(True, True, True),
        "legacy": DiscoveryConfig(True, False, False),
    }
    if preset in presets:
        return presets[preset]
    if preset != "custom":
        raise ValueError("未知资产发现模式")
    return DiscoveryConfig(
        bool(oneforall.get("enabled", True)),
        bool(subfinder.get("enabled", False)),
        bool(dnsx.get("enabled", False)),
    )


def _root_for_host(host: str, roots: list[str]) -> str | None:
    normalized = host.lower().rstrip(".")
    matches = [root for root in roots if normalized == root or normalized.endswith(f".{root}")]
    return max(matches, key=len) if matches else None


def _jsonl(path: Path):
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
    except OSError:
        return
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            yield value


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _ordered_unique(values: list[str], *, dnsx_last: bool = False) -> list[str]:
    unique = list(dict.fromkeys(item.strip() for item in values if item and item.strip()))
    if not dnsx_last:
        return unique

    def source_rank(item: str) -> tuple[int, str]:
        lowered = item.lower()
        if lowered.startswith("oneforall"):
            return (0, lowered)
        if lowered.startswith("subfinder"):
            return (1, lowered)
        if lowered == "dnsx":
            return (9, lowered)
        return (5, lowered)

    return sorted(unique, key=source_rank)


def parse_subfinder_jsonl(path: Path, roots: list[str]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for payload in _jsonl(path) or ():
        host = str(payload.get("host") or payload.get("input") or "").lower().rstrip(".")
        root = _root_for_host(host, roots)
        if not root:
            continue
        sources = _string_list(payload.get("sources")) or _string_list(payload.get("source"))
        prefixed = [source if source.startswith("Subfinder") else source for source in sources]
        current = rows.setdefault(
            host,
            {"host": host, "root_domain": root, "sources": []},
        )
        current["sources"] = _ordered_unique(current["sources"] + prefixed)
    return list(rows.values())


def _candidate_urls(host: str, schemes: set[str], ports: set[int]) -> list[tuple[str, int]]:
    candidates: list[tuple[str, int]] = []
    display_host = f"[{host}]" if ":" in host else host
    for port in sorted(ports):
        for scheme in sorted(schemes):
            if port == 80 and scheme != "http":
                continue
            if port == 443 and scheme != "https":
                continue
            default_port = 443 if scheme == "https" else 80
            suffix = "" if port == default_port else f":{port}"
            candidates.append((f"{scheme}://{display_host}{suffix}", port))
    return candidates


def parse_dnsx_jsonl(
    path: Path,
    roots: list[str],
    *,
    allowed_schemes: set[str] | frozenset[str],
    allowed_ports: set[int] | frozenset[int],
    sources_by_host: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    sources_by_host = sources_by_host or {}
    for payload in _jsonl(path) or ():
        host = str(payload.get("host") or payload.get("input") or "").lower().rstrip(".")
        root = _root_for_host(host, roots)
        if not root:
            continue
        addresses = _ordered_unique(
            _string_list(payload.get("a")) + _string_list(payload.get("aaaa"))
        )
        cnames = _ordered_unique(_string_list(payload.get("cname")))
        sources = _ordered_unique(sources_by_host.get(host, []) + ["dnsx"], dnsx_last=True)
        for url, port in _candidate_urls(host, set(allowed_schemes), set(allowed_ports)):
            assets.append(
                {
                    "root_domain": root,
                    "subdomain": host,
                    "url": url,
                    "ip": ",".join(addresses),
                    "port": str(port),
                    "status_code": "",
                    "title": "",
                    "banner": "",
                    "server": "",
                    "cdn": ",".join(cnames),
                    "source": ",".join(sources),
                }
            )
    return assets


def discovery_rows_to_assets(
    rows: list[dict[str, Any]],
    *,
    allowed_schemes: set[str] | frozenset[str],
    allowed_ports: set[int] | frozenset[int],
) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for row in rows:
        host = str(row.get("host") or "").lower().rstrip(".")
        root = str(row.get("root_domain") or "")
        if not host or not root:
            continue
        raw_sources = _string_list(row.get("sources"))
        sources = [
            source if source.lower().startswith("subfinder") else f"Subfinder:{source}"
            for source in raw_sources
        ] or ["Subfinder"]
        for url, port in _candidate_urls(host, set(allowed_schemes), set(allowed_ports)):
            assets.append(
                {
                    "root_domain": root,
                    "subdomain": host,
                    "url": url,
                    "ip": "",
                    "port": str(port),
                    "status_code": "",
                    "title": "",
                    "banner": "",
                    "server": "",
                    "cdn": "",
                    "source": ",".join(_ordered_unique(sources, dnsx_last=True)),
                }
            )
    return assets


def merge_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in assets:
        key = str(item.get("url", "")).rstrip("/")
        if not key:
            continue
        if key not in merged:
            merged[key] = dict(item, url=key)
            continue
        current = merged[key]
        for field in ("source", "ip"):
            values = _string_list(current.get(field)) + _string_list(item.get(field))
            expanded = [part.strip() for value in values for part in value.split(",")]
            current[field] = ",".join(_ordered_unique(expanded, dnsx_last=field == "source"))
        for field in ("status_code", "title", "banner", "server", "cdn"):
            if not current.get(field) and item.get(field):
                current[field] = item[field]
    return list(merged.values())


def build_nuclei_command(
    binary: str,
    targets_file: Path,
    output_file: Path,
    templates: list[Path],
    *,
    rate_limit: int,
    concurrency: int,
) -> list[str]:
    if not templates:
        raise ValueError("Nuclei 模板白名单为空")
    command = [binary, "-list", str(targets_file)]
    for template in templates:
        command.extend(["-t", str(template)])
    command.extend(
        [
            "-type",
            "http",
            "-disable-unsigned-templates",
            "-disable-redirects",
            "-restrict-local-network-access",
            "-no-interactsh",
            "-exclude-tags",
            "dos,brute-force,intrusive,fuzz,oast",
            "-rate-limit",
            str(rate_limit),
            "-concurrency",
            str(concurrency),
            "-bulk-size",
            "2",
            "-jsonl-export",
            str(output_file),
            "-omit-raw",
            "-disable-update-check",
            "-response-size-read",
            "1048576",
            "-silent",
        ]
    )
    return command


def load_nuclei_routes(allowlist_file: Path, templates_dir: Path) -> list[NucleiRoute]:
    try:
        lines = allowlist_file.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise FileNotFoundError(f"Nuclei 模板白名单不可读：{allowlist_file}") from exc
    root = templates_dir.resolve()
    routes: list[NucleiRoute] = []
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        selector_text, separator, relative_text = line.partition("|")
        selectors = tuple(
            dict.fromkeys(
                item.strip().lower() for item in selector_text.split(",") if item.strip()
            )
        )
        relative = Path(relative_text.strip())
        if not separator or not selectors or not relative_text.strip():
            raise ValueError(f"Nuclei 白名单第 {number} 行格式错误")
        if relative.is_absolute() or relative.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError(f"Nuclei 白名单第 {number} 行模板路径非法")
        template = (root / relative).resolve()
        if not template.is_relative_to(root):
            raise ValueError(f"Nuclei 白名单第 {number} 行模板路径越界")
        if not template.is_file():
            raise FileNotFoundError(f"Nuclei 白名单模板不存在：{relative.as_posix()}")
        routes.append(NucleiRoute(selectors, template))
    if not routes:
        raise ValueError("Nuclei 模板白名单为空")
    return routes


def select_nuclei_templates(routes: list[NucleiRoute], evidence: str) -> list[Path]:
    normalized = evidence.lower()
    selected: list[Path] = []
    for route in routes:
        if any(selector in normalized for selector in route.selectors):
            selected.append(route.template)
    return list(dict.fromkeys(selected))


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        return value.rstrip("/")
    default = (parsed.scheme == "http" and parsed.port == 80) or (
        parsed.scheme == "https" and parsed.port == 443
    )
    port = "" if parsed.port is None or default else f":{parsed.port}"
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def parse_nuclei_jsonl(
    path: Path,
    assets_by_url: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    priority_by_severity = {
        "critical": "P1",
        "high": "P1",
        "medium": "P2",
        "low": "P3",
        "info": "P3",
        "unknown": "P3",
    }
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for payload in _jsonl(path) or ():
        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        matched_at = str(payload.get("matched-at") or payload.get("host") or "").strip()
        base_url = _origin(str(payload.get("host") or matched_at))
        source_asset = assets_by_url.get(base_url.rstrip("/"), {})
        template_id = str(payload.get("template-id") or "unknown-template")
        key = (template_id, matched_at)
        if not matched_at or key in seen:
            continue
        seen.add(key)
        severity = str(info.get("severity") or "unknown").lower()
        name = str(info.get("name") or template_id)
        tags = ", ".join(_string_list(info.get("tags")))
        findings.append(
            {
                "root_domain": source_asset.get("root_domain", ""),
                "subdomain": source_asset.get("subdomain", urlsplit(base_url).hostname or ""),
                "base_url": base_url,
                "endpoint_url": matched_at,
                "function": name,
                "category": "NUCLEI",
                "access_state": "NUCLEI_MATCH",
                "confidence": "HIGH",
                "priority": priority_by_severity.get(severity, "P3"),
                "status_code": "",
                "title": name,
                "server": "",
                "x_powered_by": "",
                "content_type": "",
                "response_length": 0,
                "redirect_url": "",
                "similarity": 0,
                "next_check": (
                    f"人工复核 Nuclei 模板 {template_id} 命中，确认实际影响和修复状态"
                    + (f"；标签：{tags}" if tags else "")
                ),
                "scan_time": str(payload.get("timestamp") or ""),
            }
        )
    return findings


def merge_findings(
    existing: list[dict[str, Any]],
    additional: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged = [dict(item) for item in existing]
    by_endpoint = {
        str(item.get("endpoint_url") or "").rstrip("/").lower(): item
        for item in merged
        if item.get("endpoint_url")
    }
    priority_rank = {"P1": 1, "P2": 2, "P3": 3}
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for item in additional:
        key = str(item.get("endpoint_url") or "").rstrip("/").lower()
        current = by_endpoint.get(key)
        if current is None:
            copy = dict(item)
            merged.append(copy)
            if key:
                by_endpoint[key] = copy
            continue
        if priority_rank.get(str(item.get("priority")), 99) < priority_rank.get(
            str(current.get("priority")), 99
        ):
            current["priority"] = item["priority"]
        if confidence_rank.get(str(item.get("confidence")), 0) > confidence_rank.get(
            str(current.get("confidence")), 0
        ):
            current["confidence"] = item["confidence"]
        notes = [str(current.get("next_check") or ""), str(item.get("next_check") or "")]
        current["next_check"] = "；".join(dict.fromkeys(note for note in notes if note))
    return merged
