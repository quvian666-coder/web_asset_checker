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
            "-exclude-tags",
            "dos,brute-force,intrusive,fuzz",
            "-rate-limit",
            str(rate_limit),
            "-concurrency",
            str(concurrency),
            "-bulk-size",
            "2",
            "-jsonl-export",
            str(output_file),
            "-omit-raw",
            "-silent",
        ]
    )
    return command


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
