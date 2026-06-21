from __future__ import annotations

import argparse
import asyncio
import csv
import re
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from enum import StrEnum
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import httpx


DEFAULT_PATHS = (
    "/admin",
    "/login",
    "/manage",
    "/system",
    "/api",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/v2/api-docs",
    "/doc.html",
    "/druid",
    "/actuator",
    "/actuator/env",
    "/phpinfo.php",
    "/.git/config",
    "/backup.zip",
)

USER_AGENT = "WebAssetChecker/1.0 (authorized-security-testing-only)"
HOME_BODY_LIMIT = 512 * 1024
PATH_BODY_LIMIT = 64 * 1024
SOFT404_THRESHOLD = 0.85


class FindingState(StrEnum):
    CONFIRMED = "CONFIRMED"
    PROTECTED = "PROTECTED"
    REDIRECTED = "REDIRECTED"
    NOT_FOUND = "NOT_FOUND"
    SOFT_404 = "SOFT_404"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class ScanOptions:
    concurrency: int
    per_host: int
    timeout: float
    retries: int
    verify_tls: bool
    soft404_threshold: float = SOFT404_THRESHOLD


@dataclass(slots=True)
class ProbeResponse:
    requested_url: str
    final_url: str = ""
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    response_length: int = 0
    redirect_count: int = 0
    truncated: bool = False
    error: str = ""


@dataclass(slots=True)
class PathFinding:
    path: str
    state: FindingState
    status_code: int | None
    similarity: float = 0.0
    location: str = ""
    title: str = ""
    response_length: int = 0
    server: str = ""
    x_powered_by: str = ""
    content_type: str = ""
    error: str = ""


@dataclass(slots=True)
class AssetResult:
    input_url: str
    normalized_url: str = ""
    alive: bool = False
    status_code: int | None = None
    title: str = ""
    response_length: int = 0
    server: str = ""
    x_powered_by: str = ""
    final_url: str = ""
    findings: list[PathFinding] = field(default_factory=list)
    error: str = ""


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title" and not self.parts:
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data)


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ignored_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript"}:
            self.ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth:
            self.parts.append(data)


def decode_body(body: bytes, content_type: str = "") -> str:
    charset_match = re.search(r"charset\s*=\s*['\"]?([^\s;'\"]+)", content_type, re.I)
    encodings = [charset_match.group(1)] if charset_match else []
    encodings.extend(["utf-8", "gb18030"])

    for encoding in dict.fromkeys(encodings):
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def extract_title(body: bytes, content_type: str = "") -> str:
    lowered_type = content_type.lower()
    if lowered_type and "html" not in lowered_type and "xhtml" not in lowered_type:
        return ""

    parser = _TitleParser()
    try:
        parser.feed(decode_body(body, content_type))
    except Exception:
        return ""
    return " ".join("".join(parser.parts).split())[:200]


def header_value(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value.strip()
    return ""


def normalize_target(value: str) -> tuple[str, ...]:
    value = value.strip()
    if not value:
        raise ValueError("目标为空")

    candidates = (value,) if "://" in value else (f"https://{value}", f"http://{value}")
    normalized: list[str] = []

    for candidate in candidates:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("只支持 http 和 https")
        if not parsed.hostname:
            raise ValueError("缺少有效主机名")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("端口格式无效") from exc
        normalized.append(candidate)

    return tuple(normalized)


def load_targets(path: Path) -> list[tuple[str, tuple[str, ...]]]:
    targets: list[tuple[str, tuple[str, ...]]] = []
    seen: set[tuple[str, ...]] = set()

    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            candidates = normalize_target(value)
        except ValueError as exc:
            print(f"[!] 跳过第 {line_number} 行：{value}（{exc}）")
            continue
        dedupe_key = tuple(item.lower() for item in candidates)
        if dedupe_key not in seen:
            seen.add(dedupe_key)
            targets.append((value, candidates))
    return targets


def load_paths(path: Path) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()

    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "://" in value or value.startswith("//"):
            print(f"[!] 跳过 paths.txt 第 {line_number} 行：只允许站内路径")
            continue
        parts = [part.strip() for part in value.split("|")]
        if len(parts) > 4 and parts[4].lower() in {"0", "false", "off", "disabled"}:
            continue
        value = parts[0]
        value = "/" + value.lstrip("/")
        if value not in seen:
            seen.add(value)
            paths.append(value)
    return paths


def origin_from_url(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{host}{port}"


def join_root_path(origin: str, path: str) -> str:
    return f"{origin.rstrip('/')}/{path.lstrip('/')}"


class BoundedHttpClient:
    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self.global_semaphore = asyncio.Semaphore(options.concurrency)
        self.host_semaphores: dict[str, asyncio.Semaphore] = {}
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "BoundedHttpClient":
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.options.timeout),
            verify=self.options.verify_tls,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        if self.client is not None:
            await self.client.aclose()

    def _host_semaphore(self, url: str) -> asyncio.Semaphore:
        key = origin_from_url(url)
        if key not in self.host_semaphores:
            self.host_semaphores[key] = asyncio.Semaphore(self.options.per_host)
        return self.host_semaphores[key]

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = False,
        max_body_bytes: int = PATH_BODY_LIMIT,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        if self.client is None:
            raise RuntimeError("HTTP 客户端尚未启动")

        last_error = ""
        for attempt in range(self.options.retries + 1):
            try:
                async with self._host_semaphore(url):
                    async with self.global_semaphore:
                        async with self.client.stream(
                            method,
                            url,
                            follow_redirects=follow_redirects,
                            headers=headers,
                        ) as response:
                            body = bytearray()
                            truncated = False

                            if method.upper() != "HEAD":
                                async for chunk in response.aiter_bytes():
                                    remaining = max_body_bytes - len(body)
                                    if remaining <= 0:
                                        truncated = True
                                        break
                                    body.extend(chunk[:remaining])
                                    if len(chunk) > remaining:
                                        truncated = True
                                        break

                            content_length = response.headers.get("Content-Length", "")
                            try:
                                response_length = int(content_length)
                            except ValueError:
                                response_length = len(body)

                            if response_length > len(body) and method.upper() != "HEAD":
                                truncated = truncated or len(body) >= max_body_bytes

                            return ProbeResponse(
                                requested_url=url,
                                final_url=str(response.url),
                                status_code=response.status_code,
                                headers=dict(response.headers),
                                body=bytes(body),
                                response_length=response_length,
                                redirect_count=len(response.history),
                                truncated=truncated,
                            )
            except httpx.RequestError as exc:
                last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
                if attempt < self.options.retries:
                    await asyncio.sleep(0.2 * (attempt + 1))
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
                break

        return ProbeResponse(requested_url=url, error=last_error or "请求失败")


def normalize_page_text(response: ProbeResponse) -> str:
    text = decode_body(response.body, header_value(response.headers, "Content-Type"))
    parser = _TextParser()
    try:
        parser.feed(text)
        text = " ".join(parser.parts)
    except Exception:
        pass

    request_path = urlsplit(response.requested_url).path
    text = text.lower().replace(request_path.lower(), " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:20000]


def response_similarity(current: ProbeResponse, sample: ProbeResponse) -> float:
    if current.status_code != sample.status_code:
        return 0.0

    current_text = normalize_page_text(current)
    sample_text = normalize_page_text(sample)
    if current_text or sample_text:
        body_score = SequenceMatcher(None, current_text, sample_text).ratio()
    else:
        body_score = 1.0

    largest_length = max(current.response_length, sample.response_length, 1)
    length_score = 1.0 - abs(current.response_length - sample.response_length) / largest_length

    current_title = extract_title(current.body, header_value(current.headers, "Content-Type"))
    sample_title = extract_title(sample.body, header_value(sample.headers, "Content-Type"))
    title_score = 1.0 if current_title and current_title == sample_title else 0.0

    current_location = header_value(current.headers, "Location")
    sample_location = header_value(sample.headers, "Location")
    location_score = 1.0 if current_location and current_location == sample_location else 0.0

    return round(
        0.65 * body_score + 0.20 * max(length_score, 0.0) + 0.10 * title_score + 0.05 * location_score,
        4,
    )


async def build_soft404_baseline(client: BoundedHttpClient, origin: str) -> list[ProbeResponse]:
    urls = [join_root_path(origin, f"/web-asset-check-{secrets.token_hex(8)}") for _ in range(2)]
    samples = await asyncio.gather(
        *(client.fetch(url, max_body_bytes=PATH_BODY_LIMIT) for url in urls)
    )
    return [sample for sample in samples if sample.status_code is not None]


def best_soft404_similarity(response: ProbeResponse, samples: list[ProbeResponse]) -> float:
    return max((response_similarity(response, sample) for sample in samples), default=0.0)


def classify_path(
    response: ProbeResponse,
    samples: list[ProbeResponse],
    threshold: float = SOFT404_THRESHOLD,
) -> tuple[FindingState, float]:
    if response.status_code is None:
        return FindingState.ERROR, 0.0
    if response.status_code in {404, 410}:
        return FindingState.NOT_FOUND, 0.0

    similarity = best_soft404_similarity(response, samples)
    if similarity >= threshold:
        return FindingState.SOFT_404, similarity
    if response.status_code in {401, 403}:
        return FindingState.PROTECTED, similarity
    if 200 <= response.status_code < 300:
        return FindingState.CONFIRMED, similarity
    if 300 <= response.status_code < 400:
        return FindingState.REDIRECTED, similarity
    return FindingState.ERROR, similarity


async def probe_sensitive_path(
    client: BoundedHttpClient,
    origin: str,
    path: str,
    samples: list[ProbeResponse],
    soft404_threshold: float = SOFT404_THRESHOLD,
) -> PathFinding:
    url = join_root_path(origin, path)

    if path.lower().endswith(".zip"):
        head_response = await client.fetch(url, method="HEAD", max_body_bytes=0)
        if head_response.status_code is not None and (
            200 <= head_response.status_code < 300 or head_response.status_code in {405, 501}
        ):
            response = await client.fetch(
                url,
                headers={"Range": "bytes=0-4095"},
                max_body_bytes=4096,
            )
        else:
            response = head_response
    else:
        response = await client.fetch(url, max_body_bytes=PATH_BODY_LIMIT)

    state, similarity = classify_path(response, samples, soft404_threshold)
    return PathFinding(
        path=path,
        state=state,
        status_code=response.status_code,
        similarity=similarity,
        location=header_value(response.headers, "Location"),
        title=extract_title(response.body, header_value(response.headers, "Content-Type")),
        response_length=response.response_length,
        server=header_value(response.headers, "Server"),
        x_powered_by=header_value(response.headers, "X-Powered-By"),
        content_type=header_value(response.headers, "Content-Type"),
        error=response.error,
    )


async def scan_target(
    client: BoundedHttpClient,
    raw_target: str,
    candidates: tuple[str, ...],
    paths: list[str],
    soft404_threshold: float = SOFT404_THRESHOLD,
) -> AssetResult:
    result = AssetResult(input_url=raw_target)
    candidate_errors: list[str] = []
    home: ProbeResponse | None = None

    for candidate in candidates:
        response = await client.fetch(
            candidate,
            follow_redirects=True,
            max_body_bytes=HOME_BODY_LIMIT,
        )
        if response.status_code is not None:
            home = response
            break
        candidate_errors.append(f"{candidate}: {response.error}")

    if home is None:
        result.error = " | ".join(candidate_errors) or "未收到 HTTP 响应"
        return result

    result.normalized_url = home.requested_url
    result.alive = True
    result.status_code = home.status_code
    result.title = extract_title(home.body, header_value(home.headers, "Content-Type"))
    result.response_length = home.response_length
    result.server = header_value(home.headers, "Server")
    result.x_powered_by = header_value(home.headers, "X-Powered-By")
    result.final_url = home.final_url

    origin = origin_from_url(home.final_url or home.requested_url)
    samples = await build_soft404_baseline(client, origin)
    findings = await asyncio.gather(
        *(
            probe_sensitive_path(client, origin, path, samples, soft404_threshold)
            for path in paths
        )
    )
    result.findings = list(findings)
    return result


async def scan_all(
    targets: list[tuple[str, tuple[str, ...]]],
    paths: list[str],
    options: ScanOptions,
) -> list[AssetResult]:
    async with BoundedHttpClient(options) as client:
        return list(
            await asyncio.gather(
                *(
                    scan_target(client, raw, candidates, paths, options.soft404_threshold)
                    for raw, candidates in targets
                )
            )
        )


def write_csv(results: list[AssetResult], output: Path) -> None:
    fields = (
        "URL",
        "Alive",
        "StatusCode",
        "Title",
        "ResponseLength",
        "Server",
        "X-Powered-By",
        "RedirectURL",
        "SensitiveFound",
        "SensitiveCount",
        "SensitivePaths",
        "Error",
        "ScanTime",
    )
    actionable_states = {
        FindingState.CONFIRMED,
        FindingState.PROTECTED,
        FindingState.REDIRECTED,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    scan_time = datetime.now().astimezone().isoformat(timespec="seconds")
    with output.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for result in results:
            actionable = [finding for finding in result.findings if finding.state in actionable_states]
            sensitive_paths = "; ".join(
                f"{finding.path}({finding.state}:{finding.status_code or '-'})"
                for finding in actionable
            )
            redirect_url = ""
            if result.final_url and result.final_url.rstrip("/") != result.normalized_url.rstrip("/"):
                redirect_url = result.final_url

            writer.writerow(
                {
                    "URL": result.normalized_url or result.input_url,
                    "Alive": result.alive,
                    "StatusCode": result.status_code if result.status_code is not None else "",
                    "Title": result.title,
                    "ResponseLength": result.response_length,
                    "Server": result.server,
                    "X-Powered-By": result.x_powered_by,
                    "RedirectURL": redirect_url,
                    "SensitiveFound": bool(actionable),
                    "SensitiveCount": len(actionable),
                    "SensitivePaths": sensitive_paths,
                    "Error": result.error,
                    "ScanTime": scan_time,
                }
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web 资产存活与敏感路径检测工具（仅用于已授权目标）"
    )
    parser.add_argument("-u", "--urls", default="urls.txt", help="URL 文件，默认 urls.txt")
    parser.add_argument("-p", "--paths", default="paths.txt", help="敏感路径文件，默认 paths.txt")
    parser.add_argument("-o", "--output", default="result.csv", help="输出 CSV，默认 result.csv")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="全局并发，默认 20")
    parser.add_argument("--per-host", type=int, default=3, help="单主机并发，默认 3")
    parser.add_argument("-t", "--timeout", type=float, default=8.0, help="请求超时秒数，默认 8")
    parser.add_argument("-r", "--retries", type=int, default=1, help="失败重试次数，默认 1")
    parser.add_argument("-k", "--insecure", action="store_true", help="忽略 HTTPS 证书验证")
    parser.add_argument("--soft404", type=float, default=0.85, help="软 404 相似度阈值，默认 0.85")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not 1 <= args.concurrency <= 100:
        parser.error("-c/--concurrency 必须在 1 到 100 之间")
    if not 1 <= args.per_host <= 10:
        parser.error("--per-host 必须在 1 到 10 之间")
    if not 0.5 <= args.timeout <= 120:
        parser.error("-t/--timeout 必须在 0.5 到 120 之间")
    if not 0 <= args.retries <= 3:
        parser.error("-r/--retries 必须在 0 到 3 之间")
    if not 0.5 <= args.soft404 <= 0.99:
        parser.error("--soft404 必须在 0.5 到 0.99 之间")


async def async_main(args: argparse.Namespace) -> int:
    urls_file = Path(args.urls)
    paths_file = Path(args.paths)
    output_file = Path(args.output)

    if not urls_file.is_file():
        print(f"[x] URL 文件不存在：{urls_file}", file=sys.stderr)
        return 1
    if not paths_file.is_file():
        print(f"[x] 路径文件不存在：{paths_file}", file=sys.stderr)
        return 1

    targets = load_targets(urls_file)
    paths = load_paths(paths_file)
    if not targets:
        print("[x] URL 文件中没有有效目标", file=sys.stderr)
        return 1
    if not paths:
        print("[x] 路径文件中没有有效路径", file=sys.stderr)
        return 1

    options = ScanOptions(
        concurrency=args.concurrency,
        per_host=args.per_host,
        timeout=args.timeout,
        retries=args.retries,
        verify_tls=not args.insecure,
        soft404_threshold=args.soft404,
    )

    print(f"[*] 目标数量：{len(targets)}，敏感路径：{len(paths)}")
    print(f"[*] 并发：{options.concurrency}，超时：{options.timeout:g}s，重试：{options.retries}")
    results = await scan_all(targets, paths, options)
    write_csv(results, output_file)

    alive_count = sum(result.alive for result in results)
    finding_count = sum(
        finding.state in {FindingState.CONFIRMED, FindingState.PROTECTED, FindingState.REDIRECTED}
        for result in results
        for finding in result.findings
    )
    print(f"[+] 扫描完成：存活 {alive_count}/{len(results)}，发现或疑似路径 {finding_count}")
    print(f"[+] 结果文件：{output_file.resolve()}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    print("[!] 请仅扫描已获得明确授权的目标。")
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n[x] 用户中止扫描", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
