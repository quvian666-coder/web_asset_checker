from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PathRule:
    path: str
    category: str
    function: str
    keywords: tuple[str, ...] = ()
    enabled: bool = True

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["keywords"] = list(self.keywords)
        return data


DEFAULT_METADATA: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "/admin": ("ADMIN", "后台管理入口", ("admin", "管理后台")),
    "/login": ("LOGIN", "登录入口", ("login", "sign in", "登录")),
    "/manage": ("MANAGEMENT", "系统管理入口", ("manage", "management")),
    "/system": ("MANAGEMENT", "系统管理入口", ("system", "系统管理")),
    "/api": ("API", "API 入口", ("api",)),
    "/swagger-ui.html": ("API_DOCS", "Swagger 接口文档", ("swagger", "api docs")),
    "/swagger/index.html": ("API_DOCS", "Swagger 接口文档", ("swagger", "api docs")),
    "/v2/api-docs": ("API_DOCS", "Swagger 接口定义", ("swagger",)),
    "/doc.html": ("API_DOCS", "接口文档", ("api", "接口文档")),
    "/druid": ("DATABASE_MONITOR", "Druid 监控入口", ("druid",)),
    "/actuator": ("MONITORING", "Spring 管理端点", ("actuator",)),
    "/actuator/env": ("MONITORING", "Spring 环境端点", ("actuator", "environment")),
    "/phpinfo.php": ("DEBUG_INFO", "PHP 调试信息", ("phpinfo",)),
    "/.git/config": ("SOURCE_CONTROL", "Git 配置文件", ("repositoryformatversion",)),
    "/backup.zip": ("BACKUP_FILE", "网站备份文件", ("zip",)),
}

INFERRED_METADATA: tuple[
    tuple[tuple[str, ...], tuple[str, str, tuple[str, ...]]], ...
] = (
    (
        ("/.git", "/.svn", "/.hg"),
        ("SOURCE_CONTROL", "源码/版本控制配置", ("repository", "git", "svn")),
    ),
    (
        ("backup", ".bak", ".sql", ".zip", ".tar", ".tgz", ".7z", "dump"),
        ("BACKUP_FILE", "备份或归档文件", ("backup", "archive", "download")),
    ),
    (
        ("swagger", "openapi", "api-docs", "/docs", "/redoc", "doc.html"),
        ("API_DOCS", "API 接口文档", ("swagger", "openapi", "api docs")),
    ),
    (
        ("druid", "phpmyadmin", "adminer"),
        ("DATABASE_MONITOR", "数据库管理/监控入口", ("druid", "database", "adminer")),
    ),
    (
        ("actuator", "prometheus", "metrics", "monitor", "/health", "/env"),
        ("MONITORING", "系统监控或管理端点", ("actuator", "metrics", "monitor")),
    ),
    (
        ("phpinfo", "debug", "trace", "profiler"),
        ("DEBUG_INFO", "调试或环境信息页面", ("debug", "phpinfo", "trace")),
    ),
    (
        ("login", "signin", "sign-in", "/auth", "/sso"),
        ("LOGIN", "登录或认证入口", ("login", "sign in", "登录")),
    ),
    (
        ("admin", "control-panel"),
        ("ADMIN", "后台管理入口", ("admin", "control panel", "管理后台")),
    ),
    (
        ("manage", "manager", "management", "console", "/system"),
        ("MANAGEMENT", "系统管理入口", ("manage", "management", "console")),
    ),
    (
        ("/api",),
        ("API", "API 入口", ("api",)),
    ),
)

NEXT_CHECK: dict[str, str] = {
    "LOGIN": "检查认证流程、验证码、MFA、会话和退出机制",
    "ADMIN": "检查身份认证、权限隔离和管理功能访问控制",
    "MANAGEMENT": "检查角色权限和管理操作授权",
    "API": "确认接口类型、认证方式和权限边界",
    "API_DOCS": "检查接口文档是否公开及接口是否要求认证",
    "MONITORING": "检查管理端点访问控制和信息暴露",
    "DATABASE_MONITOR": "检查监控入口认证及管理功能访问控制",
    "DEBUG_INFO": "检查版本、路径和环境信息泄露",
    "SOURCE_CONTROL": "仅确认暴露并记录证据，不下载完整仓库",
    "BACKUP_FILE": "仅确认文件存在和访问控制，不下载完整备份",
    "CUSTOM": "根据状态码、标题和跳转地址进行人工确认",
    "UNKNOWN": "根据状态码、标题和跳转地址进行人工确认",
}


def infer_metadata(rule_path: str) -> tuple[str, str, tuple[str, ...]]:
    """为一行一个的简单路径自动生成分类信息。"""
    lowered_path = rule_path.lower()
    exact = DEFAULT_METADATA.get(lowered_path)
    if exact is not None:
        return exact

    for fragments, metadata in INFERRED_METADATA:
        if any(fragment in lowered_path for fragment in fragments):
            return metadata

    return "CUSTOM", "自定义敏感路径", ()


def load_rules(path: Path) -> list[PathRule]:
    rules: list[PathRule] = []
    seen: set[str] = set()
    if not path.is_file():
        return rules

    for line in path.read_text(encoding="utf-8-sig").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        parts = [part.strip() for part in value.split("|")]
        rule_path = "/" + parts[0].lstrip("/")
        if rule_path in seen or "://" in rule_path or rule_path.startswith("//"):
            continue
        default = infer_metadata(rule_path)
        category = (parts[1] if len(parts) > 1 and parts[1] else default[0]).upper()
        function = parts[2] if len(parts) > 2 and parts[2] else default[1]
        keywords = tuple(
            keyword.strip().lower()
            for keyword in (parts[3].split(",") if len(parts) > 3 else default[2])
            if keyword.strip()
        )
        enabled = not (
            len(parts) > 4 and parts[4].lower() in {"0", "false", "off", "disabled"}
        )
        rules.append(PathRule(rule_path, category, function, keywords, enabled))
        seen.add(rule_path)
    return rules


def save_rules(path: Path, rules: list[PathRule]) -> None:
    lines: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if not rule.path.startswith("/") or "://" in rule.path or rule.path.startswith("//"):
            raise ValueError(f"非法站内路径：{rule.path}")
        normalized_path = "/" + rule.path.lstrip("/")
        if normalized_path in seen:
            raise ValueError(f"重复站内路径：{normalized_path}")
        seen.add(normalized_path)
        category = rule.category.strip().upper() or "CUSTOM"
        function = rule.function.strip() or "自定义敏感路径"
        keywords = ",".join(keyword.strip() for keyword in rule.keywords if keyword.strip())
        lines.append(f"{normalized_path}|{category}|{function}|{keywords}|{int(rule.enabled)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def rule_map(rules: list[PathRule]) -> dict[str, PathRule]:
    return {rule.path: rule for rule in rules if rule.enabled}


def classify_result(
    rule: PathRule,
    *,
    state: str,
    status_code: int | None,
    title: str,
) -> dict[str, str]:
    lowered_title = title.lower()
    keyword_match = bool(rule.keywords) and any(keyword in lowered_title for keyword in rule.keywords)

    if state == "CONFIRMED" and keyword_match:
        confidence = "HIGH"
    elif state in {"CONFIRMED", "PROTECTED"}:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    p1_paths = {"/.git/config", "/backup.zip", "/phpinfo.php", "/actuator/env"}
    if state == "CONFIRMED" and rule.path in p1_paths:
        priority = "P1"
    elif rule.category in {
        "LOGIN",
        "ADMIN",
        "MANAGEMENT",
        "API_DOCS",
        "MONITORING",
        "DATABASE_MONITOR",
        "SOURCE_CONTROL",
        "BACKUP_FILE",
        "DEBUG_INFO",
    }:
        priority = "P2"
    else:
        priority = "P3"

    access_state = {
        "CONFIRMED": "ACCESSIBLE",
        "PROTECTED": "AUTH_REQUIRED" if status_code == 401 else "FORBIDDEN",
        "REDIRECTED": "REDIRECTED",
    }.get(state, state)

    return {
        "function": rule.function,
        "category": rule.category,
        "confidence": confidence,
        "priority": priority,
        "access_state": access_state,
        "next_check": NEXT_CHECK.get(rule.category, NEXT_CHECK["UNKNOWN"]),
    }
