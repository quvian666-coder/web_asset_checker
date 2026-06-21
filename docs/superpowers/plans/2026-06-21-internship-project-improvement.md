# Web Asset Console 实习项目精简改进 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 保留现有可用 MVP，只实现扫描范围安全、生产部署安全、结果复测管理三个高价值闭环，把项目提升为可解释、可测试、适合实习简历展示的安全测试平台。

**Architecture:** 扫描任务继续使用现有 FastAPI、`TaskManager`、MySQL 和 SSE 架构。新增纯 Python `ScopeGuard` 作为所有平台 HTTP 请求的唯一出口；生产部署复用现有 Nginx 和 systemd 模板；扫描原始结果继续保存在 `findings`，新增跨任务聚合的 `finding_cases` 和状态事件表承载复测流程。

**Tech Stack:** Python 3.11+、FastAPI、httpx、PyMySQL、Jinja2、原生 JavaScript、Nginx、systemd；不新增第三方 Python 依赖。

---

## 1. 基于当前代码的修正结论

以下能力已经存在，不进入重写范围（已有取消、SSE、CSV 和软 404 均保留）：

- 任务取消：`webapp/runner.py:238-256` 和 `webapp/app.py:314-318` 已实现。
- SSE 实时日志与进度：`webapp/app.py:321-357`、`webapp/static/task.js:1-72` 已实现。
- `assets.csv`、`result.csv`：`webapp/runner.py:138-221` 生成，`webapp/app.py:370-378` 下载。
- 软 404：`main.py:391-421` 已按主机生成两个随机路径，并综合状态码、正文、长度、标题和跳转地址。
- 手工 URL：`webapp/runner.py:102-135` 已支持“不填主域名时单独检测；填写后必须属于主域名范围”。只需修正文案。
- 基础部署模板：`deploy/web-asset-console.service` 已使用 `webasset` 用户，`deploy/nginx-web-asset-console.conf` 已提供 HTTPS 反向代理；当前服务器尚未按模板迁移。

因此不做任务系统重写、不重做 CSV、不重做软 404，也不把页面文案问题误判为后端逻辑缺陷。

## 2. 本轮范围

### 必须完成的三个闭环

1. **扫描范围安全闭环**：任务范围快照 → 请求前校验 → DNS 解析后校验 → 重定向逐跳校验 → 拒绝原因进入任务事件。
2. **生产部署安全闭环**：HTTPS 入口 → Uvicorn 仅回环监听 → 非 root systemd 服务 → 强密码/安全 Cookie → 登录限速和响应头自动测试。
3. **结果复测闭环**：扫描 observation → 跨任务 case 聚合 → 负责人/状态/备注/标签/证据摘要 → 状态变更历史和最近复测时间。

### 完成前三项后再做

- 失败任务重试、复制任务、仅复用历史资产执行路径检测。
- 模块参数联动、规则即时校验、空状态入口和移动导航无障碍。

### 本轮明确不做

- 暂停和断点续跑、MFA、完整 RBAC、PDF、定时任务、邮件/Webhook。
- 页面截图、favicon hash、大规模服务端分页、Nuclei 自动扫描。
- 扫描差异对比；`finding_cases` 会为以后实现差异功能提供稳定指纹基础。

## 3. 文件结构与职责

### 新增文件

- `webapp/scope.py`：范围策略、URL 规范化、IP/CIDR 判断、DNS 校验和错误码。
- `webapp/security.py`：登录滑动窗口限速器和统一安全响应头。
- `webapp/findings.py`：稳定指纹、复测状态枚举和状态更新校验。
- `webapp/static/findings.js`：复测编辑弹窗、PATCH 请求和页面状态更新。
- `tests/test_scope.py`：范围、DNS、端口、协议、排除项、过期和重定向测试。
- `tests/test_findings.py`：指纹稳定性和复测状态测试。
- `tests/test_database_mysql.py`：使用独立测试库验证迁移、case upsert 和状态历史。

### 修改文件

- `main.py`：让 `BoundedHttpClient` 强制使用 `ScopeGuard` 并手动处理重定向；CLI 同样使用范围策略。
- `webapp/app.py`：新增范围请求模型、复测 API、安全头中间件和登录限速。
- `webapp/runner.py`：创建任务范围快照、记录范围拒绝事件、限制 OneForAll 绕过路径、聚合 finding case。
- `webapp/database.py`：执行版本化迁移，新增 case、状态事件和查询更新方法。
- `webapp/config.py`、`.env.example`：新增可信代理、登录限速和生产安全配置。
- `webapp/__main__.py`：生产模式只信任 `127.0.0.1` 反向代理。
- `webapp/templates/dashboard.html`、`webapp/static/app.js`：范围字段、准确文案和模块参数联动。
- `webapp/templates/findings.html`、`webapp/templates/partials/findings_table.html`：case 状态、负责人和复测编辑入口。
- `webapp/templates/base.html`、`webapp/templates/assets.html`、`webapp/templates/task_detail.html`：移除 CSP 不允许的内联事件/样式并补 ARIA。
- `webapp/static/style.css`：复测弹窗、菜单遮罩和空状态样式。
- `deploy/web-asset-console.service`、`deploy/nginx-web-asset-console.conf`：加强 systemd 沙箱、HTTP 跳转和 HTTPS 安全头。
- `tests/test_core.py`、`tests/test_web_http.py`：补充 API 形状、文案、安全头和限速回归测试。
- `README.md`、`PROJECT_GUIDE.md`：同步真实能力、部署方式和安全边界。

## 4. 闭环一：扫描范围安全

### Task 1：定义不可变范围策略

**Files:**
- Create: `webapp/scope.py`
- Modify: `webapp/app.py:65-94`
- Test: `tests/test_scope.py`

- [ ] **Step 1: 先写范围策略失败测试**

测试类命名为 `ScopePolicyTests`，测试方法依次为
`test_rejects_loopback_link_local_and_metadata`、
`test_private_ip_requires_explicit_allowed_cidr`、
`test_exclusion_wins_over_allow_rule`、
`test_rejects_disallowed_scheme_and_port`、
`test_rejects_expired_authorization`、
`test_manual_host_is_exact_when_no_root_domain_exists`。

Run in PowerShell:

```powershell
Set-Location 'D:\桌面\python渗透测试工具\web_asset_checker'
python -m unittest tests.test_scope.ScopePolicyTests -v
```

Expected: FAIL，原因是 `webapp.scope` 尚不存在。

- [ ] **Step 2: 实现 `ScopePolicy` 与明确错误码**

公共接口固定为 `ScopeViolation(code, message)`、
`ScopePolicy.from_dict(payload)`、`ScopePolicy.validate_url_shape(url)`、
`ScopePolicy.validate_ip(address)` 和 `ScopePolicy.to_dict()`。
`ScopePolicy` 是 `frozen=True, slots=True` 的 dataclass，字段为
`allowed_domains`、`allowed_cidrs`、`allowed_ports`、`allowed_schemes`、
`excluded_domains`、`excluded_cidrs`、`excluded_ports`、`valid_until`。

固定拒绝 `localhost`、`*.localhost`、`127.0.0.0/8`、`::1/128`、`169.254.0.0/16`、`fe80::/10`、unspecified、multicast、reserved，以及显式元数据地址 `169.254.169.254`、`100.100.100.200`、`fd00:ec2::254`。RFC1918 和 IPv6 ULA 默认拒绝，只有地址落入 `allowed_cidrs` 时允许；固定拒绝地址不能被 CIDR 放行。

允许规则和排除规则都按 DNS label 边界匹配，`example.com.attacker.test` 不能命中 `example.com`；排除规则优先。

- [ ] **Step 3: 在请求模型中保存范围快照**

在 `webapp/app.py` 增加：

```python
class ScopeRequest(BaseModel):
    allowed_cidrs: list[str] = Field(default_factory=list, max_length=100)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443], max_length=100)
    allowed_schemes: list[Literal["http", "https"]] = Field(
        default_factory=lambda: ["http", "https"]
    )
    excluded_domains: list[str] = Field(default_factory=list, max_length=500)
    excluded_cidrs: list[str] = Field(default_factory=list, max_length=100)
    excluded_ports: list[int] = Field(default_factory=list, max_length=100)
    valid_until: datetime | None = None
```

`TaskRequest` 增加 `scope: ScopeRequest`。`TaskManager._run()` 根据 `domains` 和手工 URL 主机生成 `allowed_domains`，再调用 `ScopePolicy.from_dict()`；最终策略继续保存在现有 `tasks.config_json` 和任务目录 `config.json`，无需为范围快照新增数据库表。

- [ ] **Step 4: 运行测试并提交**

Expected: `ScopePolicyTests` 全部 PASS。

Suggested commit: `feat(scope): add immutable task scope policy`

### Task 2：DNS 解析后复检

**Files:**
- Modify: `webapp/scope.py`
- Test: `tests/test_scope.py`

- [ ] **Step 1: 写 DNS 失败测试**

使用 `unittest.mock.patch("socket.getaddrinfo")`，覆盖：同一域名解析出公有地址和私有地址时整体拒绝；A/AAAA 均校验；解析失败返回 `SCOPE_DNS_FAILED`；显式授权的 RFC1918 CIDR 可通过。

- [ ] **Step 2: 实现异步解析接口**

`ValidatedTarget` 使用不可变 dataclass，字段为 `url`、`host`、`port`、
`addresses`。`ScopeGuard(policy).validate_target(url)` 是异步方法：先调用
`validate_url_shape()`，再通过 `asyncio.to_thread(socket.getaddrinfo)` 解析，
去重全部 A/AAAA 地址并逐一调用 `validate_ip()`；任一地址被拒绝则整次请求拒绝。

每个 HTTP hop 都重新调用 `validate_target()`。该实现消除当前“只校验字符串域名、不校验解析 IP”的主要风险；文档应如实说明它不是传输层 DNS pinning，不能夸大为完全消除 DNS TOCTOU。

- [ ] **Step 3: 运行测试并提交**

Expected: DNS 测试全部 PASS。

Suggested commit: `feat(scope): validate every resolved address`

### Task 3：HTTP 请求前和重定向逐跳复检

**Files:**
- Modify: `main.py:53-60,256-345,465-509,590-646`
- Modify: `webapp/runner.py:450-549`
- Test: `tests/test_scope.py`

- [ ] **Step 1: 写重定向和端口测试**

给 `BoundedHttpClient` 注入 `httpx.MockTransport`，构造：

- 允许域名 302 到 `127.0.0.1`，第二跳在发请求前拒绝。
- 允许域名跳到排除域名，拒绝码为 `SCOPE_DOMAIN_EXCLUDED`。
- 跳到未授权端口，拒绝码为 `SCOPE_PORT_DENIED`。
- 合法相对跳转最多跟随 5 次，第 6 次返回 `SCOPE_TOO_MANY_REDIRECTS`。

- [ ] **Step 2: 修改 `BoundedHttpClient`**

构造函数改为
`BoundedHttpClient(options, scope_guard, *, transport=None)`；`transport` 仅用于
测试时注入 `httpx.MockTransport`，生产调用必须传入 `ScopeGuard`。

`httpx.AsyncClient` 设置 `follow_redirects=False`、`trust_env=False`。`fetch()` 不再把 `follow_redirects=True` 交给 httpx，而是在本类中处理 `301/302/303/307/308`：使用 `urljoin()` 生成下一跳、重新调用 `ScopeGuard.validate_target()`、限制 5 跳，再发送请求。所有首页、软 404、敏感路径、HEAD 和 Range 请求自动复用该逻辑。

CLI 必须从输入目标、`--allow-cidr`、`--allow-port`、`--allow-scheme` 生成策略，不允许通过“不传 guard”恢复旧的不安全请求路径。

- [ ] **Step 3: 将范围拒绝写入任务事件**

`TaskManager._run_checker()` 捕获 `ScopeViolation`，事件格式固定为：

```text
[SCOPE_IP_DENIED] 已阻止越界请求：https://example.com/redirect
```

事件不输出完整 DNS 内部地址列表，只输出错误码、规范化 URL 和简短原因。

- [ ] **Step 4: 运行核心测试**

```powershell
python -m unittest tests.test_scope tests.test_core -v
python -m compileall -q main.py webapp
```

Expected: PASS，且不存在仍使用 `follow_redirects=True` 的平台请求。

Suggested commit: `feat(scope): enforce scope on requests and redirects`

### Task 4：关闭 OneForAll 的范围绕过路径

**Files:**
- Modify: `webapp/runner.py:58-99,273-350,381-448`
- Modify: `webapp/app.py:65-73`
- Modify: `webapp/templates/dashboard.html:30-44`
- Modify: `webapp/static/app.js:86-104`
- Test: `tests/test_core.py`

- [ ] **Step 1: 写 host-only OneForAll 结果测试**

扩展 `OneForAllParserTests`：当 JSON 只有 `subdomain`、没有 `url` 时仍返回域名种子；超出根域边界的种子被丢弃。

- [ ] **Step 2: 强制 OneForAll 只做域名发现**

`_run_oneforall()` 固定传入：

```text
--req False --alive False --takeover False
```

原因：OneForAll 是独立子进程，其 HTTP 请求不会经过 `ScopeGuard`。平台依据允许协议和端口为发现的主机生成候选 URL，再由 `BoundedHttpClient` 完成存活和路径探测。页面移除“HTTP 请求、仅导出存活、接管检查”三个可绕过平台范围控制的开关，并说明 HTTP 探测由平台安全请求器执行。

- [ ] **Step 3: 保持资产上限和去重**

候选 URL 在发请求前计入 `max_assets`，按规范化的 `scheme://host:port` 去重。80/443 使用默认端口格式；非默认端口显式保留。只有收到 HTTP 响应的候选进入 `assets`，避免把所有端口组合都写成有效资产。

- [ ] **Step 4: 运行测试并提交**

Expected: OneForAll parser、任务请求模型和范围测试全部 PASS。

Suggested commit: `fix(scope): route OneForAll web probes through scope guard`

### Task 5：范围配置界面和准确文案

**Files:**
- Modify: `webapp/templates/dashboard.html:18-69`
- Modify: `webapp/static/app.js:76-137`
- Modify: `webapp/static/style.css`
- Test: `tests/test_web_http.py`

- [ ] **Step 1: 增加范围输入**

新增允许协议、允许端口、显式允许 CIDR、排除域名、排除 CIDR、排除端口和授权截止时间。默认端口为 `80,443`；CIDR 输入为空表示不允许 RFC1918。

- [ ] **Step 2: 修正文案**

手工 URL 帮助文字改为：

```text
可单独填写；如果同时填写主域名，URL 必须属于这些主域名。协议、端口、解析 IP 还需满足下方授权范围。
```

- [ ] **Step 3: 后端重复校验**

前端只负责提示；`TaskRequest` 和 `ScopePolicy.from_dict()` 必须拒绝非法 CIDR、重复/越界端口、过去时间和空协议集合。

- [ ] **Step 4: 运行 HTTP 页面测试并提交**

Suggested commit: `feat(scope): add task scope controls to scan form`

## 5. 闭环二：生产部署安全

### Task 6：应用安全头、敏感响应禁用缓存和登录限速

**Files:**
- Create: `webapp/security.py`
- Modify: `webapp/app.py:51-58,146-191`
- Modify: `webapp/config.py:11-87`
- Modify: `webapp/templates/assets.html`
- Modify: `webapp/templates/findings.html`
- Modify: `webapp/templates/task_detail.html`
- Modify: `.env.example`
- Test: `tests/test_web_http.py`

- [ ] **Step 1: 先写安全响应失败测试**

验证 `/login`、`/` 和认证 API 包含：

```text
Content-Security-Policy
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store
```

CSP 至少包含 `default-src 'self'`、`frame-ancestors 'none'`、`base-uri 'self'`、`form-action 'self'`。

- [ ] **Step 2: 清除 CSP 阻塞项**

将 `assets.html`、`findings.html` 的内联 `onchange` 改为 `data-auto-submit`，由 `app.js` 绑定事件；将 `task_detail.html` 的内联 `style` 改成 `data-progress-value`，由 `task.js` 设置宽度。完成后再启用严格 CSP，不使用 `'unsafe-inline'`。

- [ ] **Step 3: 实现统一安全中间件**

统一入口命名为 `apply_security_headers(response, *, sensitive)`，返回增加安全头后的同一响应对象。

所有 HTML 和 API 设置安全头；登录、登出、任务、发现、证据和下载响应设置 `Cache-Control: no-store`。SSE 保留 `Cache-Control: no-cache` 和 `X-Accel-Buffering: no`，避免破坏现有实时日志。

- [ ] **Step 4: 实现无依赖滑动窗口限速**

`webapp/security.py` 提供：

`LoginRateLimiter(max_attempts, window_seconds, block_seconds)` 提供
`check(key, now=None) -> int`、`record_failure(key, now=None)` 和 `reset(key)`。
`check()` 返回剩余封禁秒数，未封禁时返回 0。

key 使用“规范化用户名 + 客户端 IP”。默认 5 次/5 分钟，封禁 15 分钟；返回统一“用户名或密码错误”，避免账号枚举。限速命中返回 429 和 `Retry-After`。该实现适配当前单进程部署；文档明确多进程时需改成共享存储。

- [ ] **Step 5: 运行测试并提交**

```powershell
python -m unittest tests.test_web_http -v
python -m compileall -q webapp
```

Suggested commit: `feat(security): add login throttling and response headers`

### Task 7：迁移到 HTTPS 和低权限运行

**Files:**
- Modify: `deploy/web-asset-console.service`
- Modify: `deploy/nginx-web-asset-console.conf`
- Modify: `webapp/__main__.py`
- Modify: `.env.example`
- Modify: `PROJECT_GUIDE.md`

- [ ] **Step 1: 加强 systemd 沙箱**

保留 `User=webasset`、`Group=webasset`、`NoNewPrivileges=true`、`PrivateTmp=true`，增加：

```ini
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/var/lib/web-asset-console
```

代码部署到 `/opt/web_asset_checker`，由 root 拥有且服务用户只读；任务数据改到 `/var/lib/web-asset-console` 并由 `webasset:webasset` 拥有。OneForAll 程序只读，结果目录通过 `--path` 指向任务数据目录。

- [ ] **Step 2: 完善 Nginx**

新增 80 端口到 HTTPS 的 301 跳转；443 保留 SSE 所需的 `proxy_buffering off` 和长读取超时；增加 HSTS 前先确认 HTTPS 和证书续期稳定，首轮不启用 `preload`。

- [ ] **Step 3: 更新生产环境变量**

必须满足：

```ini
WEBAPP_HOST=127.0.0.1
WEBAPP_COOKIE_SECURE=true
WEBAPP_PASSWORD=<至少 20 位随机密码>
WEBAPP_SESSION_SECRET=<openssl rand -hex 32>
WEBAPP_DATA_DIR=/var/lib/web-asset-console
FORWARDED_ALLOW_IPS=127.0.0.1
```

删除当前 `admin/admin`。服务继续只使用一个管理员账号，本轮不引入 MFA/RBAC。

- [ ] **Step 4: 在 Linux 服务器执行部署验证**

```bash
sudo systemd-analyze security web-asset-console.service
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl restart web-asset-console nginx
curl -I http://scanner.example.com/login
curl -kI https://scanner.example.com/login
ss -lntp | grep -E '(:80|:443|:8000|:3306)'
ps -o user,group,cmd -C python3
```

Expected：HTTP 301 到 HTTPS；8000 只监听 `127.0.0.1`；Python 进程用户为 `webasset`；3306 只监听 `127.0.0.1`；登录响应包含安全头和 `no-store`。

Suggested commit: `chore(deploy): harden nginx and systemd deployment`

## 6. 闭环三：结果复测管理

### 设计说明

不能只在当前 `findings` 行上增加“首次发现时间”。`findings` 是每次任务的扫描观测，跨任务会重复；直接加字段只能得到“本任务首次发现”，不是真正的项目级首次发现。

采用两层模型：

- `findings`：不可变扫描 observation，保留状态码、标题、相似度等原始证据。
- `finding_cases`：按稳定指纹跨任务聚合，保存负责人、工作流状态、备注、标签、证据摘要、首次/最近发现和最近复测。
- `finding_case_events`：每次人工更新的不可覆盖历史。

### Task 8：稳定指纹和复测状态模型

**Files:**
- Create: `webapp/findings.py`
- Test: `tests/test_findings.py`

- [ ] **Step 1: 写指纹与状态失败测试**

覆盖默认端口、主机大小写、尾斜杠等价性；不同协议、非默认端口、路径或分类必须生成不同指纹。状态只允许：

```text
PENDING_RETEST
CONFIRMED
FALSE_POSITIVE
FIXED
ACCEPTED_RISK
```

- [ ] **Step 2: 实现公共接口**

`ReviewStatus` 使用 `StrEnum`。`normalize_endpoint(url)` 负责 URL 规范化，
`finding_fingerprint(endpoint_url, category)` 返回十六进制 SHA-256。
`FindingReviewUpdate` 是不可变 dataclass，字段为 `status`、`assignee`、
`notes`、`tags`、`evidence_summary`、`mark_retested`。

指纹使用 `sha256(f"{normalized_endpoint}\n{category.upper()}")`。标签去空白、去重，最多 20 个；负责人最长 80 字符；备注和证据摘要分别限制 5000 字符。

- [ ] **Step 3: 运行测试并提交**

Suggested commit: `feat(findings): add stable case identity and review states`

### Task 9：数据库迁移、case upsert 和状态历史

**Files:**
- Modify: `webapp/database.py:64-159,314-387`
- Modify: `webapp/runner.py:500-549`
- Test: `tests/test_database_mysql.py`

- [ ] **Step 1: 增加版本化迁移表**

`Database.initialize()` 先创建 `schema_migrations(version, applied_at)`，再按版本执行迁移。迁移 1 创建：

```sql
CREATE TABLE finding_cases (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    fingerprint CHAR(64) NOT NULL UNIQUE,
    root_domain VARCHAR(253) NOT NULL,
    subdomain VARCHAR(253) NOT NULL,
    endpoint_url TEXT NOT NULL,
    `function` VARCHAR(200) NOT NULL,
    category VARCHAR(80) NOT NULL,
    review_status VARCHAR(24) NOT NULL DEFAULT 'PENDING_RETEST',
    assignee VARCHAR(80) NOT NULL DEFAULT '',
    notes TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    evidence_summary TEXT NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    last_retested_at DATETIME NULL,
    updated_at DATETIME NOT NULL,
    INDEX idx_case_status(review_status),
    INDEX idx_case_assignee(assignee),
    INDEX idx_case_last_seen(last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

迁移同时给 `findings` 增加可空 `case_id BIGINT` 和索引/外键，并创建 `finding_case_events`，字段包含 `case_id`、`actor`、`old_status`、`new_status`、`assignee`、`notes`、`tags_json`、`evidence_summary`、`created_at`。

- [ ] **Step 2: 在事务中 upsert case**

`replace_findings()` 对每条 observation 计算 fingerprint：首次出现时插入 case；再次出现只更新 `last_seen_at`、最近 URL/标题相关元数据，不覆盖人工状态、负责人、备注和首次发现时间。将 case ID 写入 observation。

- [ ] **Step 3: 实现状态更新事务**

新增 `list_finding_cases(task_id=None, limit=1000)`、
`get_finding_case(case_id)`、`update_finding_case(case_id, update, actor)`、
`list_finding_case_events(case_id)` 四个数据库方法。

`update_finding_case()` 必须在同一事务中锁定 case、更新当前值、插入事件。`mark_retested=True` 时写入 `last_retested_at=NOW()`。

- [ ] **Step 4: 使用独立 MySQL 测试库验证**

测试必须验证：重复 fingerprint 不新增 case；`first_seen_at` 不变；`last_seen_at` 更新；人工字段不被新扫描覆盖；状态更新必定产生 event；数据库异常时更新和 event 一起回滚。

Suggested commit: `feat(database): persist finding cases and review history`

### Task 10：复测 API 与界面

**Files:**
- Modify: `webapp/app.py:96-101,261-275,365-367`
- Modify: `webapp/templates/findings.html`
- Modify: `webapp/templates/partials/findings_table.html`
- Create: `webapp/static/findings.js`
- Modify: `webapp/static/style.css`
- Modify: `tests/test_web_http.py`

- [ ] **Step 1: 新增受 CSRF 保护的 PATCH API**

```text
GET   /api/finding-cases/{case_id}
PATCH /api/finding-cases/{case_id}
GET   /api/finding-cases/{case_id}/events
```

PATCH 请求包含 `status`、`assignee`、`notes`、`tags`、`evidence_summary`、`mark_retested`。当前系统只有单管理员，`actor` 使用 Session 用户名；本轮不伪造多用户/RBAC。

- [ ] **Step 2: 结果中心切换为 case 列表**

表格新增复测状态、负责人、首次发现、最近发现、最近复测和“编辑”按钮。保留入口 URL、分类、访问状态和优先级；任务详情仍展示本任务 observation，但连接到对应 case。

- [ ] **Step 3: 增加轻量复测弹窗**

使用原生 `<dialog>`，不引入前端框架。保存成功后更新当前行；事件历史在弹窗下方只读展示。`ACCEPTED_RISK` 必须填写备注；`mark_retested` 明确控制最近复测时间。

- [ ] **Step 4: 明确 CSV 语义**

现有 `assets.csv` 和 `result.csv` 继续作为任务完成时的不可变原始扫描快照，不在人工复测后原地改写。复测状态以数据库和结果中心为准，避免用户误以为旧 CSV 会自动同步。

- [ ] **Step 5: 运行回归测试并提交**

```powershell
python -m unittest tests.test_findings tests.test_web_http -v
python -m compileall -q webapp
```

Suggested commit: `feat(findings): add review workflow and case history UI`

## 7. 第二优先级：低成本增强

### Task 11：失败重试、复制和仅重跑路径检测

**Files:**
- Modify: `webapp/runner.py:224-380`
- Modify: `webapp/app.py:293-318`
- Modify: `webapp/templates/task_detail.html`
- Modify: `webapp/static/task.js`
- Test: `tests/test_core.py`, `tests/test_web_http.py`

- [ ] `POST /api/tasks/{id}/clone`：复制配置快照，但重新检查授权有效期并创建新任务。
- [ ] `POST /api/tasks/{id}/retry`：仅允许 FAILED/CANCELLED，行为是创建新 task，不覆盖旧任务和日志。
- [ ] `POST /api/tasks/{id}/rerun-checker`：读取源任务 `assets`，跳过 OneForAll，使用当前路径规则创建新任务；新配置记录 `source_task_id` 和 `run_mode=checker_only`。
- [ ] 不实现暂停、原任务断点续跑或同一 task attempt；这些能力会显著增加状态机复杂度，简历收益不匹配。

Suggested commit: `feat(tasks): clone retry and rerun checker tasks`

### Task 12：界面细节与无障碍

**Files:**
- Modify: `webapp/static/app.js`
- Modify: `webapp/templates/base.html`
- Modify: `webapp/templates/dashboard.html`
- Modify: `webapp/templates/settings.html`
- Modify: `webapp/templates/assets.html`
- Modify: `webapp/templates/findings.html`
- Modify: `webapp/static/style.css`
- Modify: `webapp/classifier.py:144-153`
- Test: `tests/test_core.py`, `tests/test_web_http.py`

- [ ] 关闭 OneForAll 或路径检测时，禁用对应 fieldset 的子参数；后端忽略禁用模块的陈旧参数。
- [ ] `save_rules()` 对规范化后重复路径抛出明确错误；前端保存前标红非法、完整 URL 和重复路径。
- [ ] 资产、发现和任务空状态提供“新建扫描”链接；任务页虽然已有页头按钮，空行仍给出明确行动入口。
- [ ] 当前导航项设置 `aria-current="page"`；移动菜单按钮设置 `aria-expanded`、`aria-controls="sidebar"`。
- [ ] 菜单打开时显示遮罩，Escape 关闭，关闭后焦点回到菜单按钮。
- [ ] 表格增加 `caption` 或 `aria-label`。

Suggested commit: `fix(ui): improve form state and mobile navigation accessibility`

## 8. 测试、验收和发布顺序

### 本地自动化检查

```powershell
Set-Location 'D:\桌面\python渗透测试工具\web_asset_checker'
python -m unittest discover -s tests -v
python -m compileall -q main.py webapp
```

### 合法靶场端到端检查

必须使用明确授权的实验目标，至少包含：一个公网测试域名、一个显式授权的 RFC1918 地址、一个跳往越界地址的重定向目标、一个软 404 主机。

验收条件：

- [ ] 未显式授权的 localhost、链路本地、RFC1918 和云元数据地址在发请求前被阻止。
- [ ] 显式 CIDR 只放行范围内地址；排除项始终优先。
- [ ] DNS 所有 A/AAAA 地址和每个重定向 hop 都经过校验。
- [ ] OneForAll 不再直接执行绕过 `ScopeGuard` 的 HTTP/接管请求。
- [ ] 现有取消、SSE、CSV 和软 404 回归测试通过。
- [ ] 生产入口强制 HTTPS，Uvicorn/MySQL 只监听回环，服务不是 root。
- [ ] 登录限速、安全 Cookie、安全响应头和 `no-store` 检查通过。
- [ ] 同一入口跨任务只形成一个 case，首次/最近发现准确，复测变更有历史。
- [ ] 原始 `result.csv` 保持任务快照语义，不被人工状态修改污染。

发布顺序严格为：

```text
ScopePolicy 纯逻辑
→ DNS/重定向请求校验
→ OneForAll 安全模式
→ HTTPS/非 root/登录加固
→ finding case 与复测状态
→ 任务重试/复制
→ 界面细节
```

## 9. 单人实施估算与停止条件

| 阶段 | 单人兼职估算 | 完成标志 |
|---|---:|---|
| 范围安全 | 7–10 天 | 所有平台 HTTP 请求逐跳校验，OneForAll 无旁路 |
| 生产加固 | 2–4 天 | HTTPS、非 root、限速、安全头完成 |
| 结果复测 | 5–7 天 | case 聚合、状态、负责人、历史完整可用 |
| 可选增强 | 3–5 天 | 重试/复制/路径重跑和界面细节 |

完成前三项后即可停止扩展并整理简历、架构图和演示视频。不要为了功能数量继续加入 Nuclei、MFA、PDF 或调度系统。

## 10. 简历表述建议

- 设计任务级授权范围模型，基于协议/端口/域名/CIDR/有效期进行校验，并对 DNS A/AAAA 与 HTTP 重定向逐跳复检，阻断 SSRF、云元数据和内网越界访问。
- 将第三方资产发现工具限制为域名发现模式，所有 Web 探测统一收敛到受控异步 HTTP 客户端，避免子进程绕过平台安全策略。
- 基于 Nginx TLS、systemd 非 root 沙箱、Session/CSRF、登录滑动窗口限速和 CSP/no-store 完成单机生产安全加固。
- 将扫描 observation 与 finding case 分层，使用稳定指纹实现跨任务聚合、首次/最近发现、复测状态和不可覆盖的变更历史。

表述时注明“授权安全测试平台”和实际测试范围，不将敏感入口存在性描述成漏洞扫描或漏洞利用。

## 11. 实施前状态

当前本地目录不是 Git 仓库。执行本计划前应在实际代码仓库或独立工作分支中实施；上面的 Suggested commit 是建议的提交边界，不应在当前零版本控制目录中伪造提交历史。
