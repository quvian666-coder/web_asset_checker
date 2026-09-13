# Web Asset Console 项目配置与部署说明

> 更新日期：2026-09-13
> 使用范围：仅用于自有资产或已获得明确授权的安全测试。

## 0. 开发与部署交接状态（后续窗口必须先读）

### 0.1 当前结论

基础安全改造已于 **2026-06-22 原地增量部署到 Linux 服务器**。2026-09-13 的多源发现和 Nuclei 白名单功能已完成本地测试、合并并推送 GitHub；但本轮 Linux 增量部署尚未完成，因为服务器未返回 SSH 协议横幅且 Web 8000 超时。后续部署必须继续保留现有 `/root/web_asset_checker`、root systemd、HTTP 8000、环境变量、数据库、虚拟环境、任务数据、路径规则和 OneForAll，不得重置配置。

| 项目 | 当前状态 |
|---|---|
| 本地项目 | `D:\桌面\python渗透测试工具\web_asset_checker` |
| GitHub | `https://github.com/quvian666-coder/web_asset_checker.git`，Public |
| 默认分支 | `main`，包含多源工具链合并提交 `abd8a4a` |
| 开发分支 | `codex/discovery-nuclei-adapters`，已合并，暂留作实现参照 |
| 当前功能提交 | `abd8a4a`，已推送到 `origin/main` |
| 合并状态 | 2026-09-13 已通过 `--no-ff` 合并到 `main`，无需 PR |
| 自动测试 | 本地 51 项 `unittest` 全部通过；Linux 本轮待部署后复验 |
| Python 编译检查 | `python -m compileall -q main.py webapp` 通过 |
| JavaScript 语法 | `node --check webapp/static/*.js` 通过 |
| Linux 服务器 | `10.0.0.174`，最后确认仍运行旧版；新工具链尚未部署 |
| Linux 登录 | 用户确认使用 `root` 账号和密码登录；密码不得写入仓库或本文档 |
| 本轮部署状态 | 阻塞于 SSH 横幅前断开；没有停止、重启或覆盖远端服务 |
| 当前访问地址 | `http://10.0.0.174:8000` |
| 数据库迁移 | `schema_migrations=[1,2]`；迁移 2 将 `assets.ip` 扩展为 `TEXT` |
| 服务器备份 | `/root/web-asset-backups/20260621133810` |

2026-09-13 仓库状态更新：GitHub 仓库已公开，`codex/harden-platform` 已快进合并到默认分支 `main`。本次仅更新交接状态文档，没有修改扫描逻辑或 Linux 服务。

2026-09-13 工具链更新：GitHub `main` 已包含 `abd8a4a`。新增 Subfinder、dnsx、四种发现方案和受控 Nuclei；本地 51 项测试通过。Linux 部署必须在 `10.0.0.174` 恢复正常 SSH 横幅后继续，不能把“TCP 22 可连接”误判为“SSH 可登录”。

2026-06-22 热修复：新建扫描页面的空端口字段曾被前端 `Number("")` 转换为端口 `0`，触发 `[SCOPE_PORT_INVALID]`。现已在数值转换前过滤空项，并原地部署；无需修改已有范围配置或服务器配置。

2026-06-22 数据库热修复：DNS 安全复检会保存同一主机解析到的全部 IPv4/IPv6，`autodiscover.ppdai.com` 和 `autodiscover.xinye.com` 的 IP 列表长度达到 277，超过原 `assets.ip VARCHAR(255)` 并触发 MySQL 1406。迁移 2 将该列改为 `TEXT NOT NULL`，完整保留 DNS 证据，不做截断。

2026-06-22 误报热修复：一次扫描中 217 条 `.git/config` 均为 HTTP 203、标题“安全告警”、长度 1131 的统一 HTML 页面，并非 Git 配置。根因是随机软 404 基线全部超时时仍继续把任意 2xx 判为可访问。现已在基线完全不可用时跳过该主机的敏感路径判定，并要求 `.git/config` 响应同时包含 `[core]` 和 `repositoryformatversion` 特征。历史结果保留，需使用“重跑路径检测”生成修正后的结果。

### 0.2 已实现的改造

#### A. 扫描范围安全闭环

- 新增 `webapp/scope.py`：`ScopePolicy`、`ScopeGuard`、稳定错误码和 URL/IP/DNS 校验。
- 支持允许域名、手工 URL 精确主机、允许 CIDR、允许端口、允许协议、排除域名/CIDR/端口和授权截止时间。
- 固定阻止 localhost、`127.0.0.0/8`、`::1`、链路本地、unspecified、multicast、reserved 及云元数据地址。
- RFC1918 和 IPv6 ULA 默认禁止，只有任务明确配置 `allowed_cidrs` 后才允许。
- `main.py` 中 `BoundedHttpClient` 在每次请求前解析并校验全部 A/AAAA 地址，HTTP 重定向由平台手动逐跳处理，最多 5 跳，每一跳重新校验。
- `httpx.AsyncClient` 使用 `follow_redirects=False` 和 `trust_env=False`，避免自动跳转和环境代理绕过。
- CLI 同样必须生成范围策略，支持 `--allow-cidr`、`--allow-port`、`--exclude-domain`、`--exclude-cidr`、`--exclude-port`。
- OneForAll 被限制为域名发现模式，固定使用 `--req False --alive False --takeover False`；Web 探测全部由平台受控客户端执行。
- 页面已增加协议、端口、CIDR、排除项和授权截止时间配置。

注意：当前实现是“请求前 DNS 全量复检”，未实现传输层 DNS pinning，不能夸大为完全消除 DNS TOCTOU。该实现已解决当前项目最主要的字符串域名校验和自动重定向越界问题。

#### B. 生产安全加固

- 新增 `webapp/security.py`：单进程滑动窗口登录限速和统一安全响应头。
- 默认登录限制为 5 次/5 分钟，封禁 15 分钟；配置项见 `.env.example`。
- 响应头包括严格 CSP、`X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy`、`Permissions-Policy`。
- 登录、页面、敏感 API 和下载响应使用 `Cache-Control: no-store`；SSE 保留 `no-cache`。
- `WEBAPP_COOKIE_SECURE`、可信反向代理和弱密码提醒已完善；`admin` 也会被识别为弱密码。
- `deploy/web-asset-console.service` 已改为 `webasset` 低权限用户，并加入 systemd 沙箱。
- `deploy/nginx-web-asset-console.conf` 已改为 HTTP 强制跳转 HTTPS、TLS 1.2/1.3、回环代理和 SSE 配置。
- 新增 `deploy/install-production.sh`，可创建服务用户、数据目录、自签名 IP 证书、安装 Nginx/systemd 配置并启动服务。
- 可编辑的 `paths.txt` 生产路径改为 `WEBAPP_PATHS_FILE=/var/lib/web-asset-console/paths.txt`，避免服务进程写入只读代码目录。

#### C. 结果复测闭环

- 新增 `webapp/findings.py`：URL 规范化、SHA-256 稳定指纹、复测状态和字段校验。
- `findings` 继续保存每次任务的原始扫描 observation。
- 新增 `finding_cases`：跨任务聚合同一入口，保存负责人、状态、备注、标签、证据摘要、首次发现、最近发现和最近复测时间。
- 新增 `finding_case_events`：保存不可覆盖的人工状态变更历史。
- 状态包括 `PENDING_RETEST`、`CONFIRMED`、`FALSE_POSITIVE`、`FIXED`、`ACCEPTED_RISK`。
- `ACCEPTED_RISK` 必须填写备注。
- 新增 case 查询、更新和历史 API；结果中心增加原生 `<dialog>` 复测界面。
- `assets.csv` 和 `result.csv` 继续作为任务完成时的不可变原始快照，不会被人工复测状态覆盖。

#### D. 第二优先级功能

- 保留已有任务取消和 SSE，不重写任务系统。
- 增加复制任务、失败/取消任务重试、复用历史资产仅重跑路径检测。
- 未实现暂停和断点续跑。
- 关闭模块时会禁用子参数；关闭路径检测时会同步关闭依赖存活资产的 Nuclei。
- 手工 URL 文案已改为：可单独填写；填写主域名后必须属于主域名及配置范围。
- 规则编辑器增加前后端格式检查和重复路径拒绝。
- 空状态增加“新建扫描”入口。
- 移动导航增加 `aria-current`、`aria-expanded`、`aria-controls`、遮罩和 Escape 关闭。
- 表格增加 `aria-label`，并移除会被严格 CSP 阻止的内联事件和内联样式。

#### E. 多源发现与受控 Nuclei（2026-09-13）

- 保留 OneForAll，不替换、不删除其代码、虚拟环境或历史任务。
- 新增四种发现方案：`quick`（Subfinder → dnsx）、`comprehensive`（Subfinder + OneForAll → 合并 → dnsx，默认推荐）、`legacy`（OneForAll + 内置 MassDNS）和 `custom`（独立开关）。
- 新增 `webapp/toolchain.py`，集中负责预设解析、Subfinder/dnsx JSONL 解析、URL/IP/来源合并、Nuclei 白名单解析和 finding 转换。
- Subfinder 只做被动子域发现，默认速率 5/秒；dnsx 验证 A、AAAA 和 CNAME，默认速率 50/秒。
- 多个工具发现同一 URL 时不会互相覆盖，`assets.source` 会合并来源，IP 字段也会合并去重。
- 所有候选资产无论来自哪个工具，仍必须经过 `ScopeGuard.validate_target()`；工具不能绕过允许域名、CIDR、协议、端口、排除项和授权有效期。
- Nuclei 默认关闭，只对路径检测确认存活的资产执行。它按单个资产的标题、Server、URL 和已发现入口选择模板，不匹配指纹时安全跳过。
- `nuclei-allowlist.txt` 当前只允许官方 Git 配置、Jenkins、Grafana 和 Spring Boot 检测模板，前端不能提交模板路径。
- Nuclei 固定使用 HTTP 模板、官方签名校验、禁重定向、禁 OAST、禁本地/私网访问、1 MiB 响应读取上限、低速率和小并发。
- Nuclei JSONL 只作为进程间临时文件；转换为最小 finding 后立即删除，避免模板 extractor 将凭据片段长期落盘。
- 如果 Nuclei 与平台路径检测命中同一 Endpoint URL，会合并证据、取更高复测优先级和置信度，避免重复 finding。
- 路径检测得到的状态码、标题和 Server 会同步回内存资产，避免任务末尾用旧数据覆盖数据库，也为 Nuclei 指纹路由提供证据。
- 旧任务配置没有 `discovery_preset` 时按 `legacy` 执行，保证任务重试/复制的向后兼容；“仅重跑路径检测”会关闭全部发现器和 Nuclei。

安全限制：Nuclei 固定启用 `-restrict-local-network-access`，因此即使平台范围显式允许 RFC1918 CIDR，Nuclei 阶段也仍会跳过私网；平台自带路径检测器不受此额外限制。此选择是外部模板执行的纵深防御，不应删除。

### 0.3 新增或重点修改文件

```text
webapp/scope.py                    # 范围策略、DNS/IP/重定向校验
webapp/security.py                 # 登录限速和安全响应头
webapp/findings.py                 # finding 指纹和复测状态
webapp/toolchain.py                # Subfinder/dnsx/Nuclei 适配与安全路由
webapp/static/findings.js          # 复测弹窗与 API 交互
nuclei-allowlist.txt               # 指纹关键词到官方签名模板的固定映射
tests/test_scope.py                # 范围与重定向测试
tests/test_security.py             # 登录限速测试
tests/test_findings.py             # 指纹和复测状态测试
tests/test_toolchain.py             # 发现预设、解析器、白名单和 Nuclei 结果测试
deploy/install-production.sh       # Linux 生产安装脚本
deploy/web-asset-console.service   # 非 root systemd 沙箱
deploy/nginx-web-asset-console.conf # HTTPS 反向代理
```

核心修改还涉及 `main.py`、`webapp/app.py`、`webapp/runner.py`、`webapp/database.py`、`webapp/config.py`、模板和静态资源。

### 0.4 测试命令与本机路径问题

Codex PowerShell 有时将逻辑工作目录映射为 `D:\claude`，因此后续窗口应优先使用绝对路径和 `git -C`。本地测试使用：

```powershell
$root = 'D:\桌面\python渗透测试工具\web_asset_checker'
$env:PYTHONPATH = $root
& "$root\.venv\Scripts\python.exe" -m unittest discover -s "$root\tests" -v
& "$root\.venv\Scripts\python.exe" -m compileall -q "$root\main.py" "$root\webapp"
Get-ChildItem "$root\webapp\static\*.js" | ForEach-Object { node --check $_.FullName }
git -C $root status -sb
```

2026-09-13 本地最后一次完整结果：51 项测试通过，Python 编译检查和全部 JavaScript 语法检查通过。测试输出只有 FastAPI/Starlette 关于 TestClient 的弃用警告，不影响结果，当前不应为了该警告引入新依赖。

### 0.5 SSH 登录与 Paramiko 部署方式

服务器允许 root 密码认证。`ssh.exe` 在非交互自动化中不能填写密码不代表服务器要求公钥；Codex 可以使用隔离目录中的 Paramiko 按 SSH 协议提交用户已授权的凭据。不要修改全局 Python，也不要把密码写进仓库、本文档、环境示例或命令日志。

本机隔离依赖准备：

```powershell
$Python = "C:\Users\LENOVO\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$Deps = "$env:TEMP\codex_ssh_deps"
New-Item -ItemType Directory -Force $Deps | Out-Null
& $Python -m pip install --target $Deps paramiko
$env:PYTHONPATH = $Deps
```

连接参数为 `10.0.0.174`、用户 `root`；密码应只从当前用户授权上下文临时提供给 `client.connect()`。文件增量部署使用 `client.open_sftp().put()`，不得覆盖 `.venv`、`data`、`paths.txt`、`urls.txt`、`result.csv`、环境文件、MySQL 数据或 OneForAll。

2026-09-13 本轮连接诊断：目标 TCP 22 曾可建立连接，但服务器在发送 SSH 协议横幅前主动关闭，Paramiko 报 `Error reading SSH protocol banner`；同时 `http://10.0.0.174:8000/login` 超时。出现该状态时不要假定部署成功，也不要反复重启本地或远程进程，应等待服务器网络/SSH 恢复后重新执行只读状态检查。

### 0.6 已完成的实际部署记录与可选生产迁移

实际部署已完成，不需要后续窗口重复执行：

- 上传并解压 Git 提交 `febface` 的精确归档。
- 在 `/root/web_asset_checker.release-febface` 使用现有 `.venv` 运行 35 项测试，全部通过。
- 备份 MySQL、应用代码、任务数据、环境文件和 systemd 到 `/root/web-asset-backups/20260621133810`。
- 数据库备份使用 `mysqldump --no-tablespaces --single-transaction`，文件已验证包含 `tasks` 建表语句。
- 停止现有服务，原地覆盖代码；明确保留 `.venv`、`data`、`paths.txt`、`urls.txt`、`result.csv`、`/etc/web-asset-console.env` 和 systemd unit。
- 执行加法型数据库迁移版本 1，然后启动原有服务。
- 服务器再次运行 35 项测试，全部通过。
- 登录态验收确认首页包含 `scope-ports`、`scope-allowed-cidrs`，结果页包含 `data-review-dialog`，设置页包含 `data-rules-table`。
- 配置文件、systemd unit 和 `paths.txt` 与部署前备份逐字节/哈希一致。
- Windows 访问 `http://10.0.0.174:8000/login` 返回 HTTP 200，并包含 CSP、`no-store` 等新安全响应头。
- 当前服务 PID 会随重启变化，仍使用 root 和 `0.0.0.0:8000`；这是用户要求保留现有配置的结果，不是生产模板遗漏。

以下步骤只在用户以后明确要求从当前实验环境迁移到 `/opt`、Nginx HTTPS 和 `webasset` 低权限服务时执行，当前不要执行：

1. 使用上述专用密钥确认可无交互登录 `root@10.0.0.174`。
2. 备份当前数据库、`/root/web_asset_checker`、`/etc/web-asset-console.env` 和 systemd 服务。
3. 将 `codex/harden-platform` 克隆或拉取到 `/opt/web_asset_checker`，不要直接覆盖唯一旧副本。
4. 当前 OneForAll 位于 `/root/OneForAll`，低权限服务和 `ProtectHome=true` 无法访问。必须将 OneForAll 迁移到 `/opt/OneForAll`，重建其虚拟环境，并确认 `webasset` 用户可读/执行。
5. 在 `/opt/web_asset_checker` 创建新的 `.venv` 并安装 `requirements.txt`。
6. 保留 `/etc/web-asset-console.env` 中真实 MySQL 密码，但更新应用路径和安全配置；Web 密码必须替换 `admin/admin`，Session 密钥必须重新生成。
7. 首次启动会执行 `schema_migrations` 版本 1，创建 `finding_cases`、`finding_case_events`，给 `findings` 增加 `case_id` 并回填历史结果。
8. 运行 `deploy/install-production.sh`，验证 Nginx、systemd、MySQL 迁移和页面。
9. 使用合法靶场验证范围阻断、显式 RFC1918 CIDR 放行、SSE、取消、CSV 和复测状态。
10. 验收通过后再合并 `codex/harden-platform` 到 `main`。

建议的服务器命令框架：

```bash
set -euo pipefail

# 备份
mkdir -p /root/web-asset-backups
mysqldump -h 127.0.0.1 -u webasset -p --single-transaction web_asset_checker \
  > /root/web-asset-backups/web_asset_checker_$(date +%F_%H%M%S).sql
cp -a /root/web_asset_checker /root/web-asset-backups/web_asset_checker_before_hardening
cp -a /etc/web-asset-console.env /root/web-asset-backups/web-asset-console.env
cp -a /etc/systemd/system/web-asset-console.service /root/web-asset-backups/web-asset-console.service

# 拉取应用分支
apt update
apt install -y git nginx openssl python3 python3-venv python3-pip
rm -rf /opt/web_asset_checker.new
git clone --branch codex/harden-platform --single-branch \
  https://github.com/quvian666-coder/web_asset_checker.git /opt/web_asset_checker.new
mv /opt/web_asset_checker.new /opt/web_asset_checker
python3 -m venv /opt/web_asset_checker/.venv
/opt/web_asset_checker/.venv/bin/pip install --upgrade pip
/opt/web_asset_checker/.venv/bin/pip install -r /opt/web_asset_checker/requirements.txt

# 迁移 OneForAll：复制代码后应删除旧 venv 并按它自己的 requirements 重建
cp -a /root/OneForAll /opt/OneForAll
rm -rf /opt/OneForAll/.venv
python3 -m venv /opt/OneForAll/.venv
/opt/OneForAll/.venv/bin/pip install --upgrade pip
/opt/OneForAll/.venv/bin/pip install -r /opt/OneForAll/requirements.txt
chown -R root:root /opt/OneForAll /opt/web_asset_checker
chmod -R a+rX /opt/OneForAll /opt/web_asset_checker
```

环境文件至少调整为：

```ini
WEBAPP_HOST=127.0.0.1
WEBAPP_PORT=8000
WEBAPP_USERNAME=admin
WEBAPP_PASSWORD=<至少20位随机密码，不得使用admin>
WEBAPP_SESSION_SECRET=<openssl rand -hex 32>
WEBAPP_COOKIE_SECURE=true
WEBAPP_DATA_DIR=/var/lib/web-asset-console
WEBAPP_PATHS_FILE=/var/lib/web-asset-console/paths.txt
WEBAPP_LOGIN_MAX_ATTEMPTS=5
WEBAPP_LOGIN_WINDOW_SECONDS=300
WEBAPP_LOGIN_BLOCK_SECONDS=900
FORWARDED_ALLOW_IPS=127.0.0.1

ONEFORALL_DIR=/opt/OneForAll
ONEFORALL_PYTHON=/opt/OneForAll/.venv/bin/python
```

保留现有 `MYSQL_*` 值。然后执行：

```bash
cd /opt/web_asset_checker
PYTHONPATH=/opt/web_asset_checker .venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=/opt/web_asset_checker .venv/bin/python -m compileall -q main.py webapp
SERVER_IP=10.0.0.174 bash deploy/install-production.sh
systemctl status web-asset-console nginx --no-pager
journalctl -u web-asset-console -n 100 --no-pager
curl -kI https://127.0.0.1/login
ss -lntp | grep -E '(:80|:443|:8000|:3306)'
```

`install-production.sh` 会生成包含 `10.0.0.174` IP SAN 的自签名证书，因此浏览器首次打开 `https://10.0.0.174/` 会显示证书不受信任提示。隔离实验网可手工信任该证书；公网部署必须替换为受信 CA 证书。

### 0.7 后续生产化迁移时必须重点验证的风险

- 数据库迁移已在服务器 MySQL 8.0.46 上执行成功；以后新增迁移仍必须先备份。
- 必须确认当前 OneForAll 在 `--req False` 时仍输出包含 `subdomain` 的 JSON。若其版本行为不同，不得重新开启 OneForAll HTTP 请求，应调整 parser 或 OneForAll 输出参数。
- systemd 的 `ProtectSystem=strict` 和 `ProtectHome=true` 会阻止访问 `/root/OneForAll`，所以必须完成 `/opt/OneForAll` 迁移。
- 如果 OneForAll 仍尝试写自身代码目录，应根据日志只为其必要运行目录增加 `ReadWritePaths`，不要改回 root 运行整个 Web 服务。
- 登录限速当前使用进程内存，适用于当前单进程 Uvicorn；未来多进程部署才需要 Redis/MySQL 共享限速。
- 当前未实现 MFA、完整 RBAC、PDF、定时任务、通知、暂停和断点续跑；Nuclei 已实现为默认关闭的指纹定向白名单验证，不是宽泛自动扫描。
- 当前功能部署已验证，但开发分支尚未合并到 `main`；不要删除 `/root/web_asset_checker` 和数据库备份。

## 1. 项目定位

Web Asset Console 是一个轻量级 Web 资产发现和敏感路径辅助检测平台，将以下工作串成一个自动任务：

```text
输入已授权主域名 / 手工 URL
    ↓
按预设运行 OneForAll、Subfinder 与 dnsx
    ↓
多源合并、DNS/IP/协议/端口范围复检和 URL 去重
    ↓
读取 paths.txt 的全部启用规则
    ↓
存活检测、软 404 识别和敏感路径存在性检测
    ↓
功能分类、访问状态和复测优先级计算
    ↓
可选的 Nuclei 指纹定向白名单验证
    ↓
MySQL 持久化 + Web 展示 + CSV 导出
```
本项目只做信息收集、存在性检测和结果整理，不执行登录绕过、漏洞利用或敏感文件批量下载。

## 2. 当前服务器状态

| 项目 | 当前值 |
|---|---|
| Linux | Ubuntu 24.04 LTS |
| 服务器 IP | `10.0.0.174` |
| Web 地址 | `http://10.0.0.174:8000` |
| Web 用户名 | `admin` |
| Web 密码 | 从 `/etc/web-asset-console.env` 的 `WEBAPP_PASSWORD` 读取；当前实验环境按要求设为 `admin` |
| 项目目录 | `/root/web_asset_checker` |
| 项目 Python | `/root/web_asset_checker/.venv/bin/python` |
| OneForAll 目录 | `/root/OneForAll` |
| OneForAll Python | `/root/OneForAll/.venv/bin/python` |
| Nuclei | `/root/go/bin/nuclei` |
| MySQL | `127.0.0.1:3306` |
| 数据库 | `web_asset_checker` |
| 数据库用户 | `webasset@127.0.0.1` |
| systemd 服务 | `web-asset-console.service` |
| 运行状态 | 已启用开机自启，监听 `0.0.0.0:8000` |
| MySQL 暴露范围 | 仅监听 `127.0.0.1:3306`，不对局域网开放 |

SSH root 密码、MySQL 密码和 Session 密钥不写入本文档。密钥统一保存在权限为 `600` 的 `/etc/web-asset-console.env` 中。

## 3. 项目目录结构

```text
web_asset_checker/
├── main.py                         # 独立 CLI 存活与敏感路径检测器
├── urls.txt                       # CLI 目标示例
├── paths.txt                      # 敏感路径规则，Web 和 CLI 共用
├── result.csv                     # CLI 默认结果文件
├── requirements.txt               # Python 依赖
├── .env.example                   # 环境变量示例，不存放真实密码
├── README.md                      # 简要使用说明
├── PROJECT_GUIDE.md               # 本文档
├── data/
│   └── tasks/<task_id>/              # 每个 Web 任务的输入、中间文件和 CSV
├── deploy/
│   ├── web-asset-console.service    # 通用 systemd 参考模板
│   └── nginx.conf                  # 如需 HTTPS/反向代理时使用
├── tests/
│   ├── test_core.py                # 核心逻辑、OneForAll 结果解析和规则测试
│   └── test_web_http.py            # 登录和页面 HTTP 测试
└── webapp/
    ├── __main__.py                   # `python -m webapp` 入口
    ├── app.py                        # FastAPI 页面、认证、CSRF 和 API
    ├── config.py                     # 环境变量和工具路径
    ├── database.py                   # MySQL 连接、建表和数据读写
    ├── runner.py                     # OneForAll 和路径检测任务编排
    ├── classifier.py                 # paths.txt 解析、自动分类和优先级
    ├── templates/                    # Jinja2 HTML 模板
    └── static/                       # CSS 和 JavaScript
```

## 4. 组件边界

### 4.1 OneForAll

- 根据主域名收集子域名。
- 保留内置 DNS/MassDNS 和可选子域爆破能力。
- 平台固定 `--req False --alive False --takeover False`，OneForAll 不直接进行 Web 请求或接管检测。
- 平台读取 JSON 中的子域并按授权协议/端口构造候选 URL。
- 只保留属于输入主域名范围的结果。

### 4.2 Python 敏感路径检测器

- 检测基础 URL 是否存活。
- 记录状态码、标题、响应长度、`Server`、`X-Powered-By`、Content-Type 和跳转地址。
- 对 `paths.txt` 的全部启用规则进行存在性检测。
- 使用随机不存在路径建立 404 基线，降低“所有路径都返回 200”造成的误报。
- 不会提交表单、猜解密码或执行漏洞利用。

### 4.3 Nuclei

- 默认关闭，必须由用户对单个任务明确启用。
- 只接收平台路径检测确认存活并再次通过范围复检的 URL。
- 根据每个资产已有指纹选择 `nuclei-allowlist.txt` 中的精确官方模板；没有匹配模板时不运行。
- 强制官方签名校验、HTTP 类型、禁跳转、禁 OAST、禁私网、低速率和小并发。
- Nuclei 命中会转换成现有 finding；同一 Endpoint URL 与路径检测结果合并。

### 4.4 Subfinder 与 dnsx

- Subfinder 以 `-dL` 批量读取授权主域名，使用 JSONL 和来源字段输出被动发现结果，不执行 HTTP。
- dnsx 对 OneForAll、Subfinder 和输入主域名的合并主机集执行 A/AAAA/CNAME 验证。
- dnsx 输出只用于候选过滤与证据保存；平台仍会在 HTTP 前重新解析并校验全部地址。

### 4.5 httpx

- `requirements.txt` 中的 `httpx` 是 Python HTTP 依赖。
- Linux 上安装的 Go `httpx` 不在当前 Web 任务主链路中，不需要另外配置参数。

## 5. Web 任务的自动执行方式

使用者在 Web 页面中只需：

1. 输入已授权的主域名或手工 URL。
2. 选择“综合（推荐）”“快速”“兼容”或“自定义”发现方案。
3. 按需开启 Nuclei，设置参数并勾选授权确认。
4. 点击“创建并运行任务”。

后续流程全部自动执行：发现器完成后，平台合并来源、调用 dnsx、逐个范围复检、读取 `paths.txt`、运行敏感路径检测、按指纹选择 Nuclei 白名单模板、存入 MySQL 并生成 CSV。不需要手工导入任何外部工具结果。

手工 URL 是可选补充：

- 任一发现器开启时：与发现结果合并后去重。
- 所有发现器关闭时：可使用手工 URL 单独检测。
- 如同时提供主域名，手工 URL 也必须属于授权主域名范围。

## 6. Web 参数说明

### 6.1 任务参数

| 参数 | 默认值 | 范围/含义 |
|---|---:|---|
| 任务名称 | `full-scan` | 1–80 字符，用于任务中心和归档 |
| 主域名 | 空 | 最多 500 个，每行一个，不填协议和路径 |
| 手工 URL | 空 | 最多 1000 个，可包含端口 |
| 最大资产数 | `500` | 1–5000，超过则任务停止，防止意外扩大范围 |
| 授权确认 | 未勾选 | 未勾选时禁止创建扫描任务 |

### 6.2 资产发现方案

| 方案 | 工具链 | 默认用途 |
|---|---|---|
| `quick` | Subfinder → dnsx | 快速被动发现 |
| `comprehensive` | Subfinder + OneForAll → 合并 → dnsx | 默认推荐、提高来源覆盖 |
| `legacy` | OneForAll + 内置 MassDNS | 保持原流程兼容 |
| `custom` | 三个发现组件独立开关 | 调试和定向任务 |

### 6.3 OneForAll 参数

| 参数 | 默认值 | 说明 |
|---|---:|---|
| 启用 | 开 | 有主域名时调用 OneForAll |
| 端口组 | `small` | `small` 主要检测 80/443；`medium` 增加 8000/8080/8443 等 |
| DNS 解析 | 开 | 对发现的子域执行 DNS 解析 |
| HTTP 请求 | 固定关 | Web 请求统一由平台范围校验器执行 |
| 子域爆破 | 关 | 会明显增加 DNS 请求，仅在授权范围内使用 |
| 仅导出存活 | 关 | 关闭可保留部分 4xx/5xx 高价值资产 |
| 接管检查 | 关 | OneForAll 自带的 takeover 检查，默认不运行 |
| 运行超时 | `1800` 秒 | 60–7200 秒；超时会终止 OneForAll 进程 |

### 6.4 Subfinder / dnsx 参数

| 工具 | 参数 | 默认值 | 允许范围 |
|---|---|---:|---:|
| Subfinder | 速率上限 | 5/秒 | 1–50 |
| Subfinder | 运行超时 | 600 秒 | 60–3600 |
| dnsx | 速率上限 | 50/秒 | 1–500 |
| dnsx | 运行超时 | 600 秒 | 60–3600 |

### 6.5 敏感路径检测参数

| 参数 | 默认值 | 允许范围 | 含义 |
|---|---:|---:|---|
| 启用 | 开 | - | OneForAll 结果整理后自动继续检测 |
| 全局并发 | `10` | 1–100 | 整个任务同时进行的 HTTP 请求上限 |
| 单主机并发 | `2` | 1–10 | 对同一个主机同时进行的 HTTP 请求上限 |
| 请求超时 | `8` 秒 | 0.5–120 | 单次 HTTP 请求等待时间 |
| 失败重试 | `1` | 0–3 | 连接错误或超时后的额外尝试次数 |
| 软 404 阈值 | `0.85` | 0.5–0.99 | 页面与随机 404 基线越相似，越可能是伪存在 |
| 忽略 HTTPS 证书 | 关 | - | 自签名证书目标可开启；会降低 TLS 验证保护 |

并发示例：全局并发 10、单主机并发 2，表示任务总请求最多同时 10 个，但同一网站最多同时 2 个。这些参数不控制 OneForAll 内部并发。

### 6.6 Nuclei 参数

| 参数 | 默认值 | 允许范围 | 说明 |
|---|---:|---:|---|
| 启用 | 关 | - | 只对存活资产执行指纹定向模板 |
| 速率上限 | 2/秒 | 1–20 | Nuclei 全局请求速率 |
| 模板并发 | 2 | 1–5 | 同时处理模板数量 |
| 单模板进程超时 | 900 秒 | 60–3600 | 超时终止当前 Nuclei 子进程 |

## 7. paths.txt 批量规则

### 7.1 推荐的简单格式

直接编辑：

```bash
nano /root/web_asset_checker/paths.txt
```

每行一个站内路径：

```text
# 这是注释
/admin
/login
/signin
/swagger-ui.html
/v3/api-docs
/actuator/health
/.git/config
/backup.zip
/internal/status
```

保存后无需重启服务。每个新任务开始路径检测时，都会重新读取文件。设置页刷新后也会展示新规则。

规则：

- 允许写 `/admin` 或 `admin`，后者会自动补全 `/`。
- 空行和以 `#` 开头的行会被忽略。
- 重复路径仅保留第一条。
- 不允许写完整 `http://` 或 `https://` URL；这个文件只保存站内路径。
- 所有有效路径都会参与检测；无法推断功能的路径标记为 `CUSTOM`，不会被丢弃。

### 7.2 自动分类

| 路径特征 | 分类 |
|---|---|
| `login`、`signin`、`auth`、`sso` | `LOGIN` |
| `admin`、`control-panel` | `ADMIN` |
| `manage`、`manager`、`management`、`console`、`system` | `MANAGEMENT` |
| `/api` | `API` |
| `swagger`、`openapi`、`api-docs`、`docs`、`redoc` | `API_DOCS` |
| `actuator`、`prometheus`、`metrics`、`monitor`、`health`、`env` | `MONITORING` |
| `druid`、`phpmyadmin`、`adminer` | `DATABASE_MONITOR` |
| `phpinfo`、`debug`、`trace`、`profiler` | `DEBUG_INFO` |
| `.git`、`.svn`、`.hg` | `SOURCE_CONTROL` |
| `backup`、`.bak`、`.sql`、`.zip`、`.tar`、`.tgz`、`.7z`、`dump` | `BACKUP_FILE` |
| 其他有效路径 | `CUSTOM` |

### 7.3 高级格式

需要手工覆盖自动分类时：

```text
路径|分类|功能名称|标题关键词|是否启用
```

示例：

```text
/custom-admin|ADMIN|自定义管理入口|admin,control panel|1
/old-debug|DEBUG_INFO|旧调试页|debug,trace|0
```

- `1` 表示启用。
- `0`、`false`、`off` 或 `disabled` 表示禁用。
- 显式填写的分类、功能和关键词优先于自动推断。
- 在 Web 设置页点击“保存规则”时，文件会被规范化为这种结构化格式，两种格式的扫描效果相同。

## 8. 环境变量

当前服务从以下文件读取：

```text
/etc/web-asset-console.env
```

查看时注意该文件包含密码：

```bash
sudo ls -l /etc/web-asset-console.env
sudo nano /etc/web-asset-console.env
```

当前应用的结构如下：

```ini
WEBAPP_HOST=0.0.0.0
WEBAPP_PORT=8000
WEBAPP_USERNAME=admin
WEBAPP_PASSWORD=<web-login-password>
WEBAPP_SESSION_SECRET=<long-random-secret>
WEBAPP_COOKIE_SECURE=false
WEBAPP_DATA_DIR=/root/web_asset_checker/data

MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=webasset
MYSQL_PASSWORD=<mysql-password>
MYSQL_DATABASE=web_asset_checker

ONEFORALL_DIR=/root/OneForAll
ONEFORALL_PYTHON=/root/OneForAll/.venv/bin/python
SUBFINDER_BIN=/root/go/bin/subfinder
DNSX_BIN=/root/go/bin/dnsx
NUCLEI_BIN=/root/go/bin/nuclei
NUCLEI_TEMPLATES_DIR=/root/nuclei-templates
NUCLEI_ALLOWLIST_FILE=/root/web_asset_checker/nuclei-allowlist.txt
```

| 变量 | 说明 |
|---|---|
| `WEBAPP_HOST` | `0.0.0.0` 表示允许其他局域网主机访问 |
| `WEBAPP_PORT` | Web 服务端口 |
| `WEBAPP_USERNAME` / `WEBAPP_PASSWORD` | Web 登录凭据 |
| `WEBAPP_SESSION_SECRET` | Session 签名密钥，更改后已登录会话会失效 |
| `WEBAPP_COOKIE_SECURE` | 使用 HTTPS 后应设为 `true` |
| `WEBAPP_DATA_DIR` | 任务文件和 CSV 保存目录 |
| `MYSQL_*` | MySQL 连接参数 |
| `ONEFORALL_*` | OneForAll 目录和其独立 Python |
| `SUBFINDER_BIN` / `DNSX_BIN` | ProjectDiscovery 发现工具可执行文件绝对路径 |
| `NUCLEI_BIN` | Nuclei 可执行文件绝对路径 |
| `NUCLEI_TEMPLATES_DIR` | 官方 `nuclei-templates` 根目录 |
| `NUCLEI_ALLOWLIST_FILE` | 项目维护的模板路由白名单文件 |

修改环境变量后必须重启服务：

```bash
systemctl restart web-asset-console
```

## 9. MySQL 配置

### 9.1 数据库和用户

```sql
CREATE DATABASE IF NOT EXISTS web_asset_checker
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

CREATE USER 'webasset'@'127.0.0.1'
IDENTIFIED BY '<strong-random-password>';

GRANT ALL PRIVILEGES ON web_asset_checker.*
TO 'webasset'@'127.0.0.1';

FLUSH PRIVILEGES;
```

应用启动时会自动创建表，不会自动创建 MySQL 数据库和 MySQL 用户。

### 9.2 数据表

| 表 | 作用 |
|---|---|
| `tasks` | 任务状态、参数快照、进度、计数和错误 |
| `task_events` | 任务实时日志和 SSE 事件来源 |
| `assets` | 主域名、子域名、URL、IP、端口、状态码、标题和 Banner |
| `findings` | 敏感入口、功能分类、访问状态、置信度、优先级和复测建议 |

检查表：

```bash
set -a
source /etc/web-asset-console.env
set +a
/root/web_asset_checker/.venv/bin/python - <<'PY'
import os, pymysql
conn = pymysql.connect(
    host=os.environ["MYSQL_HOST"],
    port=int(os.environ["MYSQL_PORT"]),
    user=os.environ["MYSQL_USER"],
    password=os.environ["MYSQL_PASSWORD"],
    database=os.environ["MYSQL_DATABASE"],
)
with conn.cursor() as cursor:
    cursor.execute("SHOW TABLES")
    print([row[0] for row in cursor.fetchall()])
conn.close()
PY
```

### 9.3 MySQL 网络边界

`/etc/mysql/mysql.conf.d/mysqld.cnf` 应包含：

```ini
[mysqld]
bind-address = 127.0.0.1
port = 3306
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
```

确认监听：

```bash
ss -lntp | grep 3306
```

## 10. systemd 部署

当前服务文件：

```text
/etc/systemd/system/web-asset-console.service
```

当前 `/root` 部署使用：

```ini
[Unit]
Description=Web Asset Discovery Console
Wants=network-online.target
After=network-online.target mysql.service
Requires=mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/web_asset_checker
EnvironmentFile=/etc/web-asset-console.env
Environment=PYTHONUNBUFFERED=1
ExecStart=/root/web_asset_checker/.venv/bin/python -m webapp
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
```

仓库 `deploy/web-asset-console.service` 是 `/opt` + 专用用户的通用模板，不是当前 `/root` 服务器的实际路径。当前项目和 OneForAll 都位于 `/root`，因此当前服务使用 `User=root`。如要用于长期生产环境，应迁移到 `/opt` 并改用专用低权限用户。

常用命令：

```bash
systemctl status web-asset-console --no-pager
systemctl restart web-asset-console
systemctl stop web-asset-console
systemctl start web-asset-console
systemctl enable web-asset-console
journalctl -u web-asset-console -f
```

不需要在 systemd 运行时再手工执行 `python -m webapp`，否则会与 systemd 争用 8000 端口。

## 11. 从新服务器安装

### 11.1 系统依赖

```bash
apt update
apt install -y python3 python3-venv python3-pip mysql-server curl
systemctl enable --now mysql
```

OneForAll、Subfinder、dnsx、Nuclei 和官方模板应先安装到预期路径，或修改环境变量指向真实路径。

### 11.2 项目 Python

```bash
cd /root/web_asset_checker
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
```

### 11.3 配置 MySQL

```bash
systemctl enable --now mysql
mysql_secure_installation
sudo mysql
```

在 MySQL 中执行第 9.1 节的建库和授权 SQL，再将密码填入 `/etc/web-asset-console.env`。

### 11.4 环境文件和服务

```bash
install -m 600 /dev/null /etc/web-asset-console.env
nano /etc/web-asset-console.env
nano /etc/systemd/system/web-asset-console.service
systemctl daemon-reload
systemctl enable --now web-asset-console
```

生成 Session 密钥：

```bash
openssl rand -hex 32
```

部署后验证：

```bash
systemctl is-enabled web-asset-console
systemctl is-active web-asset-console
curl -I http://127.0.0.1:8000/login
ss -lntp | grep -E '(:8000|:3306)'
```

## 12. CLI 使用

CLI 不调用 OneForAll，直接从 `urls.txt` 读取 URL 或域名，并使用同一个 `paths.txt`。

```bash
cd /root/web_asset_checker
source .venv/bin/activate
python main.py -u urls.txt -p paths.txt -o result.csv -c 20 --per-host 3 -t 8 -r 1 --soft404 0.85
```

| CLI 参数 | 说明 |
|---|---|
| `-u`, `--urls` | URL/域名输入文件 |
| `-p`, `--paths` | 敏感路径文件 |
| `-o`, `--output` | CSV 输出文件 |
| `-c`, `--concurrency` | 全局并发，1–100 |
| `--per-host` | 单主机并发，1–10 |
| `-t`, `--timeout` | 请求超时，0.5–120 秒 |
| `-r`, `--retries` | 失败重试，0–3 |
| `-k`, `--insecure` | 忽略 HTTPS 证书验证 |
| `--soft404` | 软 404 相似度阈值，0.5–0.99 |

## 13. 输出和状态

### 13.1 assets.csv

资产结果主要包含：

- RootDomain
- Subdomain
- URL
- IP
- Port
- StatusCode
- Title
- Banner
- Server
- CDN
- Source

### 13.2 result.csv

敏感入口结果包含：

- RootDomain / Subdomain / BaseURL / EndpointURL
- Function / Category
- StatusCode / AccessState
- Confidence / ReviewPriority
- Title / Server / X-Powered-By / ContentType
- ResponseLength / RedirectURL / Similarity
- NextCheck / ScanTime

### 13.3 访问状态

| 状态 | 含义 |
|---|---|
| `ACCESSIBLE` | 路径可直接访问，仍需人工确认内容 |
| `AUTH_REQUIRED` | 返回 401，需要认证 |
| `FORBIDDEN` | 返回 403，路径存在但禁止访问 |
| `REDIRECTED` | 跳转到登录或其他页面 |
| `SOFT_404` | 与不存在页面高度相似，通常不作为有效发现 |

`P1/P2/P3` 是人工复测顺序，不是漏洞严重程度。

## 14. 测试和更新

修改代码后：

```bash
cd /root/web_asset_checker
source .venv/bin/activate
python -m unittest discover -s tests -v
python -m compileall -q main.py webapp
```

测试通过后：

```bash
systemctl restart web-asset-console
for i in $(seq 1 30); do
  curl -fsS -o /dev/null http://127.0.0.1:8000/login && break
  sleep 1
done
systemctl status web-asset-console --no-pager
```

服务启动需要数秒，不应在 `systemctl restart` 后立即将第一次 `curl` 失败判定为启动失败。

## 15. 备份与恢复

### 15.1 数据库备份

```bash
mkdir -p /root/mysql-backups
mysqldump -h 127.0.0.1 -u webasset -p \
  --single-transaction web_asset_checker \
  > /root/mysql-backups/web_asset_checker_$(date +%F_%H%M%S).sql
```

恢复：

```bash
mysql -h 127.0.0.1 -u webasset -p web_asset_checker \
  < /root/mysql-backups/<backup-file>.sql
```

### 15.2 配置和项目备份

```bash
cp -a /etc/web-asset-console.env /root/web-asset-console.env.backup
cp -a /etc/systemd/system/web-asset-console.service /root/web-asset-console.service.backup
tar -czf /root/web_asset_checker_$(date +%F_%H%M%S).tar.gz \
  /root/web_asset_checker
```

备份中包含密码时，必须限制读取权限。

## 16. 常见故障排查

### 16.1 网页无法访问

```bash
systemctl status web-asset-console --no-pager
ss -lntp | grep 8000
curl -I http://127.0.0.1:8000/login
journalctl -u web-asset-console -n 100 --no-pager
```

如仅监听 `127.0.0.1:8000`，检查 `WEBAPP_HOST`。需要局域网直连时使用 `0.0.0.0`。

### 16.2 MySQL `using password: NO`

说明手工启动应用时没有加载环境文件：

```bash
set -a
source /etc/web-asset-console.env
set +a
python -m webapp
```

正常运行建议使用 systemd，它会自动加载 `EnvironmentFile`。

### 16.3 MySQL `Access denied`

- 检查 `MYSQL_USER`、`MYSQL_PASSWORD` 和 `MYSQL_HOST`。
- 应用使用 `127.0.0.1`，MySQL 用户也是 `'webasset'@'127.0.0.1'`。
- 修改密码后要同时更新 `/etc/web-asset-console.env` 并重启服务。

### 16.4 `mysqld.cnf` 格式错误

所有 MySQL 选项必须位于配置分组之下：

```ini
[mysqld]
bind-address = 127.0.0.1
```

验证：

```bash
mysqld --validate-config
systemctl restart mysql
```

### 16.5 OneForAll 不可用

```bash
test -f /root/OneForAll/oneforall.py && echo script-ok
test -x /root/OneForAll/.venv/bin/python && echo python-ok
/root/OneForAll/.venv/bin/python --version
```

检查 `/etc/web-asset-console.env` 中的 `ONEFORALL_DIR` 和 `ONEFORALL_PYTHON`。

### 16.6 修改 paths.txt 后页面没变化

- 刷新“设置”页。
- 检查编辑的是 `/root/web_asset_checker/paths.txt`。
- 正在运行的任务使用开始检测时的规则；新规则主要对后续任务生效。

## 17. 安全建议

- 当前 `admin/admin` 只适合受控实验网络，不要将 8000 端口暴露到公网。
- 长期使用时应更换为随机 Web 密码，使用 Nginx HTTPS，并将 `WEBAPP_COOKIE_SECURE=true`。
- MySQL 3306 只监听 127.0.0.1，不在 UFW 中放行。
- 当前服务因项目在 `/root` 下而使用 root 运行；生产环境应迁移到 `/opt` 并使用专用用户。
- 只对明确授权的域名和 URL 创建任务。
- 路径“存在”不等于存在漏洞，所有结果都需要人工复测。

## 18. 日常使用速查

```bash
# 打开 Web
http://10.0.0.174:8000

# 查看服务
systemctl status web-asset-console --no-pager

# 实时日志
journalctl -u web-asset-console -f

# 编辑敏感路径
nano /root/web_asset_checker/paths.txt

# 修改应用配置
nano /etc/web-asset-console.env
systemctl restart web-asset-console

# 运行项目测试
cd /root/web_asset_checker
.venv/bin/python -m unittest discover -s tests -v

# 检查工具
test -f /root/OneForAll/oneforall.py && echo OneForAll-OK
/root/go/bin/subfinder -version
/root/go/bin/dnsx -version
/root/go/bin/nuclei -version
```
