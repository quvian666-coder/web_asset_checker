# Web Asset Console 项目配置与部署说明

> 更新日期：2026-06-21
> 使用范围：仅用于自有资产或已获得明确授权的安全测试。

## 1. 项目定位

Web Asset Console 是一个轻量级 Web 资产发现和敏感路径辅助检测平台，将以下工作串成一个自动任务：

```text
输入已授权主域名
    ↓
OneForAll 子域名发现和 Web 请求
    ↓
解析、范围校验和 URL 去重
    ↓
读取 paths.txt 的全部启用规则
    ↓
存活检测、软 404 识别和敏感路径存在性检测
    ↓
功能分类、访问状态和复测优先级计算
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
- 可选 DNS 解析、HTTP 请求、子域爆破、存活过滤和接管检查。
- 平台固定输出 JSON，再从 JSON 中提取 Web URL。
- 只保留属于输入主域名范围的结果。

### 4.2 Python 敏感路径检测器

- 检测基础 URL 是否存活。
- 记录状态码、标题、响应长度、`Server`、`X-Powered-By`、Content-Type 和跳转地址。
- 对 `paths.txt` 的全部启用规则进行存在性检测。
- 使用随机不存在路径建立 404 基线，降低“所有路径都返回 200”造成的误报。
- 不会提交表单、猜解密码或执行漏洞利用。

### 4.3 Nuclei

- 当前只检测 Nuclei 是否安装并在设置页展示。
- 第一版不会自动运行 Nuclei 模板，避免未审核模板扩大请求范围。

### 4.4 httpx

- `requirements.txt` 中的 `httpx` 是 Python HTTP 依赖。
- Linux 上安装的 Go `httpx` 不在当前 Web 任务主链路中，不需要另外配置参数。

## 5. Web 任务的自动执行方式

使用者在 Web 页面中只需：

1. 输入已授权的主域名。
2. 保持“OneForAll 资产发现”和“敏感路径检测”开启。
3. 设置参数并勾选授权确认。
4. 点击“创建并运行任务”。

后续流程全部自动执行：OneForAll 完成后，平台自动解析 URL、去重、读取 `paths.txt`、运行敏感路径检测、存入 MySQL 并生成 CSV。不需要手工导入 OneForAll 结果。

手工 URL 是可选补充：

- OneForAll 开启时：与 OneForAll 结果合并后去重。
- OneForAll 关闭时：必须提供手工 URL。
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

### 6.2 OneForAll 参数

| 参数 | 默认值 | 说明 |
|---|---:|---|
| 启用 | 开 | 有主域名时调用 OneForAll |
| 端口组 | `small` | `small` 主要检测 80/443；`medium` 增加 8000/8080/8443 等 |
| DNS 解析 | 开 | 对发现的子域执行 DNS 解析 |
| HTTP 请求 | 开 | 提取可用 Web URL、状态码和标题 |
| 子域爆破 | 关 | 会明显增加 DNS 请求，仅在授权范围内使用 |
| 仅导出存活 | 关 | 关闭可保留部分 4xx/5xx 高价值资产 |
| 接管检查 | 关 | OneForAll 自带的 takeover 检查，默认不运行 |
| 运行超时 | `1800` 秒 | 60–7200 秒；超时会终止 OneForAll 进程 |

### 6.3 敏感路径检测参数

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
NUCLEI_BIN=/root/go/bin/nuclei
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
| `NUCLEI_BIN` | Nuclei 可执行文件绝对路径 |

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

OneForAll 和 Nuclei 应先安装到预期路径，或修改环境变量指向真实路径。

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
/root/go/bin/nuclei -version
```
