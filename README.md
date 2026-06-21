# Web Asset Console

面向已授权安全测试的 Web 资产发现与敏感入口分类工具。项目保留原有 CLI，同时提供 FastAPI Web 控制台，将 OneForAll 资产发现、异步 Web 存活检测、软 404 识别、敏感路径分类和 CSV 报告串成一个任务流程。

## 功能

- OneForAll 批量主域名发现，支持 `small/medium` 端口组。
- 手工 URL 输入，可单独使用敏感路径检测器。
- 全局并发、单主机并发、超时、重试、TLS 校验和软 404 阈值配置。
- 路径规则可视化编辑，包含功能、分类和标题关键词。
- 敏感入口访问状态、置信度、P1/P2/P3 复测优先级和复测建议。
- MySQL 持久化任务、事件日志、资产与敏感入口。
- SSE 实时日志、进度、任务取消、CSV 下载。
- 登录、Session、CSRF 和授权范围过滤。
- Nuclei 安装状态展示；第一版不自动执行 Nuclei 模板。

## 项目结构

```text
web_asset_checker/
├── main.py                 # 原有 CLI 扫描器
├── paths.txt               # 敏感路径分类规则
├── webapp/
│   ├── app.py              # FastAPI 页面与 API
│   ├── runner.py           # OneForAll 和扫描任务执行器
│   ├── database.py         # MySQL 数据层
│   ├── classifier.py       # 功能识别与优先级
│   ├── templates/          # Jinja2 页面
│   └── static/             # CSS 与 JavaScript
├── tests/
├── deploy/
├── requirements.txt
└── .env.example
```

## Python 环境

Web 控制台建议使用 Python 3.11 或更高版本。当前工具和 OneForAll 使用独立虚拟环境。

```bash
cd /opt/web_asset_checker
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

OneForAll 示例路径：

```text
/opt/OneForAll
/opt/OneForAll/.venv/bin/python
```

## MySQL 初始化

应用会自动创建数据表，但数据库和账号需要由管理员预先创建：

```sql
CREATE DATABASE web_asset_checker
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER 'webasset'@'127.0.0.1'
  IDENTIFIED BY '替换为高强度密码';

GRANT ALL PRIVILEGES ON web_asset_checker.*
  TO 'webasset'@'127.0.0.1';

FLUSH PRIVILEGES;
```

应用不需要 MySQL 全局管理权限。

## 环境变量

复制示例并修改：

```bash
sudo cp .env.example /etc/web-asset-console.env
sudo chmod 600 /etc/web-asset-console.env
sudo editor /etc/web-asset-console.env
```

必须修改：

```text
WEBAPP_PASSWORD
WEBAPP_SESSION_SECRET
MYSQL_PASSWORD
ONEFORALL_DIR
ONEFORALL_PYTHON
```

如果使用 Nginx HTTPS，将以下配置改成 `true`：

```text
WEBAPP_COOKIE_SECURE=true
```

## 开发运行

当前终端加载环境变量后运行：

```bash
set -a
source /etc/web-asset-console.env
set +a

cd web_asset_checker
source .venv/bin/activate
python -m webapp --host 127.0.0.1 --port 8000
```

浏览器访问：

```text
http://127.0.0.1:8000
```

默认开发账号为 `admin/change-me`，只能用于本机调试。远程访问前必须通过环境变量修改密码。

## systemd

```bash
sudo cp deploy/web-asset-console.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now web-asset-console
sudo systemctl status web-asset-console
```

服务使用普通用户 `webasset` 运行。该用户需要：

- 读取 OneForAll 程序和虚拟环境。
- 写入项目 `data/`。
- 写入 OneForAll 自身运行所需的结果目录。
- 连接 MySQL。

## Nginx

`deploy/nginx-web-asset-console.conf` 是 HTTPS 反向代理示例。替换域名和证书路径后启用。

不要在没有登录保护和 HTTPS 的情况下直接把 Uvicorn 暴露到公网：

```text
错误：--host 0.0.0.0 并直接开放 8000
推荐：Nginx HTTPS → 127.0.0.1:8000
```

SSE 实时日志要求 Nginx 关闭代理缓冲，示例配置已经包含：

```nginx
proxy_buffering off;
proxy_read_timeout 3600s;
```

## Web 使用流程

1. 登录控制台。
2. 输入已授权主域名或手工 URL。
3. 配置 OneForAll 与敏感路径参数。
4. 勾选授权确认并创建任务。
5. 在任务详情查看进度和实时日志。
6. 在资产中心和敏感入口中心筛选结果。
7. 下载 `assets.csv` 与 `result.csv` 进行人工复测。

## CLI

原有命令仍然可用：

```bash
python main.py -u urls.txt -p paths.txt -o result.csv -c 20 -t 8 -r 1
```

自签名证书目标：

```bash
python main.py -k
```

调整软 404 阈值：

```bash
python main.py --soft404 0.85
```

## 路径规则格式

推荐直接使用“一行一个路径”，保存 `paths.txt` 后，下一个扫描任务会自动读取全部规则：

```text
/admin
/signin
/v3/api-docs
/internal/status
```

工具会根据路径名自动识别 `LOGIN`、`ADMIN`、`MANAGEMENT`、`API`、`API_DOCS`、`MONITORING`、`DATABASE_MONITOR`、`DEBUG_INFO`、`SOURCE_CONTROL` 和 `BACKUP_FILE`。无法确定类型的路径不会被丢弃，会作为 `CUSTOM` 类型正常检测。

需要手工指定分类时，可使用扩展格式：

```text
路径|分类|功能名称|关键词|是否启用
```

示例：

```text
/login|LOGIN|登录入口|login,sign in,登录|1
/.git/config|SOURCE_CONTROL|Git 配置文件|repositoryformatversion|1
```

显式填写的分类、功能名称和关键词优先于自动识别结果。空行、重复路径和以 `#` 开头的注释会被自动忽略。

## 测试

```bash
python -m unittest discover -s tests -v
python -m compileall -q main.py webapp
```

## 使用边界

- 仅扫描自己拥有或已经获得明确书面授权的目标。
- 本工具只进行存在性探测和结果整理，不进行登录绕过或漏洞利用。
- 对 Git 配置、备份文件等结果只确认存在并记录证据，不下载完整敏感内容。
- P1/P2/P3 表示人工复测优先级，不等同于漏洞严重等级。
