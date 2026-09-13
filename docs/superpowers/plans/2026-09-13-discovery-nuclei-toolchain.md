# Discovery and Controlled Nuclei Toolchain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在保留 OneForAll 的前提下加入 Subfinder、dnsx 和受控 Nuclei，并通过快速、综合、兼容、自定义四种模式让用户明确选择扫描链路。

**Architecture:** 新建独立 `webapp/toolchain.py` 负责外部工具命令构建、JSONL 解析、来源合并和 Nuclei 结果转换；`TaskManager` 只负责编排阶段与数据库写入。所有发现结果先合并去重，再由现有 `ScopeGuard` 做请求前 DNS/IP/端口校验；Nuclei 只接收已存活且再次校验过的 URL，固定关闭重定向并使用服务端模板白名单。

**Tech Stack:** Python 3.11、FastAPI/Pydantic、asyncio subprocess、ProjectDiscovery Subfinder/dnsx/Nuclei、原生 unittest、Jinja2/JavaScript。

---

### Task 1: 请求模型、工具配置与预设解析

**Files:**
- Modify: `webapp/config.py`
- Modify: `webapp/app.py`
- Create: `webapp/toolchain.py`
- Test: `tests/test_toolchain.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_comprehensive_preset_keeps_oneforall_and_enables_pd_chain():
    resolved = resolve_discovery_config("comprehensive", {}, {}, {})
    assert resolved.oneforall_enabled is True
    assert resolved.subfinder_enabled is True
    assert resolved.dnsx_enabled is True

def test_nuclei_defaults_are_bounded():
    request = NucleiRequest()
    assert request.enabled is False
    assert request.rate_limit == 2
    assert request.concurrency == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_toolchain -v`
Expected: FAIL because the new models and resolver do not exist.

- [ ] **Step 3: Implement exact request/config contracts**

```python
DiscoveryPreset = Literal["quick", "comprehensive", "legacy", "custom"]

class SubfinderRequest(BaseModel):
    enabled: bool = True
    rate_limit: int = Field(default=5, ge=1, le=50)
    timeout: int = Field(default=600, ge=60, le=3600)

class DnsxRequest(BaseModel):
    enabled: bool = True
    rate_limit: int = Field(default=50, ge=1, le=500)
    timeout: int = Field(default=600, ge=60, le=3600)

class NucleiRequest(BaseModel):
    enabled: bool = False
    rate_limit: int = Field(default=2, ge=1, le=20)
    concurrency: int = Field(default=2, ge=1, le=5)
    timeout: int = Field(default=900, ge=60, le=3600)
```

Add `subfinder_binary`, `dnsx_binary`, `nuclei_templates_dir`, and `nuclei_allowlist_file` to `AppSettings`, resolve them only from environment/server-owned paths, and expose availability in `tool_status()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_toolchain -v`
Expected: PASS for preset and bounded-default tests.

- [ ] **Step 5: Commit**

```bash
git add webapp/config.py webapp/app.py webapp/toolchain.py tests/test_toolchain.py
git commit -m "feat: add discovery presets and tool contracts"
```

### Task 2: Subfinder/dnsx adapters and merged discovery

**Files:**
- Modify: `webapp/toolchain.py`
- Modify: `webapp/runner.py`
- Test: `tests/test_toolchain.py`

- [ ] **Step 1: Write failing parser and merge tests**

```python
def test_subfinder_jsonl_keeps_sources_and_scope_root(tmp_path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text('{"host":"api.example.com","sources":["crtsh","hackertarget"]}\n')
    rows = parse_subfinder_jsonl(path, ["example.com"])
    assert rows == [{"host": "api.example.com", "root_domain": "example.com", "sources": ["crtsh", "hackertarget"]}]

def test_merge_assets_combines_source_labels():
    rows = merge_assets([asset("https://api.example.com", "OneForAll"), asset("https://api.example.com", "Subfinder+dnsx")])
    assert rows[0]["source"] == "OneForAll,Subfinder+dnsx"
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m unittest tests.test_toolchain -v`
Expected: FAIL because JSONL parsing and source-aware merge are absent.

- [ ] **Step 3: Implement adapters and orchestration**

Build argv arrays without a shell:

```python
[subfinder, "-dL", domains_file, "-silent", "-json", "-cs", "-rl", str(rate), "-o", output]
[dnsx, "-l", hosts_file, "-silent", "-json", "-resp", "-a", "-aaaa", "-cname", "-rl", str(rate), "-o", output]
```

For each dnsx row, retain only names belonging to an authorized root, emit candidates only for authorized scheme/port combinations, merge duplicate URLs by joining source names, then pass every candidate through `ScopeGuard.validate_target()` before HTTP probing.

- [ ] **Step 4: Run focused tests**

Run: `python -m unittest tests.test_toolchain tests.test_core -v`
Expected: PASS, including legacy OneForAll parser tests.

- [ ] **Step 5: Commit**

```bash
git add webapp/toolchain.py webapp/runner.py tests/test_toolchain.py
git commit -m "feat: integrate subfinder and dnsx discovery"
```

### Task 3: Controlled Nuclei allowlist execution

**Files:**
- Create: `nuclei-allowlist.txt`
- Modify: `webapp/toolchain.py`
- Modify: `webapp/runner.py`
- Test: `tests/test_toolchain.py`

- [ ] **Step 1: Write failing safety tests**

```python
def test_nuclei_command_is_allowlisted_and_bounded(tmp_path):
    command = build_nuclei_command("nuclei", tmp_path / "urls.txt", tmp_path / "out.jsonl", [tmp_path / "git-config.yaml"], 2, 2)
    assert "-disable-unsigned-templates" in command
    assert "-disable-redirects" in command
    assert command[command.index("-rate-limit") + 1] == "2"
    assert "dos,brute-force,intrusive,fuzz" in command

def test_nuclei_jsonl_maps_high_severity_to_p1(tmp_path):
    # Parse a representative official-template JSONL record.
    assert parse_nuclei_jsonl(...)[0]["priority"] == "P1"
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m unittest tests.test_toolchain -v`
Expected: FAIL because safe command and parser are missing.

- [ ] **Step 3: Implement the bounded runner**

Resolve each non-comment allowlist line under `NUCLEI_TEMPLATES_DIR`, reject traversal/symlinks outside that directory, and reject an empty allowlist. Build Nuclei with exact repeated `-t <file>` arguments plus `-pt http`, `-disable-unsigned-templates`, `-disable-redirects`, `-exclude-tags dos,brute-force,intrusive,fuzz`, `-rate-limit`, `-concurrency`, `-bulk-size 2`, `-jsonl`, and `-omit-raw`. Revalidate every live URL immediately before writing the target list; parse JSONL into the existing finding schema and merge it with path findings.

- [ ] **Step 4: Run focused and full tests**

Run: `python -m unittest discover -s tests -v`
Expected: all tests PASS and no external binary is launched by unit tests.

- [ ] **Step 5: Commit**

```bash
git add nuclei-allowlist.txt webapp/toolchain.py webapp/runner.py tests/test_toolchain.py
git commit -m "feat: add allowlisted nuclei verification"
```

### Task 4: Dashboard selection, status and documentation

**Files:**
- Modify: `webapp/templates/dashboard.html`
- Modify: `webapp/templates/settings.html`
- Modify: `webapp/templates/base.html`
- Modify: `webapp/static/app.js`
- Modify: `webapp/static/style.css`
- Modify: `README.md`
- Modify: `PROJECT_GUIDE.md`
- Test: `tests/test_core.py`

- [ ] **Step 1: Add a failing template contract test**

```python
def test_dashboard_exposes_toolchain_controls(self):
    source = (settings.project_root / "webapp/templates/dashboard.html").read_text("utf-8")
    for control in ("discovery-preset", "subfinder-enabled", "dnsx-enabled", "nuclei-enabled"):
        self.assertIn(f'id="{control}"', source)
```

- [ ] **Step 2: Run the test and confirm failure**

Run: `python -m unittest tests.test_core.WebAppShapeTests.test_dashboard_exposes_toolchain_controls -v`
Expected: FAIL because controls are absent.

- [ ] **Step 3: Implement the four-mode UI**

Add preset explanations:

```text
快速：Subfinder → dnsx
综合（推荐）：Subfinder + OneForAll → 合并去重 → dnsx
兼容：OneForAll + 内置 MassDNS
自定义：独立选择发现器与 dnsx
```

Preset changes update module switches; custom edits switch the preset to `custom`. Nuclei remains a separate unchecked card showing the fixed template count and conservative defaults. Update the pipeline to `目标 → 多源发现 → DNS 验证 → 范围复检 → 路径检测 → Nuclei → 报告`.

- [ ] **Step 4: Document operation and limitations**

Document environment variables, presets, allowlist review, install versions, deployment/rollback commands, and the fact that Nuclei is not a replacement for manual confirmation. Preserve all existing server credentials as environment-only data and never add them to Git.

- [ ] **Step 5: Run full tests and commit**

Run: `python -m unittest discover -s tests -v`
Expected: all tests PASS.

```bash
git add webapp/templates webapp/static README.md PROJECT_GUIDE.md tests/test_core.py
git commit -m "feat: expose selectable security toolchain"
```

### Task 5: Linux install, deploy, health check and push

**Files:**
- Modify: `/etc/web-asset-console.env` on Linux only if new path variables are required
- Deploy: `/root/web_asset_checker`

- [ ] **Step 1: Capture a non-mutating server inventory**

Run over SSH: `systemctl is-active web-asset-console; command -v subfinder dnsx nuclei; nuclei -version; go version`
Expected: current service remains `active`; missing tools are identified without restarting it.

- [ ] **Step 2: Back up the application and environment**

Run over SSH: `tar -C /root -czf /root/web_asset_checker-before-toolchain-<timestamp>.tar.gz web_asset_checker && cp -a /etc/web-asset-console.env /etc/web-asset-console.env.before-toolchain-<timestamp>`
Expected: both backup files exist and current service remains active.

- [ ] **Step 3: Install only missing Linux binaries and deploy code**

Install pinned ProjectDiscovery binaries under `/root/go/bin`, upload changed source files by SFTP, preserve `/root/web_asset_checker/data`, server environment values, MySQL data, OneForAll, and user-created path rules.

- [ ] **Step 4: Verify before and after the one required restart**

Run Linux tests from `/root/web_asset_checker`, then restart `web-asset-console` once. Check `systemctl is-active`, `curl -fsS http://127.0.0.1:8000/login`, and from Windows `http://10.0.0.174:8000/login`. If any check fails, restore the backups and restart the prior version.

- [ ] **Step 5: Merge and push**

```bash
git switch main
git merge --no-ff codex/discovery-nuclei-adapters
git push https://github.com/quvian666-coder/web_asset_checker.git main
```

Expected: GitHub `main` points to the tested deployment commit and the Linux page shows the new preset and Nuclei controls.
