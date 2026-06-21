# Paths 批量规则识别 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `paths.txt` 支持一行一个路径的批量添加，并为常见路径自动生成分类、功能名称和关键词，同时保留原有结构化格式。

**Architecture:** `webapp/classifier.py` 统一负责规则加载与元数据推断，扫描执行器继续只消费 `PathRule`，不修改请求逻辑。简单格式采用自动推断，结构化格式中的显式字段始终覆盖推断结果。

**Tech Stack:** Python 3.12、unittest、FastAPI、systemd

---

### Task 1: 锁定批量规则行为

**Files:**
- Modify: `tests/test_core.py`
- Test: `tests/test_core.py`

- [ ] **Step 1: 添加简单路径测试**

```python
def test_plain_rules_are_loaded_and_classified(self) -> None:
    content = "/signin\n/internal/status\n"
    # /signin 自动识别为 LOGIN，未知路径仍作为 CUSTOM 加载。
```
- [ ] **Step 2: 运行测试并确认旧实现失败**

```bash
python -m unittest tests.test_core.ClassificationTests -v
```

Expected: `/signin` 或 `/internal/status` 的自动分类断言失败。

### Task 2: 实现路径元数据推断

**Files:**
- Modify: `webapp/classifier.py`

- [ ] **Step 1: 新增 `infer_metadata()`**

```python
def infer_metadata(rule_path: str) -> tuple[str, str, tuple[str, ...]]:
    """优先精确规则，其次按路径关键词推断，最后返回 CUSTOM。"""
```

- [ ] **Step 2: 让 `load_rules()` 使用推断结果**

简单格式 `/signin` 直接使用推断结果；`/signin|ADMIN|...` 仍以显式字段为准。

- [ ] **Step 3: 运行核心测试**

```bash
python -m unittest discover -s tests -v
```

Expected: 全部测试通过。

### Task 3: 更新用户说明和服务器配置

**Files:**
- Modify: `README.md`
- Modify: `/etc/web-asset-console.env`（服务器）

- [ ] **Step 1: 记录两种规则格式**

```text
/signin
/custom|CUSTOM|自定义入口|keyword1,keyword2|1
```

- [ ] **Step 2: 将 `WEBAPP_PASSWORD` 修改为 `admin`**

- [ ] **Step 3: 部署并重启服务**

```bash
systemctl restart web-asset-console
systemctl is-active web-asset-console
```

### Task 4: 端到端验证

**Files:**
- Verify: `/root/web_asset_checker/paths.txt`

- [ ] **Step 1: 用临时规则文件验证批量解析，不污染正式规则**

```bash
python -m unittest discover -s tests -v
```

- [ ] **Step 2: 使用 `/etc/web-asset-console.env` 中配置的管理员凭据登录**

- [ ] **Step 3: 打开设置页，确认所有 `paths.txt` 规则均显示且工具状态正常**
