from __future__ import annotations

import asyncio
import hmac
import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from .classifier import PathRule, load_rules, save_rules
from .config import AppSettings
from .database import Database
from .findings import FindingReviewUpdate
from .runner import TaskManager
from .scope import ScopeViolation
from .security import LoginRateLimiter, apply_security_headers


settings = AppSettings.from_env()
database = Database(
    host=settings.mysql_host,
    port=settings.mysql_port,
    user=settings.mysql_user,
    password=settings.mysql_password,
    database=settings.mysql_database,
)
manager: TaskManager | None = None
login_limiter = LoginRateLimiter(
    settings.login_max_attempts,
    settings.login_window_seconds,
    settings.login_block_seconds,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global manager
    settings.ensure_directories()
    database.initialize()
    manager = TaskManager(settings, database)
    yield
    if manager:
        active_ids = [task_id for task_id, task in manager.tasks.items() if not task.done()]
        for task_id in active_ids:
            await manager.cancel(task_id)
        active = [manager.tasks[task_id] for task_id in active_ids]
        if active:
            await asyncio.gather(*active, return_exceptions=True)


app = FastAPI(title="Web Asset Console", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="lax",
    https_only=settings.cookie_secure,
    max_age=8 * 60 * 60,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    content_type = response.headers.get("Content-Type", "").lower()
    if content_type.startswith("text/event-stream"):
        return apply_security_headers(response, sensitive=False)
    return apply_security_headers(
        response,
        sensitive=not request.url.path.startswith("/static/"),
    )

webapp_dir = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=webapp_dir / "templates")
app.mount("/static", StaticFiles(directory=webapp_dir / "static"), name="static")


class OneForAllRequest(BaseModel):
    enabled: bool = True
    brute: bool = False
    dns: bool = True
    req: bool = True
    port: Literal["small", "medium"] = "small"
    alive: bool = False
    takeover: bool = False
    timeout: int = Field(default=1800, ge=60, le=7200)


class CheckerRequest(BaseModel):
    enabled: bool = True
    concurrency: int = Field(default=10, ge=1, le=100)
    per_host: int = Field(default=2, ge=1, le=10)
    timeout: float = Field(default=8, ge=0.5, le=120)
    retries: int = Field(default=1, ge=0, le=3)
    insecure: bool = False
    soft404_threshold: float = Field(default=0.85, ge=0.5, le=0.99)


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


class TaskRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    domains: list[str] = Field(default_factory=list, max_length=500)
    manual_urls: list[str] = Field(default_factory=list, max_length=1000)
    authorization_confirmed: bool
    max_assets: int = Field(default=500, ge=1, le=5000)
    oneforall: OneForAllRequest = Field(default_factory=OneForAllRequest)
    checker: CheckerRequest = Field(default_factory=CheckerRequest)
    scope: ScopeRequest = Field(default_factory=ScopeRequest)


class RuleRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    category: str = Field(default="UNKNOWN", min_length=1, max_length=50)
    function: str = Field(default="未分类敏感路径", min_length=1, max_length=100)
    keywords: list[str] = Field(default_factory=list, max_length=20)
    enabled: bool = True


class FindingReviewRequest(BaseModel):
    status: Literal[
        "PENDING_RETEST",
        "CONFIRMED",
        "FALSE_POSITIVE",
        "FIXED",
        "ACCEPTED_RISK",
    ]
    assignee: str = Field(default="", max_length=80)
    notes: str = Field(default="", max_length=5000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    evidence_summary: str = Field(default="", max_length=5000)
    mark_retested: bool = False


def _logged_in(request: Request) -> bool:
    return request.session.get("username") == settings.username


def _csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(24)
        request.session["csrf_token"] = token
    return token


def require_api_auth(request: Request) -> None:
    if not _logged_in(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录")


def require_csrf(request: Request) -> None:
    require_api_auth(request)
    expected = request.session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF 校验失败")


def page_context(request: Request, **extra: object) -> dict[str, object]:
    return {
        "request": request,
        "username": settings.username,
        "csrf_token": _csrf_token(request),
        "default_password_warning": settings.uses_default_password,
        "tool_status": settings.tool_status(),
        **extra,
    }


def login_redirect(request: Request) -> RedirectResponse | None:
    if not _logged_in(request):
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)
    return None


def _login_key(request: Request, username: str) -> str:
    client_ip = request.client.host if request.client else "unknown"
    return f"{client_ip}:{username.strip().lower()}"


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    if _logged_in(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "csrf_token": _csrf_token(request), "next": next, "error": ""},
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
):
    login_key = _login_key(request, username)
    retry_after = login_limiter.check(login_key)
    if retry_after:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "csrf_token": _csrf_token(request),
                "next": next,
                "error": "登录失败次数过多，请稍后重试",
            },
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )
    expected_csrf = request.session.get("csrf_token", "")
    valid_csrf = bool(expected_csrf) and hmac.compare_digest(expected_csrf, csrf_token)
    valid_user = hmac.compare_digest(username, settings.username)
    valid_password = hmac.compare_digest(password, settings.password)
    if not valid_csrf or not valid_user or not valid_password:
        retry_after = login_limiter.record_failure(login_key)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "csrf_token": _csrf_token(request),
                "next": next,
                "error": "用户名或密码错误",
            },
            status_code=429 if retry_after else 400,
            headers={"Retry-After": str(retry_after)} if retry_after else None,
        )
    login_limiter.reset(login_key)
    request.session.clear()
    request.session["username"] = settings.username
    request.session["csrf_token"] = secrets.token_urlsafe(24)
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
    return RedirectResponse(safe_next, status_code=303)


@app.post("/logout")
async def logout(request: Request, _: None = Depends(require_csrf)):
    request.session.clear()
    return JSONResponse({"ok": True})


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if redirect := login_redirect(request):
        return redirect
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        page_context(
            request,
            active_page="dashboard",
            stats=database.dashboard_stats(),
            tasks=database.list_tasks(12),
            assets=database.list_assets(limit=8),
            findings=database.list_finding_cases(limit=8),
        ),
    )


@app.get("/tasks", response_class=HTMLResponse)
async def tasks_page(request: Request):
    if redirect := login_redirect(request):
        return redirect
    return templates.TemplateResponse(
        request,
        "tasks.html",
        page_context(request, active_page="tasks", tasks=database.list_tasks(200)),
    )


@app.get("/tasks/{task_id}", response_class=HTMLResponse)
async def task_detail(request: Request, task_id: str):
    if redirect := login_redirect(request):
        return redirect
    task = database.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return templates.TemplateResponse(
        request,
        "task_detail.html",
        page_context(
            request,
            active_page="tasks",
            task=task,
            events=database.get_events(task_id, 0, 200),
            assets=database.list_assets(task_id, 100),
            findings=database.list_findings(task_id, 100),
        ),
    )


@app.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request, task_id: str | None = None):
    if redirect := login_redirect(request):
        return redirect
    return templates.TemplateResponse(
        request,
        "assets.html",
        page_context(
            request,
            active_page="assets",
            selected_task=task_id or "",
            tasks=database.list_tasks(100),
            assets=database.list_assets(task_id, 1000),
        ),
    )


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, task_id: str | None = None):
    if redirect := login_redirect(request):
        return redirect
    return templates.TemplateResponse(
        request,
        "findings.html",
        page_context(
            request,
            active_page="findings",
            selected_task=task_id or "",
            tasks=database.list_tasks(100),
            findings=database.list_finding_cases(task_id, 1000),
        ),
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    if redirect := login_redirect(request):
        return redirect
    return templates.TemplateResponse(
        request,
        "settings.html",
        page_context(
            request,
            active_page="settings",
            rules=load_rules(settings.paths_file),
        ),
    )


@app.post("/api/tasks")
async def create_task(payload: TaskRequest, _: None = Depends(require_csrf)):
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail="必须确认已获得目标授权")
    if not payload.oneforall.enabled and not payload.manual_urls:
        raise HTTPException(status_code=400, detail="关闭 OneForAll 时必须提供手工 URL")
    if payload.oneforall.enabled and payload.domains and not payload.checker.enabled:
        raise HTTPException(status_code=400, detail="OneForAll 安全模式需要开启 Web 路径检测器")
    if manager is None:
        raise HTTPException(status_code=503, detail="任务管理器尚未启动")
    config = payload.model_dump(mode="json")
    try:
        task_id = manager.create(payload.name, config)
    except (ValueError, ScopeViolation) as exc:
        detail = f"[{exc.code}] {exc}" if isinstance(exc, ScopeViolation) else str(exc)
        raise HTTPException(status_code=400, detail=detail) from exc
    return {"id": task_id, "url": f"/tasks/{task_id}"}


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str, _: None = Depends(require_api_auth)):
    task = database.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task


@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, _: None = Depends(require_csrf)):
    if manager is None or not await manager.cancel(task_id):
        raise HTTPException(status_code=409, detail="任务当前无法取消")
    return {"ok": True}


@app.post("/api/tasks/{task_id}/clone")
async def clone_task(task_id: str, _: None = Depends(require_csrf)):
    if manager is None:
        raise HTTPException(status_code=503, detail="任务管理器尚未启动")
    try:
        new_id = manager.clone(task_id, "full")
    except (ValueError, ScopeViolation) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": new_id, "url": f"/tasks/{new_id}"}


@app.post("/api/tasks/{task_id}/retry")
async def retry_task(task_id: str, _: None = Depends(require_csrf)):
    if manager is None:
        raise HTTPException(status_code=503, detail="任务管理器尚未启动")
    try:
        new_id = manager.clone(task_id, "retry")
    except (ValueError, ScopeViolation) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": new_id, "url": f"/tasks/{new_id}"}


@app.post("/api/tasks/{task_id}/rerun-checker")
async def rerun_checker(task_id: str, _: None = Depends(require_csrf)):
    if manager is None:
        raise HTTPException(status_code=503, detail="任务管理器尚未启动")
    try:
        new_id = manager.clone(task_id, "checker_only")
    except (ValueError, ScopeViolation) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": new_id, "url": f"/tasks/{new_id}"}


@app.get("/api/tasks/{task_id}/events")
async def task_events(request: Request, task_id: str, after: int = 0):
    require_api_auth(request)
    if database.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")

    async def stream():
        last_id = max(0, after)
        idle_terminal_ticks = 0
        while True:
            if await request.is_disconnected():
                break
            events = database.get_events(task_id, last_id, 200)
            for event in events:
                last_id = event["id"]
                yield f"id: {last_id}\nevent: log\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
            task = database.get_task(task_id)
            if task:
                status_data = {
                    "status": task["status"],
                    "stage": task["stage"],
                    "progress": task["progress"],
                    "counts": task["counts"],
                    "error": task["error"],
                }
                yield f"event: status\ndata: {json.dumps(status_data, ensure_ascii=False)}\n\n"
                if task["status"] in {"SUCCESS", "FAILED", "CANCELLED"}:
                    idle_terminal_ticks += 1
                    if idle_terminal_ticks >= 2:
                        break
            await asyncio.sleep(0.8)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/tasks/{task_id}/assets")
async def task_assets(task_id: str, _: None = Depends(require_api_auth)):
    return database.list_assets(task_id, 5000)


@app.get("/api/tasks/{task_id}/findings")
async def task_findings(task_id: str, _: None = Depends(require_api_auth)):
    return database.list_findings(task_id, 5000)


@app.get("/api/finding-cases/{case_id}")
async def get_finding_case(case_id: int, _: None = Depends(require_api_auth)):
    item = database.get_finding_case(case_id)
    if item is None:
        raise HTTPException(status_code=404, detail="复测项不存在")
    return item


@app.patch("/api/finding-cases/{case_id}")
async def update_finding_case(
    case_id: int,
    payload: FindingReviewRequest,
    request: Request,
    _: None = Depends(require_csrf),
):
    try:
        update = FindingReviewUpdate.create(**payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    item = database.update_finding_case(case_id, update, request.session["username"])
    if item is None:
        raise HTTPException(status_code=404, detail="复测项不存在")
    return item


@app.get("/api/finding-cases/{case_id}/events")
async def finding_case_events(case_id: int, _: None = Depends(require_api_auth)):
    if database.get_finding_case(case_id) is None:
        raise HTTPException(status_code=404, detail="复测项不存在")
    return database.list_finding_case_events(case_id)


@app.get("/api/tasks/{task_id}/download/{kind}")
async def download_result(task_id: str, kind: Literal["assets", "result"], _: None = Depends(require_api_auth)):
    if database.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    filename = "assets.csv" if kind == "assets" else "result.csv"
    path = settings.data_dir / "tasks" / task_id / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="结果文件尚未生成")
    return FileResponse(path, filename=filename, media_type="text/csv")


@app.get("/api/rules")
async def get_rules(_: None = Depends(require_api_auth)):
    return [rule.to_dict() for rule in load_rules(settings.paths_file)]


@app.put("/api/rules")
async def update_rules(payload: list[RuleRequest], _: None = Depends(require_csrf)):
    rules = [
        PathRule(
            path=item.path,
            category=item.category,
            function=item.function,
            keywords=tuple(item.keywords),
            enabled=item.enabled,
        )
        for item in payload
    ]
    try:
        save_rules(settings.paths_file, rules)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "count": len(rules)}


@app.get("/api/health")
async def health(_: None = Depends(require_api_auth)):
    return {"status": "ok", "tools": settings.tool_status()}
