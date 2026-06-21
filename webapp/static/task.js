(() => {
  "use strict";
  const root = document.querySelector("[data-task-id]");
  if (!root) return;
  const taskId = root.dataset.taskId;
  const logConsole = document.querySelector("[data-log-console]");
  const initialProgress = document.querySelector("[data-progress-bar]");
  if (initialProgress) initialProgress.style.width = `${initialProgress.dataset.progressValue || 0}%`;
  let lastId = Number(logConsole?.lastElementChild?.dataset.eventId || 0);
  let terminalReloadScheduled = false;

  function appendLog(event) {
    const line = document.createElement("div");
    line.className = `log-line ${event.level.toLowerCase()}`;
    line.dataset.eventId = event.id;
    const time = document.createElement("time");
    time.textContent = String(event.timestamp).slice(11, 19);
    const level = document.createElement("b");
    level.textContent = `[${event.level}]`;
    const message = document.createElement("span");
    message.textContent = event.message;
    line.append(time, level, message);
    logConsole.appendChild(line);
    logConsole.scrollTop = logConsole.scrollHeight;
    lastId = Math.max(lastId, Number(event.id));
  }

  function updateStatus(data) {
    const badge = document.querySelector("[data-task-status-badge]");
    badge.textContent = data.status;
    badge.className = `status-badge ${data.status.toLowerCase()}`;
    document.querySelector("[data-task-stage]").textContent = data.stage;
    document.querySelector("[data-progress-bar]").style.width = `${data.progress}%`;
    document.querySelector("[data-progress-text]").textContent = `${data.progress}%`;
    Object.entries(data.counts || {}).forEach(([key, value]) => {
      const target = document.querySelector(`[data-count='${key}']`);
      if (target) target.textContent = value;
    });
    if (data.error) {
      const errorBox = document.querySelector("[data-task-error]");
      errorBox.textContent = data.error;
      errorBox.classList.remove("hidden");
    }
    if (["SUCCESS", "FAILED", "CANCELLED"].includes(data.status) && !terminalReloadScheduled) {
      terminalReloadScheduled = true;
      window.setTimeout(() => window.location.reload(), 1400);
    }
  }

  if (["QUEUED", "RUNNING"].includes(root.dataset.taskStatus)) {
    const source = new EventSource(`/api/tasks/${taskId}/events?after=${lastId}`);
    source.addEventListener("log", (event) => appendLog(JSON.parse(event.data)));
    source.addEventListener("status", (event) => updateStatus(JSON.parse(event.data)));
    source.onerror = () => {
      if (!terminalReloadScheduled) window.WebAssetApp.showToast("实时日志连接暂时中断，正在重试", "error");
    };
  }

  document.querySelector("[data-clear-log]")?.addEventListener("click", () => {
    logConsole.replaceChildren();
  });

  document.querySelector("[data-cancel-task]")?.addEventListener("click", async (event) => {
    if (!window.confirm("确定停止当前任务吗？OneForAll 子进程也会被终止。")) return;
    event.currentTarget.disabled = true;
    try {
      await window.WebAssetApp.apiFetch(`/api/tasks/${taskId}/cancel`, { method: "POST" });
      window.WebAssetApp.showToast("已发送停止请求", "success");
    } catch (error) {
      window.WebAssetApp.showToast(error.message, "error");
      event.currentTarget.disabled = false;
    }
  });

  document.querySelectorAll("[data-task-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const action = button.dataset.taskAction;
      const labels = { clone: "复制任务", retry: "重试任务", "rerun-checker": "仅重新执行路径检测" };
      if (!window.confirm(`确定${labels[action]}吗？将创建一个新任务并保留当前记录。`)) return;
      button.disabled = true;
      try {
        const result = await window.WebAssetApp.apiFetch(`/api/tasks/${taskId}/${action}`, {
          method: "POST",
        });
        window.location.href = result.url;
      } catch (error) {
        window.WebAssetApp.showToast(error.message, "error");
        button.disabled = false;
      }
    });
  });
})();
