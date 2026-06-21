(() => {
  "use strict";

  const csrfToken = document.body?.dataset.csrfToken || "";

  function showToast(message, type = "info") {
    const region = document.querySelector("[data-toast-region]");
    if (!region) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    region.appendChild(toast);
    window.setTimeout(() => toast.remove(), 4500);
  }

  async function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.method && options.method !== "GET") headers.set("X-CSRF-Token", csrfToken);
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(url, { ...options, headers });
    if (!response.ok) {
      let message = `请求失败（${response.status}）`;
      try {
        const data = await response.json();
        message = data.detail || message;
      } catch (_) {}
      throw new Error(message);
    }
    const contentType = response.headers.get("Content-Type") || "";
    return contentType.includes("application/json") ? response.json() : response.text();
  }

  document.querySelector("[data-sidebar-toggle]")?.addEventListener("click", () => {
    document.querySelector("#sidebar")?.classList.toggle("open");
  });

  document.querySelector("[data-logout]")?.addEventListener("click", async () => {
    try {
      await apiFetch("/logout", { method: "POST" });
      window.location.href = "/login";
    } catch (error) {
      showToast(error.message, "error");
    }
  });

  const searchInput = document.querySelector("[data-global-search]");
  searchInput?.addEventListener("input", () => {
    const query = searchInput.value.trim().toLowerCase();
    document.querySelectorAll("table.searchable tbody tr").forEach((row) => {
      row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
    });
  });

  document.querySelectorAll("[data-table-filters]").forEach((bar) => {
    bar.addEventListener("click", (event) => {
      const button = event.target.closest("[data-filter]");
      if (!button) return;
      bar.querySelectorAll("[data-filter]").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      const query = button.dataset.filter.toLowerCase();
      const table = bar.parentElement.querySelector("table.searchable");
      table?.querySelectorAll("tbody tr").forEach((row) => {
        row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
      });
    });
  });

  document.querySelectorAll(".url-cell a").forEach((link) => {
    link.addEventListener("click", (event) => {
      if (!window.confirm("即将在新窗口打开目标 URL。请确认该目标仍在授权范围内。")) {
        event.preventDefault();
      }
    });
  });

  function lines(id) {
    return document
      .querySelector(id)
      .value.split(/\r?\n/)
      .map((item) => item.trim())
      .filter((item) => item && !item.startsWith("#"));
  }

  const scanForm = document.querySelector("#scan-form");
  scanForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = scanForm.querySelector("button[type='submit']");
    const payload = {
      name: document.querySelector("#task-name").value.trim(),
      domains: lines("#domains"),
      manual_urls: lines("#manual-urls"),
      authorization_confirmed: document.querySelector("#authorization-confirmed").checked,
      max_assets: Number(document.querySelector("#max-assets").value),
      oneforall: {
        enabled: document.querySelector("#ofa-enabled").checked,
        brute: document.querySelector("#ofa-brute").checked,
        dns: document.querySelector("#ofa-dns").checked,
        req: document.querySelector("#ofa-req").checked,
        port: document.querySelector("#ofa-port").value,
        alive: document.querySelector("#ofa-alive").checked,
        takeover: document.querySelector("#ofa-takeover").checked,
        timeout: Number(document.querySelector("#ofa-timeout").value),
      },
      checker: {
        enabled: document.querySelector("#checker-enabled").checked,
        concurrency: Number(document.querySelector("#checker-concurrency").value),
        per_host: Number(document.querySelector("#checker-per-host").value),
        timeout: Number(document.querySelector("#checker-timeout").value),
        retries: Number(document.querySelector("#checker-retries").value),
        insecure: document.querySelector("#checker-insecure").checked,
        soft404_threshold: Number(document.querySelector("#soft404-threshold").value),
      },
    };

    if (!payload.domains.length && !payload.manual_urls.length) {
      showToast("请至少输入一个主域名或手工 URL", "error");
      return;
    }
    if (!payload.authorization_confirmed) {
      showToast("必须确认已获得目标测试授权", "error");
      return;
    }

    submit.disabled = true;
    submit.classList.add("loading");
    try {
      const result = await apiFetch("/api/tasks", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      showToast("任务已创建", "success");
      window.location.href = result.url;
    } catch (error) {
      showToast(error.message, "error");
      submit.disabled = false;
      submit.classList.remove("loading");
    }
  });

  const rulesTable = document.querySelector("[data-rules-table]");
  document.querySelector("[data-add-rule]")?.addEventListener("click", () => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><input type="checkbox" data-rule-enabled checked aria-label="启用规则"></td>
      <td><input value="/custom" data-rule-path></td>
      <td><input value="UNKNOWN" data-rule-category></td>
      <td><input value="自定义敏感路径" data-rule-function></td>
      <td><input value="" data-rule-keywords></td>
      <td><button class="button ghost small danger-text" type="button" data-delete-rule>删除</button></td>`;
    rulesTable?.querySelector("tbody").appendChild(row);
    row.querySelector("[data-rule-path]").focus();
  });

  rulesTable?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-delete-rule]");
    if (button && window.confirm("确定删除这条路径规则吗？")) button.closest("tr").remove();
  });

  document.querySelector("[data-save-rules]")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const rules = [...rulesTable.querySelectorAll("tbody tr")].map((row) => ({
      enabled: row.querySelector("[data-rule-enabled]").checked,
      path: row.querySelector("[data-rule-path]").value.trim(),
      category: row.querySelector("[data-rule-category]").value.trim().toUpperCase(),
      function: row.querySelector("[data-rule-function]").value.trim(),
      keywords: row
        .querySelector("[data-rule-keywords]")
        .value.split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    }));
    button.disabled = true;
    try {
      await apiFetch("/api/rules", { method: "PUT", body: JSON.stringify(rules) });
      showToast(`已保存 ${rules.length} 条路径规则`, "success");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      button.disabled = false;
    }
  });

  window.WebAssetApp = { apiFetch, showToast };
})();
