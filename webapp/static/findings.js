(() => {
  "use strict";
  const dialog = document.querySelector("[data-review-dialog]");
  const form = document.querySelector("[data-review-form]");
  if (!dialog || !form) return;
  const field = (name) => form.querySelector(`[data-review-${name}]`);

  function renderEvents(events) {
    const container = field("events");
    container.replaceChildren();
    if (!events.length) {
      container.textContent = "暂无人工变更记录";
      return;
    }
    events.forEach((event) => {
      const item = document.createElement("div");
      item.className = "review-event";
      const title = document.createElement("b");
      title.textContent = `${event.old_status} → ${event.new_status}`;
      const meta = document.createElement("small");
      meta.textContent = `${event.created_at} · ${event.actor}${event.assignee ? ` · ${event.assignee}` : ""}`;
      const notes = document.createElement("p");
      notes.textContent = event.notes || "无备注";
      item.append(title, meta, notes);
      container.appendChild(item);
    });
  }

  async function openCase(caseId) {
    try {
      const [item, events] = await Promise.all([
        window.WebAssetApp.apiFetch(`/api/finding-cases/${caseId}`),
        window.WebAssetApp.apiFetch(`/api/finding-cases/${caseId}/events`),
      ]);
      field("case-id").value = item.id;
      field("url").textContent = item.endpoint_url;
      field("status").value = item.review_status;
      field("assignee").value = item.assignee || "";
      field("tags").value = (item.tags || []).join(", ");
      field("notes").value = item.notes || "";
      field("evidence").value = item.evidence_summary || "";
      field("retested").checked = false;
      renderEvents(events);
      dialog.showModal();
    } catch (error) {
      window.WebAssetApp.showToast(error.message, "error");
    }
  }

  document.querySelectorAll("[data-edit-finding]").forEach((button) => {
    button.addEventListener("click", () => openCase(button.dataset.caseId));
  });
  document.querySelectorAll("[data-close-review]").forEach((button) => {
    button.addEventListener("click", () => dialog.close());
  });
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const caseId = field("case-id").value;
    const payload = {
      status: field("status").value,
      assignee: field("assignee").value.trim(),
      notes: field("notes").value.trim(),
      tags: field("tags").value.split(",").map((item) => item.trim()).filter(Boolean),
      evidence_summary: field("evidence").value.trim(),
      mark_retested: field("retested").checked,
    };
    const submit = form.querySelector("button[type='submit']");
    submit.disabled = true;
    try {
      await window.WebAssetApp.apiFetch(`/api/finding-cases/${caseId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      window.WebAssetApp.showToast("复测结果已保存", "success");
      window.location.reload();
    } catch (error) {
      window.WebAssetApp.showToast(error.message, "error");
      submit.disabled = false;
    }
  });
})();
