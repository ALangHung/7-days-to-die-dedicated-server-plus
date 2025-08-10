(function () {
  const CONFIRM_ID = "confirmMask";
  let maskEl = null;

  function ensureMask() {
    if (maskEl) return maskEl;
    maskEl = document.getElementById(CONFIRM_ID);
    if (!maskEl) {
      maskEl = document.createElement("div");
      maskEl.id = CONFIRM_ID;
      maskEl.className = "app-mask hidden";
      maskEl.setAttribute("aria-hidden", "true");
      document.body.appendChild(maskEl);
    }
    return maskEl;
  }

  function escapeHTML(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function normalizeNewlines(s) {
    return String(s || "")
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n")
      .replace(/\\n/g, "\n");
  }

  function showConfirm(
    message,
    { continueText = "繼續", cancelText = "取消", title = "請確認操作" } = {}
  ) {
    return new Promise((resolve) => {
      const m = ensureMask();
      if (!m) return resolve(false);

      const safeMsg = escapeHTML(
        normalizeNewlines(message || "確定要執行這個操作嗎？")
      );

      m.innerHTML = `
        <div class="app-mask__panel" role="dialog" aria-modal="true" aria-live="assertive">
          <div style="display:flex;flex-direction:column;align-items:center;gap:8px;max-width:360px">
            <div class="app-mask__icon" aria-hidden="true">⚠️</div>
            <h3 style="margin:0;font-size:1rem;">${escapeHTML(title)}</h3>
            <div class="app-mask__message">${safeMsg}</div>
            <div class="app-mask__actions">
              <button type="button" class="btn btn--ghost" data-act="cancel">${escapeHTML(
                cancelText
              )}</button>
              <button type="button" class="btn btn--danger" data-act="continue">${escapeHTML(
                continueText
              )}</button>
            </div>
          </div>
        </div>
      `;
      m.classList.remove("hidden");
      m.setAttribute("aria-hidden", "false");

      const panel = m.querySelector(".app-mask__panel");
      panel?.addEventListener("wheel", (e) => e.stopPropagation(), {
        passive: true,
      });

      const onClick = (ev) => {
        const btn = ev.target.closest("button[data-act]");
        if (!btn) return;
        ev.preventDefault();
        ev.stopPropagation();
        const act = btn.dataset.act;
        close(act === "continue");
      };

      const onKey = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          close(false);
        }
        if (e.key === "Enter") {
          if (!m.classList.contains("hidden")) {
            e.preventDefault();
            close(true);
          }
        }
      };

      function close(ok) {
        m.classList.add("hidden");
        m.setAttribute("aria-hidden", "true");
        m.removeEventListener("click", onClick, true);
        document.removeEventListener("keydown", onKey, true);
        resolve(ok);
      }

      m.addEventListener("click", onClick, true);
      document.addEventListener("keydown", onKey, true);

      m.querySelector('button[data-act="continue"]')?.focus();
    });
  }

  document.addEventListener(
    "click",
    async (e) => {
      const btn = e.target.closest("[data-danger]");
      if (!btn) return;
      if (btn.dataset.skipConfirm === "1") return;

      e.preventDefault();
      e.stopImmediatePropagation();

      const msg = btn.getAttribute("data-danger") || "確定要執行這個操作嗎？";
      const ok = await showConfirm(msg, {
        continueText: btn.getAttribute("data-continue-text") || "繼續",
        cancelText: btn.getAttribute("data-cancel-text") || "取消",
        title: btn.getAttribute("data-danger-title") || "請確認操作",
      });

      if (ok) {
        btn.dataset.skipConfirm = "1";
        setTimeout(() => {
          try {
            btn.click();
          } finally {
            delete btn.dataset.skipConfirm;
          }
        }, 0);
      }
    },
    true
  );

  window.DangerConfirm = { showConfirm };
})();
