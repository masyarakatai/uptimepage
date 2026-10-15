// Post an update to a maintenance window from its page, then reload so the
// thread shows it. Same-origin session cookie plus X-Requested-With, the
// header that gates state-changing requests.
(() => {
    const banner = document.getElementById("maintenance-errors");

    document.addEventListener("submit", async (evt) => {
        const form = evt.target.closest("[data-maintenance-update-form]");
        if (!form) return;
        evt.preventDefault();
        // Updates cannot be taken back and each reaches subscribers, so a
        // second submit while one is in flight (a repeated Cmd/Ctrl+Enter
        // still submits past the disabled button) must not post it twice.
        if (form.dataset.posting) return;
        window.smClearFormErrors(banner);
        const message = (new FormData(form).get("message") || "").toString().trim();
        if (!message) {
            window.smRenderClientError(banner, "message: cannot be empty");
            return;
        }
        const button = form.querySelector("button[type=submit]");
        if (button) button.disabled = true;
        form.dataset.posting = "1";
        let posted = false;
        try {
            const body = JSON.stringify({ message });
            const res = await fetch(`/api/v1/maintenance/${form.dataset.id}/updates`, {
                method: "POST",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Requested-With": "uptimepage",
                    "Idempotency-Key": window.smIdempotencyKey(form, body),
                },
                body,
            });
            if (res.ok) {
                posted = true;
                if (window.smToast) window.smToast({ message: "Update posted", kind: "ok" });
                window.location.reload();
                return;
            }
            let json = null;
            try { json = await res.json(); } catch { /* not JSON */ }
            window.smRenderApiError(banner, json, res.status);
        } catch (err) {
            window.smRenderClientError(banner, `Network error: ${err.message || err}`);
        } finally {
            // Posted: the reload is on its way, so the form stays locked.
            if (!posted) {
                delete form.dataset.posting;
                if (button) button.disabled = false;
            }
        }
    });

    // Cmd/Ctrl+Enter posts, as on the incident page.
    document.addEventListener("keydown", (evt) => {
        if (evt.key !== "Enter" || !(evt.metaKey || evt.ctrlKey)) return;
        const form = evt.target.closest && evt.target.closest("[data-maintenance-update-form]");
        if (!form) return;
        evt.preventDefault();
        form.requestSubmit();
    });
})();
