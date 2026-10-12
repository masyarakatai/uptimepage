// Duplicate page: one row per copy (address + name). The server copies every
// other setting from the stored monitor, so this only collects what differs.

(function () {
    const form = document.getElementById("duplicate-form");
    if (!form) return;
    const rows = form.querySelector("[data-copy-rows]");
    const tmpl = document.getElementById("copy-row-template");
    const addBtn = form.querySelector("[data-copy-add]");
    const submitBtn = form.querySelector("[data-copy-submit]");
    const limitHint = form.querySelector("[data-copy-limit]");
    const banner = document.getElementById("form-errors");

    const sourceAddress = form.dataset.sourceAddress || "";
    const urlKind = form.dataset.urlKind === "true";
    const copyName = form.dataset.copyName;
    const max = parseInt(form.dataset.max, 10);
    const headroom = form.dataset.headroom === undefined ? null : parseInt(form.dataset.headroom, 10);
    const hasAddress = Boolean(form.dataset.sourceAddress);

    let submitting = false;

    const addressOf = (row) => row.querySelector("[name='copy_address']");
    const nameOf = (row) => row.querySelector("[name='copy_name']");
    const allRows = () => [...rows.querySelectorAll("[data-copy-row]")];

    // A URL's host and path tell copies apart; a host or domain already does.
    function derivedName(address) {
        if (!address || address === sourceAddress) return copyName;
        if (!urlKind) return address;
        try {
            const url = new URL(address);
            const path = url.pathname.replace(/\/+$/, "");
            return url.host + path;
        } catch {
            return address;
        }
    }

    const isBlank = (row) => addressOf(row).value.trim() === "" && nameOf(row).value.trim() === "";

    // A blank row is a slip, not a request for another exact copy; a row with
    // only a name keeps the source's address. Without addresses, every row counts.
    function wanted() {
        if (!hasAddress) return allRows();
        return allRows().filter((row) => !isBlank(row));
    }

    function refresh() {
        for (const row of allRows()) {
            if (hasAddress) nameOf(row).placeholder = derivedName(addressOf(row).value.trim());
        }
        const n = wanted().length;
        if (!submitting) submitBtn.textContent = `create ${n} monitor${n === 1 ? "" : "s"}`;
        const full = allRows().length >= max;
        addBtn.hidden = full;
        let limit = "";
        if (headroom !== null && n > headroom) {
            limit = `Your plan has room for ${headroom} more monitor${headroom === 1 ? "" : "s"}.`;
        } else if (full) {
            limit = `Up to ${max} copies at a time.`;
        }
        // A live region reads out every write, so only a change is written.
        if (limitHint.textContent !== limit) limitHint.textContent = limit;
        submitBtn.disabled = submitting || n === 0 || (headroom !== null && n > headroom);
    }

    function addRow(after, address) {
        if (allRows().length >= max) return null;
        const frag = tmpl.content.cloneNode(true);
        const row = frag.querySelector("[data-copy-row]");
        if (address && hasAddress) addressOf(row).value = address;
        if (after) after.after(frag);
        else rows.appendChild(frag);
        return row;
    }

    addBtn.addEventListener("click", () => {
        const row = addRow(null, "");
        refresh();
        row?.querySelector("input")?.focus();
    });

    rows.addEventListener("click", (evt) => {
        const btn = evt.target.closest("[data-copy-remove]");
        if (!btn) return;
        btn.closest("[data-copy-row]").remove();
        if (allRows().length === 0) addRow(null, "");
        refresh();
    });

    rows.addEventListener("input", (evt) => {
        evt.target.removeAttribute("aria-invalid");
        refresh();
    });

    // A list fills this row, unless it holds an address of its own, and new
    // rows below it, after blank rows elsewhere are dropped. One that still
    // exceeds a limit is refused whole, so no address is left out without notice.
    rows.addEventListener("paste", (evt) => {
        const input = evt.target.closest("[name='copy_address']");
        if (!input) return;
        const parts = (evt.clipboardData?.getData("text") || "")
            .split(/\s+/)
            .map((p) => p.replace(/[,;]+$/, ""))
            .filter(Boolean);
        if (parts.length < 2) return;
        evt.preventDefault();
        let row = input.closest("[data-copy-row]");
        const current = input.value.trim();
        const replace = current === "" || current === sourceAddress;
        const kept = allRows().filter((r) => !isBlank(r) && !(r === row && replace)).length;
        const rowRoom = max - kept;
        const planRoom = headroom === null ? rowRoom : Math.max(headroom - kept, 0);
        if (parts.length > Math.min(rowRoom, planRoom)) {
            limitHint.textContent = planRoom < rowRoom
                ? `That paste has ${parts.length} addresses and your plan has room for ${planRoom} more. Nothing was added: paste a shorter list.`
                : `That paste has ${parts.length} addresses and only ${rowRoom} fit (up to ${max} copies at a time). Nothing was added: paste a shorter list.`;
            return;
        }
        for (const r of allRows()) if (r !== row && isBlank(r)) r.remove();
        if (replace) input.value = parts[0];
        for (const part of replace ? parts.slice(1) : parts) {
            const next = addRow(row, part);
            if (!next) break;
            row = next;
        }
        refresh();
    });

    // Enter walks down the list, adding a row at the end; ⌘/Ctrl+Enter creates.
    form.addEventListener("keydown", (evt) => {
        if (evt.key !== "Enter" || !evt.target.matches("[data-copy-row] input")) return;
        evt.preventDefault();
        if (evt.metaKey || evt.ctrlKey) {
            form.requestSubmit();
            return;
        }
        const row = evt.target.closest("[data-copy-row]");
        const next = row.nextElementSibling || addRow(row, "");
        refresh();
        next?.querySelector("input")?.focus();
    });

    form.addEventListener("submit", async (evt) => {
        evt.preventDefault();
        if (submitting) return;
        window.smClearFormErrors(banner);
        const sent = wanted();
        const copies = sent.map((row) => {
            const address = hasAddress ? addressOf(row).value.trim() : "";
            const copy = { name: nameOf(row).value.trim() || derivedName(address) };
            if (address && address !== sourceAddress) copy.address = address;
            return copy;
        });
        submitting = true;
        submitBtn.disabled = true;
        submitBtn.setAttribute("aria-busy", "true");
        submitBtn.textContent = "creating…";
        const restore = () => {
            submitting = false;
            submitBtn.removeAttribute("aria-busy");
            refresh();
        };

        let res;
        try {
            res = await fetch(form.dataset.action, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Requested-With": "uptimepage",
                },
                body: JSON.stringify({ copies }),
            });
        } catch (err) {
            restore();
            window.smRenderClientError(banner, `Network error: ${err.message || err}`);
            return;
        }
        if (res.ok) {
            let created = [];
            try { created = await res.json(); } catch { /* fall back to the list */ }
            window.location = created.length === 1 ? `/targets/${created[0].id}` : "/targets";
            return;
        }
        restore();
        let body;
        try { body = await res.json(); }
        catch { window.smRenderClientError(banner, `Request failed (${res.status})`); return; }
        window.smRenderApiError(banner, body, res.status, {
            onField: (field) => markInvalid(sent, field),
        });
    });

    // `copies[i].name` is the name box; anything else about a copy is its address.
    function markInvalid(sent, field) {
        const m = /^copies\[(\d+)\](?:\.(.*))?$/.exec(field);
        const row = m && sent[parseInt(m[1], 10)];
        if (!row) return;
        const el = m[2] === "name" || !hasAddress ? nameOf(row) : addressOf(row);
        el.setAttribute("aria-invalid", "true");
        el.focus({ preventScroll: true });
        el.scrollIntoView({ block: "center", behavior: "smooth" });
    }

    refresh();
})();
