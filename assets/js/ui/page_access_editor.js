// The page editor's access tab: who can open a private page, and the viewers
// who did. The list and settings ride the page's one Save; block and unblock
// act at once, like removing a subscriber. The general/access tabs switch on
// the page, so moving between them keeps unsaved edits.
(function () {
    "use strict";

    const panel = document.querySelector("[data-panel=access][data-access]");
    const root = document.querySelector("[data-page-id]");
    if (!panel || !root) return;

    const MAX_RULES = 500;
    const pageId = root.dataset.pageId;
    const locked = panel.dataset.locked === "true";
    let stored = JSON.parse(panel.dataset.access);
    let rules = stored.rules.map((r) => ({ kind: r.kind, value: r.value }));
    let touched = false;
    let viewers = null;

    const $ = (sel, from) => (from || document).querySelector(sel);
    const $$ = (sel, from) => Array.from((from || document).querySelectorAll(sel));

    function toast(message, kind) {
        if (kind === "error") window.smToastClear?.();
        window.smToast?.({ message: String(message), kind: kind || "ok" });
    }

    async function api(method, path) {
        const res = await fetch(path, { method, headers: { "X-Requested-With": "uptimepage" } });
        if (!res.ok) {
            const d = await res.json().catch(() => null);
            throw (d && d.error && d.error.message) || ("HTTP " + res.status);
        }
        return res.status === 204 ? null : res.json();
    }

    // Marks the page form dirty, so leaving with an unsaved list asks first.
    function edited() {
        touched = true;
        panel.dispatchEvent(new Event("change", { bubbles: true }));
        sync();
    }

    // ── Tabs ─────────────────────────────────────────────────────────────

    const tabs = $$("[role=tab][data-tab]");
    function showTab(name, focus) {
        tabs.forEach((t) => {
            const on = t.dataset.tab === name;
            t.setAttribute("aria-selected", String(on));
            t.tabIndex = on ? 0 : -1;
            t.classList.toggle("check-type-card--on", on);
            if (on && focus) t.focus();
        });
        $$("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== name; });
        // In the URL, so a reload stays on the tab.
        history.replaceState(history.state, "", name === "access" ? "#access" : location.pathname + location.search);
        if (name === "access" && !locked && viewers === null) loadViewers();
    }
    tabs.forEach((t, i) => {
        t.addEventListener("click", () => showTab(t.dataset.tab));
        t.addEventListener("keydown", (e) => {
            const step = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[e.key];
            if (!step) return;
            e.preventDefault();
            showTab(tabs[(i + step + tabs.length) % tabs.length].dataset.tab, true);
        });
    });

    // ── Visibility ───────────────────────────────────────────────────────

    const visibility = () => ($("input[name=visibility]:checked") || {}).value || "public";
    $$("input[name=visibility]").forEach((r) => r.addEventListener("change", () => {
        sync();
        if (visibility() === "private" && !rules.length) showTab("access");
    }));

    // ── Settings ─────────────────────────────────────────────────────────

    const passkeys = $("#access-passkeys");
    passkeys.checked = stored.email.passkeys_enabled;
    function pickRadio(name, value) {
        const v = value == null ? "" : String(value);
        const r = $("input[name=" + name + "][value='" + v + "']");
        if (r) r.checked = true;
    }
    pickRadio("access_recheck", stored.email.recheck_days);
    pickRadio("access_session", stored.email.session_days);
    const radio = (name) => {
        const v = ($("input[name=" + name + "]:checked") || {}).value;
        return v ? Number(v) : null;
    };
    passkeys.addEventListener("change", edited);
    $$("input[name=access_recheck], input[name=access_session]").forEach((r) =>
        r.addEventListener("change", edited));

    // ── The list ─────────────────────────────────────────────────────────

    const ruleBox = $("[data-access-rules]");
    const ruleInput = $("#access-rule-input");

    function renderRules() {
        ruleBox.textContent = "";
        if (!rules.length) {
            const p = document.createElement("p");
            p.className = "px-4 py-3 font-mono text-xs text-quiet";
            p.textContent = "# nobody yet · add a domain or an address";
            ruleBox.appendChild(p);
        }
        rules.forEach((r, i) => {
            const row = document.createElement("div");
            row.className = "access-rule-row";
            const value = document.createElement("span");
            value.className = "min-w-0 flex-1 break-all";
            value.textContent = (r.kind === "domain" ? "@" : "") + r.value;
            const kind = document.createElement("span");
            kind.className = "access-kind";
            kind.textContent = r.kind;
            const rm = document.createElement("button");
            rm.type = "button";
            rm.className = "row-remove";
            rm.setAttribute("aria-label", "remove " + r.value);
            rm.innerHTML = '<svg viewBox="0 0 12 12" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><path d="M2.75 2.75 9.25 9.25M9.25 2.75 2.75 9.25"/></svg>';
            rm.addEventListener("click", () => { rules.splice(i, 1); renderRules(); edited(); });
            row.append(value, kind, rm);
            ruleBox.appendChild(row);
        });
        $("[data-access-rule-count]").textContent = "# " + rules.length + " of " + MAX_RULES + " · saved with save page";
    }

    // Shape only; the server normalises (an international domain, say) and
    // has the last word.
    function parseRule(raw) {
        const v = raw.trim().replace(/^@/, "").toLowerCase();
        if (!v || /\s/.test(v)) return null;
        if (v.includes("@")) {
            return /^[^@]+@[^@]+\.[^@]+$/.test(v) ? { kind: "address", value: v } : null;
        }
        return /^[^.:/]+(\.[^.:/]+)+$/.test(v) ? { kind: "domain", value: v } : null;
    }

    function addRule() {
        const entries = ruleInput.value.split(/[,;\s]+/).filter(Boolean);
        if (!entries.length) return;
        const bad = [];
        for (const raw of entries) {
            const r = parseRule(raw);
            if (!r) { bad.push(raw); continue; }
            if (rules.some((x) => x.kind === r.kind && x.value === r.value)) continue;
            if (rules.length >= MAX_RULES) { toast("a page lists at most " + MAX_RULES + " entries", "error"); break; }
            rules.push(r);
        }
        ruleInput.value = bad.join(" ");
        if (bad.length) toast("enter a domain such as example.com or an address such as name@example.com", "error");
        renderRules();
        edited();
    }
    $("#access-rule-add").addEventListener("click", addRule);
    // Enter adds the entry instead of saving the whole page half-written.
    ruleInput.addEventListener("keydown", (e) => {
        if (e.key !== "Enter" || e.metaKey || e.ctrlKey) return;
        e.preventDefault();
        addRule();
    });

    // ── Viewers ──────────────────────────────────────────────────────────

    const base = "/api/v1/status-pages/" + pageId + "/access/viewers";
    const tbody = $("[data-viewer-rows]");
    const drawer = $("[data-viewer-drawer]");

    function when(iso) {
        if (!iso) return "never";
        const d = new Date(iso);
        const pad = (n) => String(n).padStart(2, "0");
        return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
            pad(d.getHours()) + ":" + pad(d.getMinutes());
    }

    async function loadViewers() {
        try {
            viewers = await api("GET", base);
        } catch (m) {
            viewers = [];
            toast(m, "error");
        }
        renderViewers();
        sync();
    }

    function cell(text, cls) {
        const td = document.createElement("td");
        td.className = "px-4 py-2 align-top " + (cls || "");
        if (text !== undefined) td.textContent = text;
        return td;
    }

    function renderViewers() {
        tbody.textContent = "";
        if (!viewers.length) {
            const tr = document.createElement("tr");
            const td = cell("# nobody has signed in yet", "font-mono text-xs text-quiet");
            td.colSpan = 5;
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
        viewers.forEach((v) => {
            const tr = document.createElement("tr");
            if (v.blocked_at) tr.className = "opacity-50";
            const emailTd = cell(undefined, "font-mono text-xs break-words");
            const emailBtn = document.createElement("button");
            emailBtn.type = "button";
            emailBtn.className = "text-left hover:underline";
            emailBtn.textContent = v.email;
            emailBtn.addEventListener("click", () => showHistory(v));
            emailTd.appendChild(emailBtn);
            const status = cell();
            const badge = document.createElement("span");
            badge.className = "status-badge " + (v.blocked_at ? "status-badge--down" : "status-badge--up");
            badge.textContent = v.blocked_at ? "blocked" : "active";
            status.appendChild(badge);
            const actions = cell();
            const wrap = document.createElement("div");
            wrap.className = "flex items-center justify-end gap-3";
            const hist = document.createElement("button");
            hist.type = "button";
            hist.className = "row-link";
            hist.textContent = "history";
            hist.addEventListener("click", () => showHistory(v));
            const block = document.createElement("button");
            block.type = "button";
            block.className = "row-link" + (v.blocked_at ? "" : " row-link--danger");
            block.textContent = v.blocked_at ? "unblock" : "block";
            block.addEventListener("click", () => setBlocked(v, !v.blocked_at));
            wrap.append(hist, block);
            actions.appendChild(wrap);
            tr.append(
                emailTd,
                cell(when(v.last_visit), "font-mono text-xs text-muted"),
                cell(v.passkeys > 0 ? "yes" : "no", "font-mono text-xs text-muted"),
                status,
                actions,
            );
            tbody.appendChild(tr);
        });
        const active = viewers.filter((v) => !v.blocked_at).length;
        $("[data-viewer-count]").textContent = active + " active · " + (viewers.length - active) + " blocked";
    }

    async function setBlocked(v, block) {
        if (block) {
            const ok = await window.smConfirm({
                title: "Block " + v.email + "?",
                body: "Signs them out now, removes their passkeys and their subscription. They cannot sign in again until you unblock them.",
                confirmLabel: "block",
                danger: true,
            });
            if (!ok) return;
        }
        try {
            await api("POST", base + "/" + v.id + (block ? "/block" : "/unblock"));
            toast(block ? "blocked" : "unblocked");
            await loadViewers();
        } catch (m) {
            toast(m, "error");
        }
    }

    async function showHistory(v) {
        let h;
        try {
            h = await api("GET", base + "/" + v.id + "/history");
        } catch (m) {
            toast(m, "error");
            return;
        }
        drawer.textContent = "";
        const title = document.createElement("p");
        title.className = "panel-label";
        title.textContent = "history";
        const who = document.createElement("p");
        who.className = "mt-1 font-mono text-xs break-all text-body";
        who.textContent = v.email;
        const daysLabel = document.createElement("p");
        daysLabel.className = "mt-4 mb-1.5 text-xs text-muted";
        daysLabel.textContent = "Visits, last 14 days";
        const days = document.createElement("div");
        days.className = "visit-days";
        const seen = new Set(h.visit_days);
        for (let i = 13; i >= 0; i--) {
            const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
            const day = document.createElement("span");
            day.className = "visit-day" + (seen.has(d) ? " visit-day--on" : "");
            day.title = d;
            days.appendChild(day);
        }
        const evLabel = document.createElement("p");
        evLabel.className = "mt-4 mb-1 text-xs text-muted";
        evLabel.textContent = "Sign-in events";
        drawer.append(title, who, daysLabel, days, evLabel);
        h.events.forEach((e) => {
            const row = document.createElement("div");
            row.className = "access-event";
            const at = document.createElement("span");
            at.className = "text-muted";
            at.textContent = when(e.occurred_at);
            const what = document.createElement("span");
            what.textContent = describe(e);
            row.append(at, what);
            drawer.appendChild(row);
        });
        const kept = document.createElement("p");
        kept.className = "mt-3 font-mono text-xs text-quiet";
        kept.textContent = "# kept for 1 year";
        drawer.appendChild(kept);
    }

    function describe(e) {
        const kind = e.kind.replace(/_/g, " ");
        const how = e.method === "passkey" ? " · passkey" : e.method === "email" ? " · email code" : "";
        if (e.kind === "blocked" || e.kind === "unblocked") {
            return kind + (e.actor_email ? " by " + e.actor_email : "");
        }
        if (e.kind === "code_failed") return "code failed" + (e.failure_reason ? " · " + e.failure_reason.replace(/_/g, " ") : "");
        return kind + how;
    }

    // ── Sync ─────────────────────────────────────────────────────────────

    function emptyReason() {
        return visibility() === "private" && !rules.length
            ? "Add who can open it. With email code as the only way in, the list needs at least one address or domain."
            : "";
    }

    function sync() {
        const v = visibility();
        const isPrivate = v === "private";
        $("[data-access-public]").hidden = locked || isPrivate;
        $("[data-access-body]").hidden = locked || !isPrivate;
        const hasViewers = Array.isArray(viewers) && viewers.length > 0;
        $("[data-access-viewers]").hidden = locked || !(isPrivate || hasViewers);
        const why = emptyReason();
        const warn = $("[data-access-warn]");
        warn.textContent = why;
        warn.hidden = !why;
        $("[data-access-recheck]").hidden = !passkeys.checked;
        $$("[data-public-only]").forEach((el) => { el.hidden = isPrivate; });
        $$("[data-private-only]").forEach((el) => { el.hidden = !isPrivate; });
        const active = Array.isArray(viewers) ? viewers.filter((x) => !x.blocked_at).length : null;
        const kept = $("[data-access-kept]");
        kept.textContent = rules.length
            ? "# kept from before: " + rules.length + " entr" + (rules.length === 1 ? "y" : "ies") +
              (active !== null ? ", " + active + " viewer" + (active === 1 ? "" : "s") : "") +
              ". They apply again when the page is private."
            : "";
        const meta = $("[data-access-meta]");
        if (meta && !locked) {
            meta.textContent = rules.length + " on the list" +
                (active !== null ? " · " + active + " viewer" + (active === 1 ? "" : "s") : "");
        }
    }

    // ── What the page form reads ─────────────────────────────────────────

    window.smPageAccess = {
        visibility,
        show: (name, focus = true) => showTab(name, focus),
        refusal: emptyReason,
        // Omitted when the save changes nothing about access: a page never
        // made private keeps no access row, and a held private page on a plan
        // without the feature can still be renamed or switched off.
        payload() {
            const v = visibility();
            // Off keeps whatever it returns to.
            const protect = v === "private" || (v === "off" && stored.protected);
            if (!touched && protect === stored.protected) return undefined;
            return {
                protected: protect,
                email: {
                    enabled: true,
                    passkeys_enabled: passkeys.checked,
                    recheck_days: radio("access_recheck"),
                    session_days: radio("access_session"),
                },
                rules: rules.map((r) => ({ kind: r.kind, value: r.value })),
            };
        },
        // The server's copy: it normalises entries (case, international
        // domains) and drops duplicates.
        saved(access) {
            if (access) {
                stored = access;
                rules = access.rules.map((r) => ({ kind: r.kind, value: r.value }));
                renderRules();
            }
            touched = false;
            sync();
            if (viewers !== null) loadViewers();
        },
    };

    renderRules();
    sync();
    if (location.hash === "#access") showTab("access");
})();
