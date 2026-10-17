// The page editor's access tab: who can open a private page, the ways in
// (the email code, the page password), and the viewers who came. The list,
// the settings and a new password ride the page's one Save; block, unblock
// and signing password visitors out act at once, like removing a subscriber.
// The general/access tabs switch on the page, so moving between them keeps
// unsaved edits.
import { SUGGEST_BELOW, generatePassword } from "./_page_password.js";

(function () {
    "use strict";

    const panel = document.querySelector("[data-panel=access][data-access]");
    const root = document.querySelector("[data-page-id]");
    if (!panel || !root) return;

    const MAX_RULES = 500;
    const pageId = root.dataset.pageId;
    const locked = panel.dataset.locked === "true";
    let stored = JSON.parse(panel.dataset.access);
    // The password's line; `set_at` is what says one is stored.
    let line = JSON.parse(panel.dataset.password);
    const subscriberCount = Number(panel.dataset.subscribers || 0);
    const subscribersWithPassword = Number(panel.dataset.subscribersWithPassword || 0);
    let rules = stored.rules.map((r) => ({ kind: r.kind, value: r.value }));
    let touched = false;
    let viewers = null;

    const $ = (sel, from) => (from || document).querySelector(sel);
    const $$ = (sel, from) => Array.from((from || document).querySelectorAll(sel));

    function toast(message, kind) {
        if (kind === "error") window.smToastClear?.();
        window.smToast?.({ message: String(message), kind: kind || "ok" });
    }

    const plural = (n, one, many) => n + " " + (n === 1 ? one : many);

    // A <time data-tz>, like every console time: localtime.js keeps the label
    // current and puts the full stamp on hover.
    function stamp(iso) {
        const t = document.createElement("time");
        t.dateTime = iso;
        t.dataset.tz = "";
        t.textContent = window.smLocalFmt?.relative(new Date(iso)) || iso.slice(0, 16).replace("T", " ");
        return t;
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

    // ── Ways in ──────────────────────────────────────────────────────────

    const wayEmail = $("#access-way-email");
    const wayPassword = $("#access-way-password");
    wayEmail.checked = stored.email.enabled;
    wayPassword.checked = stored.password.enabled;
    wayEmail.addEventListener("change", edited);
    // Off hides the section, and a password typed but not saved goes with it.
    wayPassword.addEventListener("change", () => {
        if (!wayPassword.checked) {
            pwInput.value = "";
            reveal(false);
        }
        edited();
    });

    // ── The password ─────────────────────────────────────────────────────

    const hasPassword = () => Boolean(line.set_at);
    const pwInput = $("#access-password");
    const pwShow = $("#access-password-show");
    const pwCopy = $("#access-password-copy");

    function reveal(on) {
        pwInput.type = on ? "text" : "password";
        pwShow.textContent = on ? "[ hide ]" : "[ show ]";
    }

    function generate() {
        pwInput.value = generatePassword();
        reveal(true);
        edited();
    }

    pwInput.addEventListener("input", edited);
    pwShow.addEventListener("click", () => reveal(pwInput.type === "password"));
    $("#access-password-generate").addEventListener("click", generate);
    $("[data-password-generate]").addEventListener("click", generate);
    pwCopy.addEventListener("click", async () => {
        let label = "[ nothing to copy ]";
        if (pwInput.value) {
            try {
                await navigator.clipboard.writeText(pwInput.value);
                label = "[ copied ]";
            } catch {
                // Refused (permissions, an insecure context): shown and
                // selected, so it can be copied by hand.
                reveal(true);
                pwInput.select();
                label = "[ copy failed · select and copy ]";
            }
        }
        pwCopy.textContent = label;
        setTimeout(() => { pwCopy.textContent = "[ copy ]"; }, 2000);
    });

    async function loadLine() {
        try {
            line = await api("GET", "/api/v1/status-pages/" + pageId + "/access/password");
        } catch (m) {
            toast(m, "error");
        }
        sync();
    }

    $("[data-password-sign-out]").addEventListener("click", async () => {
        const ok = await window.smConfirm({
            title: "Sign out every password visitor?",
            items: [
                plural(line.sessions || 0, "device goes", "devices go") + " back to the sign-in screen.",
                "The password does not change, so anyone who knows it can sign in again. To shut them out, change it.",
            ],
            confirmLabel: "sign them all out",
            danger: true,
        });
        if (!ok) return;
        try {
            await api("POST", "/api/v1/status-pages/" + pageId + "/access/password/sign-out");
            toast("signed out");
        } catch (m) {
            toast(m, "error");
        }
        loadLine();
    });

    // ── Settings ─────────────────────────────────────────────────────────

    const passkeys = $("#access-passkeys");
    passkeys.checked = stored.email.passkeys_enabled;
    function pickRadio(name, value) {
        const v = value == null ? "" : String(value);
        const r = $("input[name=" + name + "][value='" + v + "']");
        if (r) r.checked = true;
    }
    pickRadio("access_recheck", stored.email.recheck_days);
    pickRadio("access_session", stored.session_days);
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
        td.className = "px-4 py-2 align-middle " + (cls || "");
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
            wrap.className = "flex items-center justify-end gap-4";
            // A 40 px target each; the negative margin keeps the text where it was.
            const target = "row-link -mx-2 inline-flex min-h-10 items-center px-2";
            const hist = document.createElement("button");
            hist.type = "button";
            hist.className = target;
            hist.textContent = "history";
            hist.addEventListener("click", () => showHistory(v));
            const block = document.createElement("button");
            block.type = "button";
            block.className = target + (v.blocked_at ? "" : " row-link--danger");
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

    // Why the save would be refused, or "".
    function refusal() {
        if (visibility() !== "private") return "";
        if (!wayEmail.checked && !wayPassword.checked) {
            return "Pick at least one way in. A private page with none would open for nobody.";
        }
        if (wayPassword.checked && !hasPassword() && !pwInput.value) {
            return "Set a password, or turn the password card off.";
        }
        if (wayEmail.checked && !rules.length) {
            return "Add who can get a code. With the email code on, the list needs at least one address or domain.";
        }
        return "";
    }

    function syncPassword() {
        const has = hasPassword();
        const value = pwInput.value;
        const storedLine = $("[data-password-stored]");
        storedLine.hidden = !has;
        if (has) {
            storedLine.replaceChildren("set · changed ", stamp(line.set_at),
                line.set_by ? " by " + line.set_by : "");
        }
        $("[data-password-label]").textContent = has ? "New password" : "Password";
        pwInput.placeholder = has ? "empty keeps the current one" : "type one or generate it";
        $("[data-password-replace]").hidden = !(has && value);
        const length = [...value].length;
        $("[data-password-weak]").hidden = !(length > 0 && length < SUGGEST_BELOW);

        const on = stored.protected && stored.password.enabled;
        $("[data-password-line]").hidden = locked || !on;
        if (on) {
            $("[data-password-line-stats]").replaceChildren(
                plural(line.sessions || 0, "device", "devices") + " signed in",
                ...(line.last_sign_in_at ? [" · last ", stamp(line.last_sign_in_at)] : []),
                " · " + plural(line.failed_last_24h || 0, "wrong try", "wrong tries") + " in 24 h");
        }
    }

    function sync() {
        const v = visibility();
        const isPrivate = v === "private";
        $("[data-access-public]").hidden = locked || isPrivate;
        $("[data-access-body]").hidden = locked || !isPrivate;
        const hasViewers = Array.isArray(viewers) && viewers.length > 0;
        $("[data-access-viewers]").hidden = locked || !(isPrivate || hasViewers);
        const why = refusal();
        const warn = $("[data-access-warn]");
        warn.textContent = why;
        warn.hidden = !why;

        const ways = [wayEmail.checked && "email", wayPassword.checked && "password"].filter(Boolean);
        $("[data-access-email]").hidden = !wayEmail.checked;
        $("[data-access-password]").hidden = !wayPassword.checked;
        $("[data-access-ways-hint]").textContent = "# any one of them lets a visitor in" +
            (!wayPassword.checked && hasPassword()
                ? " · password off: the last one is kept, turn it on and it works again" : "");
        $("[data-access-sessions]").hidden = !ways.length;
        $("[data-access-sessions-hint]").textContent =
            (ways.length === 2 ? "Applies to email and password sign-ins."
                : ways[0] === "password" ? "Applies to password sign-ins." : "Applies to email sign-ins.") +
            " A session not used for a year ends on its own.";
        $("[data-access-recheck]").hidden = !passkeys.checked;
        syncPassword();

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
                (active !== null ? " · " + active + " viewer" + (active === 1 ? "" : "s") : "") +
                (stored.protected && stored.password.enabled ? " · password" : "");
        }
    }

    // What a save would end, as bullets for one confirm, or none.
    function consequences(next) {
        const groups = [];
        if (!next || !next.protected) return groups;
        const wasPrivate = stored.protected;
        const sessions = line.sessions || 0;
        const subscriptions = line.subscriptions || 0;
        const ending = (devices) => [
            sessions && "Signs out " + plural(sessions, "device", "devices") + " that opened the page with " + devices + ".",
            subscriptions && "Ends " + plural(subscriptions, "subscription", "subscriptions") + " made with it.",
        ].filter(Boolean);
        if (wasPrivate && stored.password.enabled) {
            if (!next.password.enabled) {
                const items = ending("it");
                if (items.length) {
                    groups.push({
                        title: "Turn the password off?",
                        label: "turn it off",
                        items: items.concat("The password is kept: turn it back on and the same one works."),
                    });
                }
            } else if (next.password.value && hasPassword()) {
                const items = ending("the old one");
                if (items.length) {
                    groups.push({
                        title: "Change the page password?",
                        label: "change password",
                        items: items.concat("Share the new one with the people who need it."),
                    });
                }
            }
        }
        if (wasPrivate && stored.email.enabled && !next.email.enabled) {
            const known = Array.isArray(viewers);
            const people = known ? viewers.filter((x) => !x.blocked_at).length : Number(panel.dataset.viewersActive || 0);
            const subscribed = known ? viewers.filter((x) => !x.blocked_at && x.subscribed).length : 0;
            if (people || subscribed) {
                groups.push({
                    title: "Turn the email code off?",
                    label: "turn it off",
                    items: [
                        "Signs out " + plural(people, "person", "people") + " who signed in by email" +
                            (subscribed ? " and ends " + subscribed + " of their subscriptions." : "."),
                        "The list, the viewers and their passkeys are kept for when you turn it back on.",
                    ],
                });
            }
        }
        if (!wasPrivate && !next.email.enabled) {
            const ends = subscriberCount - subscribersWithPassword;
            if (ends > 0) {
                groups.push({
                    title: "Make the page private?",
                    label: "make it private",
                    items: [
                        "Ends " + plural(ends, "subscription", "subscriptions") +
                            ": with the password as the only way in, only those made with the current password stay.",
                        "People who subscribed while the page was public can subscribe again with the password.",
                    ],
                });
            }
        }
        return groups;
    }

    // ── What the page form reads ─────────────────────────────────────────

    window.smPageAccess = {
        visibility,
        show: (name, focus = true) => showTab(name, focus),
        refusal,
        // Omitted when the save changes nothing about access: a page never
        // made private keeps no access row, and a held private page on a plan
        // without the feature can still be renamed or switched off.
        payload() {
            const v = visibility();
            // Off keeps whatever it returns to.
            const protect = v === "private" || (v === "off" && stored.protected);
            if (!touched && protect === stored.protected) return undefined;
            // On only with one to use: a tick left on a page made public
            // with nothing typed has nothing to turn on.
            const password = { enabled: wayPassword.checked && (hasPassword() || Boolean(pwInput.value)) };
            if (wayPassword.checked && pwInput.value) password.value = pwInput.value;
            return {
                protected: protect,
                session_days: radio("access_session"),
                email: {
                    enabled: wayEmail.checked,
                    passkeys_enabled: passkeys.checked,
                    recheck_days: radio("access_recheck"),
                },
                password,
                rules: rules.map((r) => ({ kind: r.kind, value: r.value })),
            };
        },
        // Asks first when the save signs anyone out or ends subscriptions;
        // false when the owner backs out.
        async confirm() {
            const groups = consequences(this.payload());
            if (!groups.length) return true;
            const one = groups.length === 1;
            return window.smConfirm({
                title: one ? groups[0].title : "Save these access changes?",
                items: groups.flatMap((g) => g.items),
                confirmLabel: one ? groups[0].label : "save",
                danger: true,
            });
        },
        // The server's copy: it normalises entries (case, international
        // domains) and drops duplicates.
        saved(access) {
            if (access) {
                stored = access;
                rules = access.rules.map((r) => ({ kind: r.kind, value: r.value }));
                renderRules();
            }
            pwInput.value = "";
            reveal(false);
            touched = false;
            sync();
            loadLine();
            if (viewers !== null) loadViewers();
        },
    };

    renderRules();
    sync();
    if (location.hash === "#access") showTab("access");
})();
