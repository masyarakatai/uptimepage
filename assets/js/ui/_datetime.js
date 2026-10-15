// Date + time picker in the console register. The native datetime-local popup
// is browser chrome no stylesheet reaches, so the input stays only as the
// hidden value carrier ("YYYY-MM-DDTHH:MM", wall clock, no zone). Code that
// writes input.value afterwards dispatches "input" so the trigger follows.

const MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const LONG = new Intl.DateTimeFormat("en", {
    weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC",
});
const pad = (n) => String(n).padStart(2, "0");

function parse(value) {
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(value);
    return m ? { y: +m[1], mo: +m[2] - 1, d: +m[3], h: +m[4], mi: +m[5] } : null;
}
const format = (t) => `${t.y}-${pad(t.mo + 1)}-${pad(t.d)}T${pad(t.h)}:${pad(t.mi)}`;
const utc = (t) => new Date(Date.UTC(t.y, t.mo, t.d));
const fromUtc = (dt) => ({ y: dt.getUTCFullYear(), mo: dt.getUTCMonth(), d: dt.getUTCDate() });
const addDays = (t, n) => fromUtc(new Date(Date.UTC(t.y, t.mo, t.d + n)));
const daysIn = (y, mo) => new Date(Date.UTC(y, mo + 1, 0)).getUTCDate();
const sameDay = (a, b) => a && b && a.y === b.y && a.mo === b.mo && a.d === b.d;

function addMonths(t, n) {
    const first = new Date(Date.UTC(t.y, t.mo + n, 1));
    const y = first.getUTCFullYear();
    const mo = first.getUTCMonth();
    return { y, mo, d: Math.min(t.d, daysIn(y, mo)) };
}

function localToday() {
    const now = new Date();
    return { y: now.getFullYear(), mo: now.getMonth(), d: now.getDate() };
}

// 0 = Sunday. The locale's own week where the browser exposes it.
function weekStart() {
    try {
        const loc = new Intl.Locale(navigator.language);
        const info = loc.getWeekInfo ? loc.getWeekInfo() : loc.weekInfo;
        if (info) return info.firstDay % 7;
    } catch {
        // An unknown locale tag keeps the default.
    }
    return 1;
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
}

let active = null;
let seq = 0;

// A click on the field's own <label> counts as inside: the label hands it on
// to the trigger, which toggles.
document.addEventListener("click", (e) => {
    if (active && !active.scope.contains(e.target)) active.close();
}, true);
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && active && (active.scope.contains(e.target) || e.target === document.body)) {
        e.preventDefault();
        active.dismiss();
    }
});
window.addEventListener("scroll", () => active?.position(), true);
window.addEventListener("resize", () => active?.position());

// `today` names the day the grid marks and the today button picks; a form
// whose times are in another zone passes its own.
export function attachDatetime(input, { today = localToday } = {}) {
    if (input.dataset.smDatetime) return;
    input.dataset.smDatetime = "1";
    const id = `sm-dt-${++seq}`;
    const firstDay = weekStart();

    const root = el("div", "sm-datetime");
    const trigger = el("button", `${input.className} sm-datetime__trigger`);
    trigger.type = "button";
    trigger.setAttribute("aria-haspopup", "dialog");
    trigger.setAttribute("aria-expanded", "false");
    trigger.setAttribute("aria-controls", `${id}-panel`);
    const valueEl = el("span", "sm-datetime__value");
    valueEl.id = `${id}-value`;
    const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    icon.setAttribute("class", "sm-datetime__icon");
    icon.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "#i-calendar");
    icon.appendChild(use);
    trigger.append(valueEl, icon);

    // The panel sits inside the field's <label>, whose text would otherwise
    // become the button's name.
    const label = input.closest(".field-outline")?.querySelector(".field-outline__label");
    if (label) {
        label.id ||= `${id}-label`;
        trigger.setAttribute("aria-labelledby", `${label.id} ${valueEl.id}`);
    }

    const panel = el("div", "sm-datetime__panel");
    panel.id = `${id}-panel`;
    panel.hidden = true;
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Choose date and time");

    const head = el("div", "sm-datetime__head");
    const prev = el("button", "sm-datetime__nav", "‹");
    const next = el("button", "sm-datetime__nav", "›");
    const month = el("span", "sm-datetime__month");
    const todayBtn = el("button", "sm-datetime__today", "today");
    prev.type = next.type = todayBtn.type = "button";
    prev.setAttribute("aria-label", "Previous month");
    next.setAttribute("aria-label", "Next month");
    month.id = `${id}-month`;
    month.setAttribute("aria-live", "polite");
    head.append(prev, month, next, todayBtn);

    const grid = el("table", "sm-datetime__grid");
    grid.setAttribute("role", "grid");
    grid.setAttribute("aria-labelledby", month.id);
    const headRow = el("tr");
    for (let i = 0; i < 7; i++) {
        const th = el("th", null, DAYS[(firstDay + i) % 7].slice(0, 2));
        th.scope = "col";
        headRow.appendChild(th);
    }
    const thead = el("thead");
    thead.appendChild(headRow);
    const body = el("tbody");
    grid.append(thead, body);

    const timeRow = el("div", "sm-datetime__time");
    const hour = numberField("Hour");
    const minute = numberField("Minute");
    timeRow.append(el("span", null, "time"), hour, el("span", null, ":"), minute, el("span", null, "24h"));

    panel.append(head, grid, timeRow);
    input.parentNode.insertBefore(root, input);
    root.append(trigger, panel, input);
    input.className = "sm-datetime__carrier";
    input.tabIndex = -1;
    input.setAttribute("aria-hidden", "true");

    let cursor = today();

    function numberField(name) {
        const f = el("input", "field sm-datetime__num");
        f.type = "text";
        f.inputMode = "numeric";
        f.maxLength = 2;
        f.autocomplete = "off";
        f.spellcheck = false;
        f.setAttribute("aria-label", name);
        return f;
    }

    function current() {
        return parse(input.value);
    }

    function value() {
        return current() || { ...cursor, h: 9, mi: 0 };
    }

    function write(t) {
        input.value = format(t);
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
    }

    function sync() {
        const t = current();
        valueEl.textContent = t
            ? `${DAYS[utc(t).getUTCDay()]} ${t.d} ${MONTHS[t.mo]} ${t.y} · ${pad(t.h)}:${pad(t.mi)}`
            : "pick a time";
        valueEl.classList.toggle("sm-datetime__value--empty", !t);
    }

    function render() {
        const picked = current();
        const now = today();
        month.textContent = `${MONTHS[cursor.mo]} ${cursor.y}`;
        const lead = (utc({ ...cursor, d: 1 }).getUTCDay() - firstDay + 7) % 7;
        const count = daysIn(cursor.y, cursor.mo);
        const cells = Math.ceil((lead + count) / 7) * 7;
        body.textContent = "";
        let row;
        for (let i = 0; i < cells; i++) {
            if (i % 7 === 0) row = body.appendChild(el("tr"));
            const td = row.appendChild(el("td"));
            const d = i - lead + 1;
            if (d < 1 || d > count) continue;
            const day = { y: cursor.y, mo: cursor.mo, d };
            const btn = td.appendChild(el("button", "sm-datetime__day", String(d)));
            btn.type = "button";
            btn.dataset.day = d;
            btn.tabIndex = d === cursor.d ? 0 : -1;
            btn.setAttribute("aria-label", LONG.format(utc(day)));
            if (sameDay(day, now)) btn.setAttribute("aria-current", "date");
            td.setAttribute("aria-selected", String(sameDay(day, picked)));
        }
    }

    function syncTime() {
        const t = value();
        hour.value = pad(t.h);
        minute.value = pad(t.mi);
    }

    function focusCursor() {
        body.querySelector(`[data-day="${cursor.d}"]`)?.focus();
    }

    function moveTo(day) {
        cursor = day;
        render();
        focusCursor();
    }

    function pick(day) {
        write({ ...value(), ...day });
        moveTo(day);
    }

    function position() {
        window.smPositionFloating(trigger, panel, {});
    }

    function open() {
        if (active && active !== api) active.close();
        active = api;
        const t = current();
        cursor = t ? { y: t.y, mo: t.mo, d: t.d } : today();
        render();
        syncTime();
        trigger.setAttribute("aria-expanded", "true");
        position();
        focusCursor();
    }

    function close() {
        if (active === api) active = null;
        panel.hidden = true;
        trigger.setAttribute("aria-expanded", "false");
    }

    function dismiss() {
        close();
        trigger.focus();
    }

    // The rebuilt grid drops the day that had focus, so focus stays on the
    // pressed button and Escape still reaches the panel.
    function turn(btn, months) {
        cursor = addMonths(cursor, months);
        render();
        position();
        btn.focus();
    }

    trigger.addEventListener("click", () => (active === api ? close() : open()));
    prev.addEventListener("click", () => turn(prev, -1));
    next.addEventListener("click", () => turn(next, 1));
    todayBtn.addEventListener("click", () => { pick(today()); position(); });
    body.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-day]");
        if (btn) pick({ y: cursor.y, mo: cursor.mo, d: Number(btn.dataset.day) });
    });

    const steps = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 };
    body.addEventListener("keydown", (e) => {
        const offset = (utc(cursor).getUTCDay() - firstDay + 7) % 7;
        let to = null;
        if (e.key in steps) to = addDays(cursor, steps[e.key]);
        else if (e.key === "Home") to = addDays(cursor, -offset);
        else if (e.key === "End") to = addDays(cursor, 6 - offset);
        else if (e.key === "PageUp") to = addMonths(cursor, e.shiftKey ? -12 : -1);
        else if (e.key === "PageDown") to = addMonths(cursor, e.shiftKey ? 12 : 1);
        if (!to) return;
        e.preventDefault();
        const resized = to.mo !== cursor.mo;
        moveTo(to);
        if (resized) position();
    });

    function wireTime(f, part, max, step) {
        const read = () => value()[part];
        const apply = (n) => write({ ...value(), [part]: n });
        f.addEventListener("input", () => {
            f.value = f.value.replace(/\D/g, "");
            if (f.value === "" || Number(f.value) > max) return;
            apply(Number(f.value));
            if (f === hour && (f.value.length === 2 || Number(f.value) * 10 > max)) minute.select();
        });
        f.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                dismiss();
            } else if (e.key === "ArrowUp" || e.key === "ArrowDown") {
                e.preventDefault();
                const n = read();
                const up = e.key === "ArrowUp";
                const stepped = up ? Math.floor(n / step) * step + step : Math.ceil(n / step) * step - step;
                apply((stepped + max + 1) % (max + 1));
                f.value = pad(read());
                f.select();
            }
        });
        f.addEventListener("focus", () => f.select());
        f.addEventListener("blur", () => { f.value = pad(read()); });
    }
    wireTime(hour, "h", 23, 1);
    wireTime(minute, "mi", 59, 5);

    window.smPreventPanelBlur(panel);
    // A click on the panel's empty space would otherwise activate the
    // field's <label> and toggle the trigger.
    panel.addEventListener("click", (e) => {
        if (!e.target.closest("input")) e.preventDefault();
    });
    root.addEventListener("focusout", (e) => {
        if (active === api && e.relatedTarget && !root.contains(e.relatedTarget)) close();
    });

    input.addEventListener("input", sync);
    input.addEventListener("focus", () => trigger.focus());
    new MutationObserver(() => {
        const invalid = input.getAttribute("aria-invalid");
        if (invalid) trigger.setAttribute("aria-invalid", invalid);
        else trigger.removeAttribute("aria-invalid");
    }).observe(input, { attributes: true, attributeFilter: ["aria-invalid"] });

    const api = { scope: root.closest("label") || root, close, dismiss, position };
    sync();
}
