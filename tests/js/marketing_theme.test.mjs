import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../../assets/js/marketing/theme.js", import.meta.url), "utf8");

function harness({ pick, account, writes = "allowed", dark = false, tracker = true } = {}) {
    const jar = new Map();
    if (pick) jar.set("sm_theme_pick", pick);
    if (account) jar.set("sm_app_theme", account);
    const events = {};
    const root = { dataset: {} };
    const toggles = [0, 1].map(() => ({ setAttribute(name, value) { this[name] = value; } }));
    const document = {
        documentElement: root,
        visibilityState: "visible",
        get cookie() { return [...jar].map(([k, v]) => `${k}=${v}`).join("; "); },
        set cookie(value) {
            if (writes === "throw") throw new Error("Cookie writes denied");
            if (writes === "blocked") return;
            const [name, mode] = value.split(";")[0].split("=");
            jar.set(name, mode);
        },
        querySelector: () => null,
        querySelectorAll: () => toggles,
        addEventListener: (name, fn) => { events[name] = fn; },
    };
    const os = { matches: dark, addEventListener: (name, fn) => { events[`os:${name}`] = fn; } };
    const tracked = [];
    const window = tracker ? { umami: { track: (name, data) => tracked.push([name, { ...data }]) } } : {};
    vm.runInNewContext(source, {
        document, window, matchMedia: () => os,
        location: { hostname: "www.uptimepage.test", protocol: "https:" },
    });
    return {
        root, jar, toggles, tracked,
        click() { events.click({ target: { closest: () => toggles[0] } }); },
        visible() { events.visibilitychange(); },
        flipOS() { os.matches = !os.matches; events["os:change"](); },
    };
}

test("toggle works when writes are denied, including an existing pick", () => {
    for (const writes of ["blocked", "throw"]) {
        for (const pick of [undefined, "light", "dark"]) {
            const h = harness({ writes, pick });
            const before = h.root.dataset.mkTheme;
            h.click();
            const after = before === "dark" ? "light" : "dark";
            assert.equal(h.root.dataset.mkTheme, after);
            assert.ok(h.toggles.every(t => t["aria-pressed"] === String(after === "dark")));
            h.visible();
            h.flipOS();
            assert.equal(h.root.dataset.mkTheme, after);
            h.click();
            assert.equal(h.root.dataset.mkTheme, before);
        }
    }
});

test("a persisted toggle picks up changes from another tab", () => {
    const h = harness();
    h.click();
    assert.equal(h.jar.get("sm_theme_pick"), "dark");
    h.jar.set("sm_theme_pick", "light");
    h.visible();
    assert.equal(h.root.dataset.mkTheme, "light");
});

test("a marketing pick overrides the account mirror without changing it", () => {
    for (const account of ["nord", "system", "dracula"]) {
        const h = harness({ account });
        h.click();
        assert.equal(h.jar.get("sm_app_theme"), account);
        const picked = h.root.dataset.mkTheme;
        h.jar.set("sm_app_theme", "dark");
        h.visible();
        assert.equal(h.root.dataset.mkTheme, picked);
        assert.equal(h.jar.get("sm_theme_pick"), picked);
    }
});

test("each toggle reports the mode it switched to", () => {
    const h = harness();
    h.click();
    h.click();
    assert.deepEqual(h.tracked, [["theme-toggle", { to: "dark" }], ["theme-toggle", { to: "light" }]]);
});

test("the toggle works when the tracker is blocked", () => {
    const h = harness({ tracker: false });
    h.click();
    assert.equal(h.root.dataset.mkTheme, "dark");
});
