import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../../assets/js/ui/maintenance_detail.js", import.meta.url), "utf8");

function setup() {
    const handlers = {};
    const requests = [];
    const errors = [];
    const button = { disabled: false };
    let reloads = 0;
    let submission;
    const form = {
        dataset: { id: "window-1" },
        closest: () => form,
        querySelector: () => button,
        requestSubmit() {
            submission = handlers.submit({ target: form, preventDefault() {} });
        },
    };
    vm.runInNewContext(source, {
        document: {
            getElementById: () => ({}),
            addEventListener: (name, handler) => { handlers[name] = handler; },
        },
        window: {
            smClearFormErrors() {},
            smRenderClientError: (_, error) => errors.push(error),
            smRenderApiError: (_, json, status) => errors.push(status),
            smIdempotencyKey: () => "key-1",
            location: { reload: () => { reloads++; } },
        },
        FormData: class { get() { return "Maintenance is underway"; } },
        fetch: () => new Promise((resolve, reject) => requests.push({ resolve, reject })),
    });
    return {
        button, requests, errors,
        reloads: () => reloads,
        submit(metaKey = false) {
            handlers.keydown({
                target: form, key: "Enter", metaKey, ctrlKey: !metaKey,
                preventDefault() {},
            });
            return submission;
        },
    };
}

test("repeated Cmd/Ctrl+Enter posts once while pending and while a successful reload is pending", async () => {
    const ui = setup();
    const pending = ui.submit(true);
    await ui.submit();
    await ui.submit(true);
    assert.equal(ui.requests.length, 1);
    assert.equal(ui.button.disabled, true);

    ui.requests[0].resolve({ ok: true });
    await pending;
    assert.equal(ui.reloads(), 1);
    await ui.submit();
    assert.equal(ui.requests.length, 1);
    assert.equal(ui.button.disabled, true);
});

for (const failure of ["API", "network"]) {
    test(`${failure} failure unlocks the form for a retry`, async () => {
        const ui = setup();
        const pending = ui.submit();
        await ui.submit(true);
        assert.equal(ui.requests.length, 1);
        if (failure === "API") {
            ui.requests[0].resolve({ ok: false, status: 500, json: async () => ({}) });
        } else {
            ui.requests[0].reject(new Error("offline"));
        }
        await pending;
        assert.equal(ui.errors.length, 1);
        assert.equal(ui.button.disabled, false);
        assert.equal(ui.reloads(), 0);

        const retry = ui.submit();
        assert.equal(ui.requests.length, 2);
        ui.requests[1].resolve({ ok: true });
        await retry;
        assert.equal(ui.reloads(), 1);
    });
}
