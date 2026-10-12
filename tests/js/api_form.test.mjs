import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../../assets/js/ui/api_form.js", import.meta.url), "utf8");

function render(error) {
    const window = {};
    vm.runInNewContext(source, { window, document: {} });
    const banner = {
        innerHTML: "",
        classList: { remove() {} },
        insertAdjacentHTML(_, html) { this.innerHTML += html; },
        scrollIntoView() {},
    };
    const fields = [];
    window.smRenderApiError(banner, { error }, 400, { onField: field => fields.push(field) });
    return { html: banner.innerHTML, fields };
}

test("an SSRF block keeps the server's words and adds the way out, whichever field it lands on", () => {
    for (const field of ["check.url", "check.host", "check.resolver", "check.steps"]) {
        const message = "step 3: target address 10.0.0.53 is in a blocked range";
        const { html, fields } = render({ code: "SSRF_BLOCKED", message, field });
        assert.match(html, /step 3: target address 10\.0\.0\.53 is in a blocked range\. To monitor internal services, run a monitor agent inside that network\./);
        assert.doesNotMatch(html, /URL/);
        assert.deepEqual(fields, [field]);
    }
});

test("any other refusal shows the server's message", () => {
    const { html } = render({
        code: "INVALID_DNS_PARAMS",
        message: "dns resolver must be an IP or ip:port",
        field: "check.resolver",
    });
    assert.match(html, /<strong>INVALID_DNS_PARAMS<\/strong>: dns resolver must be an IP or ip:port/);
});
