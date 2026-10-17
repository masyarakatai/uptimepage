import assert from "node:assert/strict";
import { test } from "node:test";

import { ALPHABET, LENGTH, LIMIT, generatePassword } from "../../assets/js/ui/_page_password.js";

test("the alphabet has 56 distinct symbols and none that read alike", () => {
    assert.equal(ALPHABET.length, 56);
    assert.equal(new Set(ALPHABET).size, 56);
    for (const lookalike of "IOol01") assert.ok(!ALPHABET.includes(lookalike), lookalike);
    assert.ok(LENGTH * Math.log2(ALPHABET.length) > 116);
});

test("every symbol is equally likely: bytes from the limit up are dropped", () => {
    assert.equal(LIMIT, 224);
    const counts = new Map();
    for (let b = 0; b < LIMIT; b++) {
        const c = ALPHABET[b % ALPHABET.length];
        counts.set(c, (counts.get(c) || 0) + 1);
    }
    assert.deepEqual(new Set(counts.values()), new Set([4]));

    // Only out-of-range bytes first, then one good one per call.
    let calls = 0;
    const random = (n) => {
        calls++;
        return Uint8Array.from({ length: n }, (_, i) => (calls === 1 ? 224 + (i % 32) : i === 0 ? 0 : 255));
    };
    const out = generatePassword(random);
    assert.equal(out, ALPHABET[0].repeat(LENGTH));
    assert.equal(calls, LENGTH + 1);
});

test("a generated password is 20 symbols from the alphabet", () => {
    for (let i = 0; i < 50; i++) {
        const p = generatePassword();
        assert.equal(p.length, LENGTH);
        for (const c of p) assert.ok(ALPHABET.includes(c), c);
    }
});
