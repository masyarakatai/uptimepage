// One Idempotency-Key per message a form posts: a retry of the same text after
// an error reuses it, so a post that did land is replayed instead of published
// twice; changed text gets a new one. Built from getRandomValues because
// crypto.randomUUID exists only on secure origins.
(() => {
    window.smIdempotencyKey = (form, body) => {
        if (form.dataset.idempotencyFor !== body) {
            form.dataset.idempotencyKey = Array.from(
                crypto.getRandomValues(new Uint8Array(16)),
                (b) => b.toString(16).padStart(2, "0"),
            ).join("");
            form.dataset.idempotencyFor = body;
        }
        return form.dataset.idempotencyKey;
    };
})();
