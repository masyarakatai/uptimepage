// Passkeys on a private status page: sign in with one (button or browser
// autofill), or save one after an email sign-in. Hidden where the browser has
// no WebAuthn; the email code always works.
(function () {
    "use strict";

    if (!window.smPasskey || !smPasskey.supported()) return;
    document.querySelectorAll("[data-passkey-only]").forEach(function (el) {
        el.hidden = false;
    });

    const root = document.querySelector("[data-access-step]");
    const next = root ? root.getAttribute("data-next") : "/";
    const error = document.getElementById("page-passkey-error");

    function show(message) {
        if (!error) return;
        error.textContent = message;
        error.hidden = false;
    }

    async function post(path, body) {
        const res = await fetch(path, {
            method: "POST",
            headers: smPasskey.headers,
            body: JSON.stringify(body || {}),
        });
        let code = "";
        if (!res.ok) {
            try {
                code = ((await res.json()).error || {}).code || "";
            } catch (_) {
                code = "";
            }
            const err = new Error(code || "HTTP " + res.status);
            err.code = code;
            throw err;
        }
        return res.status === 204 ? null : res.json();
    }

    // Sign-in ---------------------------------------------------------------

    const signIn = document.getElementById("page-passkey-signin");
    let pending = null;

    async function authenticate(mediation) {
        const challenge = await post("/access/passkey/login/start");
        const options = { publicKey: smPasskey.decodeOptions(challenge.options.publicKey || challenge.options) };
        if (mediation) {
            pending = new AbortController();
            options.mediation = mediation;
            options.signal = pending.signal;
        }
        const assertion = await navigator.credentials.get(options);
        if (!assertion) return;
        const done = await post("/access/passkey/login/finish", {
            handle: challenge.handle,
            credential: smPasskey.encodeCredential(assertion),
            next: next,
        });
        window.location = done.redirect;
    }

    function failed(err) {
        if (smPasskey.isAbandoned(err)) return;
        show(err.code === "PAGE_EMAIL_RECHECK"
            ? signIn.getAttribute("data-recheck")
            : signIn.getAttribute("data-refused"));
    }

    if (signIn) {
        signIn.addEventListener("click", async function () {
            if (pending) pending.abort();
            if (error) error.hidden = true;
            signIn.disabled = true;
            try {
                await authenticate(null);
            } catch (err) {
                failed(err);
            }
            signIn.disabled = false;
        });

        // Autofill: the browser lists saved passkeys under the email field.
        if (window.PublicKeyCredential.isConditionalMediationAvailable) {
            window.PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
                if (ok) authenticate("conditional").catch(failed);
            });
        }
    }

    // Save after an email sign-in ------------------------------------------

    const save = document.getElementById("page-passkey-save");
    if (save) {
        save.addEventListener("click", async function () {
            if (error) error.hidden = true;
            save.disabled = true;
            try {
                const challenge = await post("/access/passkey/register/start");
                const credential = await navigator.credentials.create({
                    publicKey: smPasskey.decodeOptions(challenge.options.publicKey || challenge.options),
                });
                if (!credential) throw new Error("no passkey was created");
                await post("/access/passkey/register/finish", {
                    handle: challenge.handle,
                    credential: smPasskey.encodeCredential(credential),
                });
                window.location = next;
            } catch (err) {
                if (!smPasskey.isAbandoned(err)) show(save.getAttribute("data-failed"));
                save.disabled = false;
            }
        });
    }
})();
