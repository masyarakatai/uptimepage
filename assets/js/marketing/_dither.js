// Footer dot field. Dots under a mouse pointer stay at full strength and the
// rest dim; touch and pen keep the plain field, having no hover to follow.
const band = document.querySelector(".mk-dither");

if (band) {
    const field = band.querySelector(".mk-dither__field");
    let x = 0;
    let y = 0;
    let pending = false;

    band.addEventListener("pointermove", (e) => {
        if (e.pointerType !== "mouse") return;
        x = e.clientX;
        y = e.clientY;
        if (pending) return;
        pending = true;
        requestAnimationFrame(() => {
            if (!pending) return;
            pending = false;
            const r = field.getBoundingClientRect();
            field.style.setProperty("--mk-dither-x", `${x - r.left}px`);
            field.style.setProperty("--mk-dither-y", `${y - r.top}px`);
            field.classList.add("mk-dither__field--lit");
        });
    });
    band.addEventListener("pointerleave", () => {
        pending = false;
        field.classList.remove("mk-dither__field--lit");
    });
}
