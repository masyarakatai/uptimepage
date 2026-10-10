// Sets <html data-mk-theme> before the stylesheet parses; the CSP allows no
// inline script, hence a blocking file. A toggle pick wins, then the account
// theme mirrored into sm_app_theme; "system" or no account follows the OS.
(() => {
    const PICK = "sm_theme_pick";
    // The app themes that set color-scheme: dark in input.css.
    const DARK_APP_THEMES = ["terminal", "dark", "night", "dim", "dracula", "synthwave"];
    const THEME_COLOR = { light: "#f9fafb", dark: "#0e1216" };
    const root = document.documentElement;
    const os = matchMedia("(prefers-color-scheme: dark)");
    // Stands in when the browser refuses the cookie.
    let clicked;

    const cookie = (name) =>
        document.cookie.match(new RegExp(`(?:^|; )${name}=([a-z]+)(?:;|$)`))?.[1];

    const mode = () => {
        const pick = clicked ?? cookie(PICK);
        if (pick === "light" || pick === "dark") return pick;
        const app = cookie("sm_app_theme");
        if (app && app !== "system") return DARK_APP_THEMES.includes(app) ? "dark" : "light";
        return os.matches ? "dark" : "light";
    };

    const apply = () => {
        const current = mode();
        root.dataset.mkTheme = current;
        document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLOR[current]);
        for (const toggle of document.querySelectorAll("[data-mk-theme-toggle]")) {
            toggle.setAttribute("aria-pressed", String(current === "dark"));
        }
    };

    // Parent domain, so the app host reads it at sign-up.
    const remember = (pick) => {
        const domain = location.hostname.replace(/^www\./, "");
        const secure = location.protocol === "https:" ? "; secure" : "";
        try {
            document.cookie = `${PICK}=${pick}; domain=${domain}; path=/; max-age=31536000; samesite=lax${secure}`;
        } catch {
            // The current page can still switch when cookie writes are denied.
        }
        clicked = cookie(PICK) === pick ? undefined : pick;
    };

    apply();
    os.addEventListener("change", apply);
    document.addEventListener("DOMContentLoaded", apply);
    // Another tab may have picked or changed the account theme.
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") apply();
    });
    document.addEventListener("click", (e) => {
        if (!e.target.closest("[data-mk-theme-toggle]")) return;
        clicked = root.dataset.mkTheme === "dark" ? "light" : "dark";
        remember(clicked);
        apply();
    });
})();
