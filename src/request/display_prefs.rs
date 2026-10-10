//! Issues the per-user display-preference cookies — theme (`sm_app_theme`) and
//! time format (`sm_time_format`) — that the page-shell boot script and
//! `localtime.js` read on first paint. One read, both cookies: every
//! sign-in goes through this so a new auth path can't ship one preference
//! cookie and silently forget the other. The DB columns remain the source of
//! truth; the per-preference PATCH handlers set their own cookie.

use axum::extract::{FromRequestParts, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use sqlx::PgPool;
use tower_cookies::Cookies;

use crate::domain::UserId;
use crate::error::Result;
use crate::request::nav_identity::is_app_page_load;
use crate::request::theme::{self, CookieScope};
use crate::request::time_format;
use crate::request::{RequestState, Session};
use crate::storage::users as users_store;

/// Issues the cookies on an app page load whose browser lacks the theme
/// mirror, such as a session signed in before the mirror existed.
pub async fn middleware(State(state): State<RequestState>, req: Request, next: Next) -> Response {
    if !is_app_page_load(&state, &req) {
        return next.run(req).await;
    }
    let (mut parts, body) = req.into_parts();
    let session = Session::from_request_parts(&mut parts, &state)
        .await
        .expect("Session extractor is infallible");
    if let (Some(pool), Some(user), Some(cookies)) = (
        state.db.as_ref(),
        session.user_id(),
        parts.extensions.get::<Cookies>(),
    ) && cookies.get(theme::COOKIE_NAME).is_none()
        && let Err(err) =
            issue_cookies(pool, CookieScope::from_config(&state.cfg), cookies, user).await
    {
        tracing::warn!(error = %err, "display-preference cookie refresh failed (non-fatal)");
    }
    next.run(Request::from_parts(parts, body)).await
}

/// A new account starts on the light/dark mode picked on the marketing site.
pub async fn adopt_pick(pool: &PgPool, cookies: &Cookies, user: UserId) -> Result<()> {
    if let Some(picked) = theme::pending_pick(cookies) {
        users_store::set_theme(pool, user, picked).await?;
    }
    Ok(())
}

pub async fn issue_cookies(
    pool: &PgPool,
    scope: CookieScope<'_>,
    cookies: &Cookies,
    user: UserId,
) -> Result<()> {
    let prefs = users_store::get_display_prefs(pool, user).await?;
    cookies.add(theme::build_cookie(prefs.theme, scope));
    cookies.add(time_format::build_cookie(prefs.time_format, scope.secure));
    Ok(())
}
