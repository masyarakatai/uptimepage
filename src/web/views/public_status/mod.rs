//! Server-rendered public status page: the routes and the pages they return.
//!
//! Reads from the same `PublicSource` (and therefore the same in-process
//! cache) as the JSON endpoint, so a JSON and HTML request landing in the
//! same 10s window share one aggregator run.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::app::AppState;
use crate::domain::AssetSlot;
use crate::domain::{PageRef, StatusPageId};
use crate::error::public::PublicAppError;
use crate::i18n::Tr;
use crate::public_status::access::{Access, feed_token, password_feed_token};
use crate::public_status::history::{HistoryEntry, HistoryPage, merge};
use crate::request::host::{
    is_subdomain_public_request, published_page_origin, resolve_status_page,
};
use crate::robots::{self, mark_private};
use crate::templates::filters;
use crate::web::error::render_public_error;
use crate::web::views::page_branding::{BrandingView, resolve_branding, status_home};

mod incident_display;
mod og;
mod past;
#[cfg(test)]
mod tests;
mod view;

pub use og::OgMeta;
pub use past::{HistoryTab, PastEntry, PastEvents, PastItem, PhaseChip, TabLink};
pub use view::{
    ARCHIVE_URL, ComponentView, DayCell, GroupView, HistoryRequest, IncidentDetailView,
    IncidentHeader, IncidentSummary, IncidentUpdateView, MaintenanceView, RSS_URL, StatusView,
};

use og::build_og_meta;
use view::{archive_path, build_view};

/// Default page size for the archive view. Small enough that each render is
/// snappy on the unauthenticated, edge-cached path; the keyset cursor walks
/// older pages on demand.
const ARCHIVE_PAGE_SIZE: u32 = 25;

#[derive(Debug, Default, Deserialize)]
pub struct StatusParams {
    /// HTMX partial swap — return just the refresh region.
    pub fragment: Option<u8>,
    /// The history tab; see [`HistoryTab::from_query`].
    pub show: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "public/status.html")]
pub struct StatusFullPage {
    pub tr: Tr,
    pub view: StatusView,
    pub branding: BrandingView,
    pub og: OgMeta,
    pub reader: Reader,
}

/// Who reads the page, for the parts that differ on a private one: the
/// signed-in strip, subscribing as oneself, and the feed link.
#[derive(Debug, Clone)]
pub struct Reader {
    /// The signed-in viewer's address on a private page.
    pub viewer: Option<String>,
    /// Signed in with the page password, which names nobody.
    pub password: bool,
    /// The page's feed, or the reader's own link to it.
    pub rss_url: String,
}

impl Default for Reader {
    fn default() -> Self {
        Self {
            viewer: None,
            password: false,
            rss_url: RSS_URL.to_owned(),
        }
    }
}

impl Reader {
    async fn of(state: &AppState, page: PageRef, access: &Access) -> Self {
        let secret = state.page_feed_secret.as_str();
        match access {
            Access::Viewer(viewer) => Self {
                viewer: Some(viewer.email.clone()),
                password: false,
                rss_url: if secret.is_empty() {
                    RSS_URL.to_owned()
                } else {
                    format!(
                        "{RSS_URL}?viewer={}&t={}",
                        viewer.id,
                        feed_token(secret, page.page, viewer.id)
                    )
                },
            },
            Access::Password { session } => Self {
                viewer: None,
                password: true,
                rss_url: password_feed_url(state, page, secret, session.as_deref())
                    .await
                    .unwrap_or_else(|| RSS_URL.to_owned()),
            },
            _ => Self::default(),
        }
    }
}

/// The page-password feed link for `session`. Cut from the stored hash, so the
/// page has to be read for it; without one the plain feed URL still works in
/// this browser.
async fn password_feed_url(
    state: &AppState,
    page: PageRef,
    secret: &str,
    session: Option<&str>,
) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let session = session?;
    let pool = state.db.as_ref()?;
    match crate::storage::page_access::password::session_hash(pool, page, session).await {
        Ok(hash) => {
            hash.map(|h| format!("{RSS_URL}?t={}", password_feed_token(secret, page.page, &h)))
        }
        Err(e) => {
            tracing::warn!(error = %e, "page-password feed link not built");
            None
        }
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "public/region.html")]
pub struct StatusRegion {
    pub tr: Tr,
    pub view: StatusView,
}

#[derive(Template, WebTemplate)]
#[template(path = "public/incident.html")]
pub struct IncidentDetailPage {
    pub tr: Tr,
    pub branding: BrandingView,
    pub incident: IncidentDetailView,
    pub generated_at: DateTime<Utc>,
    pub og: OgMeta,
    pub reader: Reader,
}

#[derive(Template, WebTemplate)]
#[template(path = "public/archive.html")]
pub struct IncidentArchivePage {
    pub tr: Tr,
    pub branding: BrandingView,
    /// Heading and empty line, in the words of the tab.
    pub heading: String,
    pub empty: String,
    pub tabs: Vec<TabLink>,
    /// Rows bucketed by `(year, month-name)` in DESC chronological order.
    /// The template iterates each month as a section so the user scans by
    /// date without explicit date-pickers — UX matches the Atlassian /
    /// Statuspage.io archive convention.
    pub months: Vec<MonthBucket>,
    /// The next page of older rows on the same tab; `None` when this is the
    /// last page.
    pub older_url: Option<String>,
    /// Per-page robots directive; see [`archive_robots`].
    pub robots: &'static str,
    pub og: OgMeta,
    pub reader: Reader,
}

pub struct MonthBucket {
    /// Already formatted ("May 2026"), so the template renders it verbatim.
    pub label: String,
    pub rows: Vec<PastEntry>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ArchiveParams {
    /// Keyset cursor returned by the previous archive page's next link.
    /// Same opaque-token shape used by `/api/public/v1/incidents`.
    pub cursor: Option<String>,
    /// The history tab; see [`HistoryTab::from_query`].
    pub show: Option<String>,
}
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<StatusParams>,
) -> Response {
    let fragment = params.fragment.unwrap_or(0) != 0;
    let home = status_home(&state, &headers);
    let (page_ref, access) = match readable(&state, &headers, home, fragment).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let (page, markers) = match state.public_source.page_with_markers(page_ref).await {
        Ok(pair) => pair,
        Err(err) => return render_public_error(err),
    };
    let silenced: std::collections::HashSet<Uuid> = state
        .silence_store
        .open_target_ids(page_ref.org)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    let tr = Tr::new(state.public_source.locale(page_ref).await);
    let history = HistoryRequest {
        tab: HistoryTab::from_query(params.show.as_deref()),
        home,
    };
    let view = build_view(&page, &markers, &silenced, history, tr);
    let resp = if fragment {
        // Chrome-free auto-refresh fragment: no header/footer/style, so the
        // branding lookup is skipped on the 30s poll.
        let mut resp = with_language(StatusRegion { tr, view }, tr);
        // The page's own content at a second URL, with no <head> to say so. A
        // bare noindex on a duplicate can take the page it duplicates with it,
        // hence the canonical.
        resp.headers_mut()
            .insert(robots::X_ROBOTS_TAG, robots::NOINDEX_FOLLOW);
        if let Some(canonical) = canonical_link(&state, &headers, page_ref.page) {
            resp.headers_mut().insert(header::LINK, canonical);
        }
        resp
    } else {
        let branding = page_branding(&state, &headers, page_ref, &access, &page.site_name).await;
        let og = build_og_meta(
            &state,
            &headers,
            page_ref.page,
            branding.home,
            branding.status_title(),
            tr.t_args(
                "og-status-description",
                [("name", branding.display_name.as_str().into())],
            ),
            "website",
            &branding,
        );
        with_language(
            StatusFullPage {
                tr,
                view,
                branding,
                og,
                reader: Reader::of(&state, page_ref, &access).await,
            },
            tr,
        )
    };
    privately(resp, &access)
}

/// The page this host serves, past the access gate. `Err` is the answer to
/// send instead: a 404, or for a private page nobody here may read yet, the
/// sign-in screen (a bare 401 for the refresh poll, which has nowhere to put
/// one). `next` is where sign-in returns to.
async fn readable(
    state: &AppState,
    headers: &HeaderMap,
    next: &str,
    fragment: bool,
) -> Result<(PageRef, Access), Response> {
    let page = resolve_status_page(&state.request_state(), headers)
        .await
        .map_err(render_public_error)?;
    match state
        .page_gate
        .check(state.db.as_ref(), page, headers)
        .await
    {
        Ok(Access::SignInRequired(_)) if fragment => {
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            mark_private(&mut resp);
            Err(resp)
        }
        Ok(Access::SignInRequired(access)) => {
            Err(super::page_access::sign_in_screen(state, headers, page, &access, next).await)
        }
        Ok(access) => Ok((page, access)),
        Err(err) => Err(render_public_error(err)),
    }
}

/// Branding as the page renders it. A private page is never offered to a
/// search engine, whatever the owner chose for it as a public one.
async fn page_branding(
    state: &AppState,
    headers: &HeaderMap,
    page: PageRef,
    access: &Access,
    fallback_name: &str,
) -> BrandingView {
    let mut branding = resolve_branding(state, headers, page.org, page.page, fallback_name).await;
    if access.is_private() {
        branding.hide_from_search = true;
        branding.follow_website_link = false;
    }
    branding
}

fn privately(mut resp: Response, access: &Access) -> Response {
    if access.is_private() {
        mark_private(&mut resp);
    }
    resp
}

fn with_language(page: impl IntoResponse, tr: Tr) -> Response {
    let mut resp = page.into_response();
    resp.headers_mut().insert(
        header::CONTENT_LANGUAGE,
        header::HeaderValue::from_static(tr.lang()),
    );
    resp
}

/// A tenant host answers the same page at `/`, so `/status` there is a second
/// URL for one page: it splits search ranking and gives visitors two addresses
/// to share. Redirect to the one the page links to itself. A path-based deploy
/// serves the operator dashboard at `/`, so `/status` stays the page there.
pub async fn status_path(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    query: Query<StatusParams>,
) -> Response {
    if !is_subdomain_public_request(&state.request_state(), &headers) {
        return index(State(state), headers, query).await;
    }
    // Resolve before redirecting so a host with no live page still 404s here
    // rather than answering for one it cannot serve.
    if let Err(err) = resolve_status_page(&state.request_state(), &headers).await {
        return render_public_error(err);
    }
    // The 30s refresh poll of an already-open tab still asks for `?fragment=1`
    // here, and losing the query would swap the whole page into the region.
    let target = match uri.query() {
        Some(q) => format!("/?{q}"),
        None => "/".to_owned(),
    };
    Redirect::permanent(&target).into_response()
}

/// Serves the page's uploaded logo (or 404 when none is set). Same host→page
/// resolution as the page itself; the query string is a cache-buster only,
/// never a selector — the bytes come from the page's `logo` asset row.
pub async fn logo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let page_ref = match resolve_status_page(&state.request_state(), &headers).await {
        Ok(p) => p,
        Err(err) => return render_public_error(err),
    };
    match state
        .page_asset_store
        .get(page_ref.page, AssetSlot::Logo)
        .await
    {
        Ok(Some(asset)) => (
            [
                (header::CONTENT_TYPE, asset.content_type),
                (
                    header::CACHE_CONTROL,
                    "public, max-age=3600, immutable".to_owned(),
                ),
                // User-uploaded bytes served on the same origin as the app
                // (path-based public routing). nosniff stops MIME-guessing
                // past the forced image type; inline keeps it a passive asset.
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
                (header::CONTENT_DISPOSITION, "inline".to_owned()),
            ],
            asset.bytes,
        )
            .into_response(),
        Ok(None) => render_public_error(PublicAppError::NotFound),
        Err(e) => render_public_error(PublicAppError::from(e)),
    }
}

/// Leads with the title: every incident on one component would otherwise ship
/// a byte-identical description. The component name is a lookup that can come
/// back empty, so it drops out rather than leaving a dangling "affecting ".
fn incident_description(title: &str, component_name: &str, display_name: &str, tr: Tr) -> String {
    // Every interpolated value is customer text, so each is capped: three
    // unbounded names would push the tag well past what a SERP snippet shows.
    let cap = crate::text::truncate_chars;
    let full = crate::public_status::status_title(display_name);
    let page = if full.chars().count() <= 37 {
        full
    } else {
        format!("{} Status", cap(display_name, 30))
    };
    let title = cap(title, 60);
    if component_name.is_empty() {
        tr.t_args(
            "og-incident-description",
            [("title", title.into()), ("page", page.into())],
        )
    } else {
        tr.t_args(
            "og-incident-description-affecting",
            [
                ("title", title.into()),
                ("component", cap(component_name, 30).into()),
                ("page", page.into()),
            ],
        )
    }
}

pub async fn incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let next = format!("/status/incidents/{id}");
    let (page_ref, access) = match readable(&state, &headers, &next, false).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let (inc_res, page_res, locale) = tokio::join!(
        state.public_source.incident_by_id(page_ref, id),
        state.public_source.page(page_ref),
        state.public_source.locale(page_ref),
    );
    let tr = Tr::new(locale);
    let inc = match inc_res {
        Ok(i) => i,
        Err(err) => return render_public_error(err),
    };
    let fallback_name = match page_res {
        Ok(p) => p.site_name.clone(),
        Err(err) => return render_public_error(err),
    };
    let branding = page_branding(&state, &headers, page_ref, &access, &fallback_name).await;
    let now = Utc::now();
    let og = build_og_meta(
        &state,
        &headers,
        page_ref.page,
        &format!("/status/incidents/{id}"),
        format!("{} · {}", inc.title, branding.status_title()),
        incident_description(&inc.title, &inc.component_name, &branding.display_name, tr),
        "article",
        &branding,
    );
    let resp = with_language(
        IncidentDetailPage {
            tr,
            branding,
            incident: IncidentDetailView::from_incident(&inc, now, tr),
            generated_at: now,
            og,
            reader: Reader::of(&state, page_ref, &access).await,
        },
        tr,
    );
    privately(resp, &access)
}

/// Cursor-paginated archive of the page's incidents and maintenance windows,
/// on the tab the reader picked. Groups visually by month in DESC order so
/// the user scans the page like a calendar without an explicit date picker.
/// The status page links here without a cursor; the "Older" link at the
/// bottom passes `?cursor=…` to walk backwards.
pub async fn archive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ArchiveParams>,
) -> Response {
    use crate::pagination::cursor::HistoryCursor;
    use crate::pagination::page::CursorPage;
    use crate::public_status::{IncidentListQuery, MaintenanceListQuery};

    let (page_ref, access) = match readable(&state, &headers, ARCHIVE_URL, false).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let tab = HistoryTab::from_query(params.show.as_deref());
    let cursor = match params.cursor.as_deref().map(HistoryCursor::decode) {
        Some(Ok(c)) => Some(c),
        Some(Err(_)) => return render_public_error(PublicAppError::BadRequest("invalid cursor")),
        None => None,
    };
    let incidents = async {
        if !tab.shows_incidents() {
            return Ok(CursorPage::new(Vec::new(), None));
        }
        let query = IncidentListQuery {
            limit: ARCHIVE_PAGE_SIZE,
            cursor,
            ongoing_only: false,
        };
        state.public_source.list_incidents(page_ref, query).await
    };
    let maintenance = async {
        if !tab.shows_maintenance() {
            return Ok(CursorPage::new(Vec::new(), None));
        }
        let query = MaintenanceListQuery {
            limit: ARCHIVE_PAGE_SIZE,
            cursor,
            ended_only: false,
        };
        state.public_source.list_maintenance(page_ref, query).await
    };
    let (page_res, incidents_res, maintenance_res, locale) = tokio::join!(
        state.public_source.page(page_ref),
        incidents,
        maintenance,
        state.public_source.locale(page_ref),
    );
    let tr = Tr::new(locale);
    let fallback_name = match page_res {
        Ok(p) => p.site_name.clone(),
        Err(err) => return render_public_error(err),
    };
    let listing: HistoryPage = match (incidents_res, maintenance_res) {
        (Ok(i), Ok(m)) => merge(i, m, ARCHIVE_PAGE_SIZE as usize),
        (Err(err), _) | (_, Err(err)) => return render_public_error(err),
    };
    let branding = page_branding(&state, &headers, page_ref, &access, &fallback_name).await;
    let months = bucket_by_month(listing.entries, Utc::now(), tr);
    // Self-canonical, tab and cursor included. Pointing such a page at the
    // entry point instead would pair a canonical with the `noindex` below,
    // and the entry point can inherit that `noindex` — the one page here
    // worth indexing.
    let path = archive_path(tab, params.cursor.as_deref());
    let heading = tab.t(tr, "archive-heading");
    let og = build_og_meta(
        &state,
        &headers,
        page_ref.page,
        &path,
        format!("{heading} · {}", branding.status_title()),
        tr.t_args(
            "og-archive-description",
            [("page", branding.status_title().into())],
        ),
        "website",
        &branding,
    );
    let robots = archive_robots(tab, params.cursor.as_deref(), &branding);
    let resp = with_language(
        IncidentArchivePage {
            tr,
            branding,
            heading,
            empty: tab.t(tr, "archive-empty"),
            tabs: past::tab_links(ARCHIVE_URL, "", tab, tr),
            months,
            older_url: listing
                .next_cursor
                .map(|cursor| archive_path(tab, Some(&cursor))),
            robots,
            og,
            reader: Reader::of(&state, page_ref, &access).await,
        },
        tr,
    );
    privately(resp, &access)
}

/// Group sorted-DESC rows into per-month buckets, each folded into rows the
/// way the status page folds them. Months come out newest first because the
/// merge hands us rows ordered by `(started_at DESC, id DESC)`.
fn bucket_by_month(entries: Vec<HistoryEntry>, now: DateTime<Utc>, tr: Tr) -> Vec<MonthBucket> {
    let mut months: Vec<(String, Vec<HistoryEntry>)> = Vec::new();
    for entry in entries {
        let label = tr.month_year(entry.started_at());
        match months.last_mut() {
            Some((month, in_month)) if *month == label => in_month.push(entry),
            _ => months.push((label, vec![entry])),
        }
    }
    months
        .into_iter()
        .map(|(label, in_month)| MonthBucket {
            label,
            rows: past::build_rows(&in_month, now, tr),
        })
        .collect()
}

/// Absolute `rel=canonical` for the page a fragment duplicates. `None` when no
/// origin is known, leaving the fragment its `noindex` alone.
fn canonical_link(
    state: &AppState,
    headers: &HeaderMap,
    page: StatusPageId,
) -> Option<header::HeaderValue> {
    let origin =
        published_page_origin(&state.request_state(), headers, page).unwrap_or_else(|| {
            state
                .cfg
                .auth
                .public_base_url
                .trim_end_matches('/')
                .to_owned()
        });
    if origin.is_empty() {
        return None;
    }
    let home = status_home(state, headers);
    let home = home.strip_suffix('/').unwrap_or(home);
    header::HeaderValue::from_str(&format!("<{origin}{home}>; rel=\"canonical\"")).ok()
}

/// A cursor is opaque but forgeable, and every forgery resolves to a valid
/// page, so only the entry point on the default tab is offered to the index.
/// The rest stay crawlable: the archive is the only path to older rows.
fn archive_robots(tab: HistoryTab, cursor: Option<&str>, branding: &BrandingView) -> &'static str {
    if cursor.is_some() || tab != HistoryTab::All {
        "noindex,follow"
    } else {
        branding.robots()
    }
}
