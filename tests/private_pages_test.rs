//! Private status pages through the SaaS router on live Postgres: one gate in
//! front of every surface of the page, an emailed code or link as the way in,
//! the same answer for every address, passkeys as a shortcut the owner can
//! switch off, and the ways access ends (block, a removed rule, the plan).
//!
//! Live-PG ignored: needs `DATABASE_URL`.

use crate::common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use chrono::Utc;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uptimepage::domain::{
    AccessRule, ComponentHistoryResponse, OverallState, OverallStatus, PageAccess,
    PageAccessSettings, PageRef, PublicIncident, PublicMaintenanceList, PublicStatusPage,
    StatusPageId, UserId,
};
use uptimepage::email::{EmailTemplate, InMemoryEmailSender};
use uptimepage::error::public::PublicAppError;
use uptimepage::pagination::page::CursorPage;
use uptimepage::public_status::access::PageGate;
use uptimepage::public_status::source::FeedLinks;
use uptimepage::public_status::{IncidentListQuery, PublicSource};
use uptimepage::storage::page_access::{settings, viewers};
use uuid::Uuid;
use webauthn_authenticator_rs::prelude::{
    CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse, Url,
    WebauthnAuthenticator,
};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

use common::{SAAS_BASE_DOMAIN, build_saas_router_with_pg_tweaked, pg_pool_from_env, unique_slug};

const FEED_SECRET: &str = "private-pages-test-feed-secret";

/// Every gated surface answers this page; what it says does not matter here.
struct AnyPage;

#[async_trait]
impl PublicSource for AnyPage {
    async fn page(&self, _page: PageRef) -> Result<Arc<PublicStatusPage>, PublicAppError> {
        Ok(Arc::new(PublicStatusPage {
            overall: OverallStatus {
                state: OverallState::Operational,
                label: "All Systems Operational".into(),
            },
            generated_at: Utc::now(),
            site_name: "Autohaus Weber".into(),
            groups: Vec::new(),
            active_incidents: Vec::new(),
            recent_incidents: Vec::new(),
            recent_incidents_has_more: false,
            active_maintenance: Vec::new(),
            upcoming_maintenance: Vec::new(),
        }))
    }
    async fn component_history(
        &self,
        _page: PageRef,
        id: Uuid,
        _days: u32,
    ) -> Result<ComponentHistoryResponse, PublicAppError> {
        Ok(ComponentHistoryResponse {
            component_id: id,
            component_name: "Workshop booking".into(),
            days: 90,
            history: Vec::new(),
        })
    }
    async fn list_incidents(
        &self,
        _page: PageRef,
        _q: IncidentListQuery,
    ) -> Result<CursorPage<PublicIncident>, PublicAppError> {
        Ok(CursorPage {
            items: Vec::new(),
            next_cursor: None,
        })
    }
    async fn incident_by_id(
        &self,
        _page: PageRef,
        _id: Uuid,
    ) -> Result<PublicIncident, PublicAppError> {
        Err(PublicAppError::NotFound)
    }
    async fn maintenance(&self, _page: PageRef) -> Result<PublicMaintenanceList, PublicAppError> {
        Ok(PublicMaintenanceList {
            active: Vec::new(),
            upcoming: Vec::new(),
        })
    }
    async fn incidents_rss(
        &self,
        _page: PageRef,
        _links: FeedLinks<'_>,
    ) -> Result<String, PublicAppError> {
        Ok("<rss version=\"2.0\"><channel/></rss>".into())
    }
}

struct Rig {
    app: Router,
    pool: PgPool,
    mail: Arc<InMemoryEmailSender>,
    gate: Arc<PageGate>,
    page: PageRef,
    owner: UserId,
    host: String,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| {
                let (pair, _) = v.split_once(';').unwrap_or((v, ""));
                let (k, val) = pair.split_once('=')?;
                (k == name).then(|| val.to_owned())
            })
    }

    fn location(&self) -> &str {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    }

    fn is_private(&self) -> bool {
        self.headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            == Some("private, no-store")
            && self
                .headers
                .get("x-robots-tag")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("noindex"))
    }
}

async fn rig() -> Option<Rig> {
    let pool = pg_pool_from_env().await?;
    let owner = common::make_user(&pool, "private-pages").await;
    let slug = unique_slug("priv");
    let org = uptimepage::storage::create_org_with_owner(&pool, owner, &slug, "Autohaus Weber")
        .await
        .unwrap()
        .unwrap();
    let (page,): (Uuid,) = sqlx::query_as(
        "INSERT INTO status_pages (org_id, slug, name, enabled) \
         VALUES ($1, $2, 'Autohaus Weber', true) RETURNING id",
    )
    .bind(org.id.0)
    .bind(&slug)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mail = Arc::new(InMemoryEmailSender::new());
    let sender = mail.clone();
    let gate_slot: Arc<Mutex<Option<Arc<PageGate>>>> = Arc::default();
    let slot = gate_slot.clone();
    let app = build_saas_router_with_pg_tweaked(
        pool.clone(),
        |cfg| cfg.auth.public_base_url = "https://app.example.test".into(),
        move |mut state| {
            state.email_sender = sender;
            state.public_source = Arc::new(AnyPage);
            *slot.lock().unwrap() = Some(state.page_gate.clone());
            state.with_page_feed_secret(FEED_SECRET.into())
        },
    )
    .await;
    let gate = gate_slot.lock().unwrap().clone().unwrap();
    let rig = Rig {
        app,
        pool,
        mail,
        gate,
        page: PageRef {
            page: StatusPageId(page),
            org: org.id,
        },
        owner,
        host: format!("{slug}.{SAAS_BASE_DOMAIN}"),
    };
    rig.set_access(
        true,
        &["dealer.example", "k.lindner@example.org"],
        true,
        None,
    )
    .await;
    Some(rig)
}

fn rules(entries: &[&str]) -> Vec<AccessRule> {
    entries
        .iter()
        .map(|e| AccessRule::parse(e).unwrap())
        .collect()
}

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

impl Rig {
    async fn set_access(
        &self,
        protected: bool,
        entries: &[&str],
        passkeys: bool,
        recheck_days: Option<i32>,
    ) {
        let mut tx = self.pool.begin().await.unwrap();
        settings::replace_in_tx(
            &mut tx,
            self.page.org,
            self.page.page,
            &PageAccess {
                settings: PageAccessSettings {
                    protected,
                    passkeys_enabled: passkeys,
                    recheck_days,
                    ..Default::default()
                },
                rules: rules(entries),
            },
            Some(self.owner),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        self.gate.invalidate(self.page.page).await;
    }

    async fn send(&self, req: axum::http::request::Builder, body: Body) -> Reply {
        let resp = self
            .app
            .clone()
            .oneshot(req.header(header::HOST, &self.host).body(body).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
            .await
            .unwrap();
        Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
        let mut req = Request::get(path);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.send(req, Body::empty()).await
    }

    async fn post_form(&self, path: &str, cookie: Option<&str>, pairs: &[(&str, &str)]) -> Reply {
        let mut req =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.send(req, Body::from(form(pairs))).await
    }

    async fn post_json(&self, path: &str, cookie: Option<&str>, body: Value) -> Reply {
        let mut req = Request::post(path).header(header::CONTENT_TYPE, "application/json");
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.send(req, Body::from(body.to_string())).await
    }

    /// The code mailed to `email`, waiting out the spawned send.
    async fn mailed(&self, email: &str) -> Option<(String, String)> {
        self.mailed_after(email, 0).await
    }

    /// The same, among the mails sent after the first `skip`.
    async fn mailed_after(&self, email: &str, skip: usize) -> Option<(String, String)> {
        for _ in 0..40 {
            let found = self.mail.sent().into_iter().skip(skip).rev().find_map(|m| {
                match (m.to.address == email, m.template) {
                    (true, EmailTemplate::PageAccessCode { code, url, .. }) => Some((code, url)),
                    _ => None,
                }
            });
            if found.is_some() {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    async fn request_code(&self, email: &str) -> (Reply, String) {
        let reply = self
            .post_form("/access/request", None, &[("email", email), ("next", "/")])
            .await;
        let nonce = reply.cookie("_up_page_code").unwrap_or_default();
        (reply, nonce)
    }

    /// Signs `email` in by its code; the page session cookie header value.
    async fn sign_in(&self, email: &str) -> String {
        let before = self.mail.sent().len();
        let (reply, nonce) = self.request_code(email).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let (code, _) = self.mailed_after(email, before).await.expect("code mailed");
        let done = self
            .post_form(
                "/access/code",
                Some(&format!("_up_page_code={nonce}")),
                &[("code", &code), ("next", "/")],
            )
            .await;
        assert_eq!(done.status, StatusCode::SEE_OTHER, "{email} {code}");
        format!(
            "_up_page={}",
            done.cookie("_up_page").expect("session cookie")
        )
    }

    async fn viewer_id(&self, email: &str) -> Uuid {
        viewers::find_by_email(&self.pool, self.page, email)
            .await
            .unwrap()
            .expect("viewer")
            .id
    }

    async fn cleanup(self) {
        let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(self.page.org.0)
            .execute(&self.pool)
            .await;
    }
}

fn address(local: &str, domain: &str) -> String {
    format!("{local}.{}@{domain}", unique_slug("v")).to_lowercase()
}

/// Every surface that shows the page, and the ones left open on purpose. One
/// table, so a route that forgets the gate fails here.
const GATED: &[&str] = &[
    "/",
    "/?fragment=1",
    "/status/incidents",
    "/api/public/v1/status",
    "/api/public/v1/components/00000000-0000-0000-0000-000000000001/history",
    "/api/public/v1/incidents",
    "/api/public/v1/incidents.rss",
    "/api/public/v1/maintenance",
    "/api/public/v1/badge.svg",
];

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn every_surface_of_a_private_page_needs_a_session() {
    let Some(rig) = rig().await else { return };
    let incident = "/status/incidents/00000000-0000-0000-0000-000000000002";
    let incident_api = "/api/public/v1/incidents/00000000-0000-0000-0000-000000000002";

    for path in GATED.iter().chain([&incident, &incident_api]) {
        let reply = rig.get(path, None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
        assert!(reply.is_private(), "{path}: {:?}", reply.headers);
    }
    let screen = rig.get("/", None).await;
    assert!(screen.body.contains(r#"action="/access/request""#));
    assert!(!screen.body.contains("og:description"));

    let cookie = rig.sign_in(&address("anna", "dealer.example")).await;
    for path in GATED {
        let reply = rig.get(path, Some(&cookie)).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}: {}", reply.body);
        assert!(reply.is_private(), "{path}: {:?}", reply.headers);
    }
    // The fake source has no incidents, so these are a 404 past the gate.
    for path in [incident, incident_api] {
        assert_eq!(
            rig.get(path, Some(&cookie)).await.status,
            StatusCode::NOT_FOUND
        );
    }
    let page = rig.get("/", Some(&cookie)).await;
    assert!(page.body.contains("/access/sign-out"));
    assert!(page.body.contains(r#"content="noindex"#));

    // The sign-in screen shows the logo to anyone, so the logo stays open.
    sqlx::query(
        "INSERT INTO page_assets (org_id, status_page_id, slot, content_type, content_hash, \
                                  byte_size, data) \
         VALUES ($1, $2, 'logo', 'image/png', 'h', 4, '\\x89504e47')",
    )
    .bind(rig.page.org.0)
    .bind(rig.page.page.0)
    .execute(&rig.pool)
    .await
    .unwrap();
    assert_eq!(
        rig.get("/status/branding/logo", None).await.status,
        StatusCode::OK
    );

    // Back to public: the same surfaces answer anyone, cacheably.
    rig.set_access(false, &["dealer.example"], true, None).await;
    let open = rig.get("/api/public/v1/status", None).await;
    assert_eq!(open.status, StatusCode::OK);
    assert!(!open.is_private());
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn every_address_gets_the_same_answer_and_only_a_listed_one_gets_mail() {
    let Some(rig) = rig().await else { return };
    let listed = address("anna", "dealer.example");
    let exact = "k.lindner@example.org".to_owned();
    let unlisted = address("mallory", "evil.test");
    let blocked = address("bob", "dealer.example");
    rig.sign_in(&blocked).await;
    let blocked_id = rig.viewer_id(&blocked).await;
    viewers::block(
        &rig.pool,
        rig.page.org,
        rig.page.page,
        blocked_id,
        rig.owner,
    )
    .await
    .unwrap();
    let before = rig.mail.sent().len();

    for email in [&listed, &exact, &unlisted, &blocked] {
        let (reply, nonce) = rig.request_code(email).await;
        assert_eq!(reply.status, StatusCode::OK, "{email}");
        assert!(reply.body.contains(r#"action="/access/code""#), "{email}");
        assert!(!nonce.is_empty(), "{email}");
    }
    assert!(rig.mailed(&listed).await.is_some());
    assert!(rig.mailed(&exact).await.is_some());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mailed: Vec<String> = rig.mail.sent()[before..]
        .iter()
        .map(|m| m.to.address.clone())
        .collect();
    assert_eq!(mailed.len(), 2, "{mailed:?}");
    assert!(!mailed.contains(&unlisted));
    assert!(!mailed.contains(&blocked));

    // An unlisted attempt is on the trail, with no address and no viewer.
    let (unnamed,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM status_page_access_events \
         WHERE status_page_id = $1 AND kind = 'code_failed' AND failure_reason = 'not_listed' \
           AND viewer_id IS NULL",
    )
    .bind(rig.page.page.0)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(unnamed, 1);
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_code_works_once_and_only_in_the_browser_that_asked() {
    let Some(rig) = rig().await else { return };
    let email = address("anna", "dealer.example");
    let (_, nonce) = rig.request_code(&email).await;
    let (code, _) = rig.mailed(&email).await.unwrap();

    let elsewhere = rig
        .post_form(
            "/access/code",
            Some("_up_page_code=other"),
            &[("code", &code)],
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::UNAUTHORIZED);
    assert!(elsewhere.cookie("_up_page").is_none());

    let wrong = if code == "AAAAAA" { "BBBBBB" } else { "AAAAAA" };
    let missed = rig
        .post_form(
            "/access/code",
            Some(&format!("_up_page_code={nonce}")),
            &[("code", wrong)],
        )
        .await;
    assert_eq!(missed.status, StatusCode::UNAUTHORIZED);
    let late = rig
        .post_form(
            "/access/code",
            Some(&format!("_up_page_code={nonce}")),
            &[("code", &code)],
        )
        .await;
    assert_eq!(
        late.status,
        StatusCode::UNAUTHORIZED,
        "one attempt per code"
    );
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn the_mailed_link_asks_before_it_signs_in() {
    let Some(rig) = rig().await else { return };
    let email = address("anna", "dealer.example");
    rig.request_code(&email).await;
    let (_, url) = rig.mailed(&email).await.unwrap();
    let path = url.split_once(SAAS_BASE_DOMAIN).unwrap().1.to_owned();
    assert!(path.starts_with("/access/verify?token="), "{url}");

    // A scanner's GET twice leaves the link working.
    rig.get(&path, None).await;
    let landing = rig.get(&path, None).await;
    assert_eq!(landing.status, StatusCode::OK);
    assert!(landing.body.contains(&email));
    let csrf = landing.cookie("_up_page_confirm").unwrap();
    let token = path.split_once("token=").unwrap().1;

    let forged = rig
        .post_form("/access/verify", None, &[("token", token), ("csrf", &csrf)])
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let done = rig
        .post_form(
            "/access/verify",
            Some(&format!("_up_page_confirm={csrf}")),
            &[("token", token), ("csrf", &csrf)],
        )
        .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    // No passkey on this host yet, so the way back passes the offer.
    assert_eq!(done.location(), "/access/passkey?next=%2F");
    let cookie = format!("_up_page={}", done.cookie("_up_page").unwrap());
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&cookie)).await.status,
        StatusCode::OK
    );
    let offer = rig.get(done.location(), Some(&cookie)).await;
    assert_eq!(offer.status, StatusCode::OK);
    assert!(offer.body.contains("page-passkey-save"));
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn block_rule_removal_and_sign_out_end_access_on_the_next_request() {
    let Some(rig) = rig().await else { return };
    let anna = address("anna", "dealer.example");
    let bob = address("bob", "dealer.example");
    let lindner = "k.lindner@example.org";
    let (a, b, l) = (
        rig.sign_in(&anna).await,
        rig.sign_in(&bob).await,
        rig.sign_in(lindner).await,
    );
    for c in [&a, &b, &l] {
        assert_eq!(
            rig.get("/api/public/v1/status", Some(c)).await.status,
            StatusCode::OK
        );
    }

    let bob_id = rig.viewer_id(&bob).await;
    viewers::block(&rig.pool, rig.page.org, rig.page.page, bob_id, rig.owner)
        .await
        .unwrap();
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&b)).await.status,
        StatusCode::UNAUTHORIZED
    );

    rig.set_access(true, &["dealer.example"], true, None).await;
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&l)).await.status,
        StatusCode::UNAUTHORIZED,
        "the address rule is gone"
    );
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&a)).await.status,
        StatusCode::OK
    );

    let out = rig.post_form("/access/sign-out", Some(&a), &[]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&a)).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Unblocking lifts the block only: Bob signs in again by email.
    viewers::unblock(&rig.pool, rig.page.org, rig.page.page, bob_id, rig.owner)
        .await
        .unwrap();
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&b)).await.status,
        StatusCode::UNAUTHORIZED
    );
    // Past the one-mail-a-minute window for his address.
    sqlx::query(
        "UPDATE status_page_access_codes SET sent_at = sent_at - interval '2 minutes' \
         WHERE status_page_id = $1 AND email = $2",
    )
    .bind(rig.page.page.0)
    .bind(&bob)
    .execute(&rig.pool)
    .await
    .unwrap();
    let again = rig.sign_in(&bob).await;
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&again)).await.status,
        StatusCode::OK
    );
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_cross_origin_post_is_refused() {
    let Some(rig) = rig().await else { return };
    let cookie = rig.sign_in(&address("anna", "dealer.example")).await;
    let forged = rig
        .send(
            Request::post("/access/sign-out")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "https://evil.example.test"),
            Body::empty(),
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&cookie)).await.status,
        StatusCode::OK
    );
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn going_private_keeps_only_the_subscriptions_the_list_covers() {
    let Some(rig) = rig().await else { return };
    rig.set_access(false, &["dealer.example"], true, None).await;
    for (channel, target) in [
        ("email", "stays@dealer.example"),
        ("email", "goes@elsewhere.test"),
        ("webhook", "https://hooks.example.test/x"),
    ] {
        sqlx::query(
            "INSERT INTO status_page_subscribers \
                 (status_page_id, org_id, channel, target, verified_at) \
             VALUES ($1, $2, $3, $4, now())",
        )
        .bind(rig.page.page.0)
        .bind(rig.page.org.0)
        .bind(channel)
        .bind(target)
        .execute(&rig.pool)
        .await
        .unwrap();
    }
    rig.set_access(true, &["dealer.example"], true, None).await;
    let left: Vec<(String,)> =
        sqlx::query_as("SELECT target FROM status_page_subscribers WHERE status_page_id = $1")
            .bind(rig.page.page.0)
            .fetch_all(&rig.pool)
            .await
            .unwrap();
    assert_eq!(left, vec![("stays@dealer.example".to_owned(),)]);

    // Signing in claims it; subscribing as oneself needs no confirmation mail.
    let cookie = rig.sign_in("stays@dealer.example").await;
    let (claimed,): (bool,) = sqlx::query_as(
        "SELECT viewer_id IS NOT NULL FROM status_page_subscribers WHERE status_page_id = $1",
    )
    .bind(rig.page.page.0)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert!(claimed);
    let anna = address("anna", "dealer.example");
    let anna_cookie = rig.sign_in(&anna).await;
    let subscribed = rig
        .post_form(
            "/subscribe",
            Some(&anna_cookie),
            &[("channel", "webhook"), ("url", "https://x.test")],
        )
        .await;
    assert_eq!(subscribed.status, StatusCode::OK, "{}", subscribed.body);
    let (verified, viewer): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT verified_at IS NOT NULL, viewer_id FROM status_page_subscribers \
         WHERE status_page_id = $1 AND target = $2",
    )
    .bind(rig.page.page.0)
    .bind(&anna)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert!(verified);
    assert_eq!(viewer, Some(rig.viewer_id(&anna).await));
    let _ = cookie;

    // Nobody signed in subscribes to a private page.
    let anon = rig
        .post_form("/subscribe", None, &[("email", "x@dealer.example")])
        .await;
    assert_eq!(anon.status, StatusCode::SEE_OTHER);
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_personal_feed_link_reads_the_feed_without_a_cookie() {
    let Some(rig) = rig().await else { return };
    let anna = address("anna", "dealer.example");
    let cookie = rig.sign_in(&anna).await;
    let page = rig.get("/", Some(&cookie)).await;
    let start = page
        .body
        .find("/api/public/v1/incidents.rss?viewer=")
        .unwrap();
    let link = &page.body[start..];
    let link = link[..link.find('"').unwrap()]
        .replace("&#38;", "&")
        .replace("&amp;", "&");
    let read = rig.get(&link, None).await;
    assert_eq!(read.status, StatusCode::OK, "{link} {}", read.body);

    let forged = link.replace("&t=", "&t=0");
    assert_eq!(
        rig.get(&forged, None).await.status,
        StatusCode::UNAUTHORIZED
    );

    let id = rig.viewer_id(&anna).await;
    viewers::block(&rig.pool, rig.page.org, rig.page.page, id, rig.owner)
        .await
        .unwrap();
    assert_eq!(rig.get(&link, None).await.status, StatusCode::UNAUTHORIZED);
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_plan_without_private_pages_holds_the_page_rather_than_opening_it() {
    let Some(rig) = rig().await else { return };
    let mut plan = uptimepage::domain::Plan::clone(
        &*uptimepage::quotas::QuotaService::new(
            &common::test_config(|_| {}),
            Some(rig.pool.clone()),
        )
        .limit_for_org(rig.page.org)
        .await
        .unwrap(),
    );
    plan.private_pages_enabled = false;
    let account = uptimepage::storage::accounts::account_for_org(&rig.pool, rig.page.org)
        .await
        .unwrap();
    let plan = Arc::new(plan);
    uptimepage::quotas::holds::reconcile_account(
        &rig.pool,
        account,
        uptimepage::quotas::holds::PlanSource::Fixed(plan.clone()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(rig.get("/", None).await.status, StatusCode::NOT_FOUND);

    // Made public by its owner, the page comes back within the same plan.
    rig.set_access(false, &["dealer.example"], true, None).await;
    uptimepage::quotas::holds::reconcile_account(
        &rig.pool,
        account,
        uptimepage::quotas::holds::PlanSource::Fixed(plan),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        rig.get("/api/public/v1/status", None).await.status,
        StatusCode::OK
    );
    rig.cleanup().await;
}

// ---------------------------------------------------------------------------
// Passkeys
// ---------------------------------------------------------------------------

impl Rig {
    fn origin(&self) -> Url {
        Url::parse(&format!("https://{}", self.host)).unwrap()
    }

    async fn register_passkey(&self, cookie: &str, authenticator: &mut SoftPasskey) -> String {
        let started = self
            .post_json("/access/passkey/register/start", Some(cookie), json!({}))
            .await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let body: Value = serde_json::from_str(&started.body).unwrap();
        let mut options: CreationChallengeResponse =
            serde_json::from_value(body["options"].clone()).unwrap();
        if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
            selection.require_resident_key = false;
        }
        let credential: RegisterPublicKeyCredential = authenticator
            .do_registration(self.origin(), options)
            .unwrap();
        let done = self
            .post_json(
                "/access/passkey/register/finish",
                Some(cookie),
                json!({ "handle": body["handle"], "credential": credential }),
            )
            .await;
        assert_eq!(done.status, StatusCode::NO_CONTENT, "{}", done.body);
        credential.id
    }

    async fn passkey_sign_in(
        &self,
        authenticator: &mut SoftPasskey,
        credential_id: &str,
        viewer: Uuid,
    ) -> Reply {
        let started = self
            .post_json("/access/passkey/login/start", None, json!({}))
            .await;
        if started.status != StatusCode::OK {
            return started;
        }
        let body: Value = serde_json::from_str(&started.body).unwrap();
        let mut options = body["options"].clone();
        options["publicKey"]["allowCredentials"] =
            json!([{ "type": "public-key", "id": credential_id }]);
        let options: RequestChallengeResponse = serde_json::from_value(options).unwrap();
        let mut assertion = authenticator
            .do_authentication(self.origin(), options)
            .unwrap();
        assertion.response.user_handle = Some(viewer.as_bytes().to_vec());
        self.post_json(
            "/access/passkey/login/finish",
            None,
            json!({ "handle": body["handle"], "credential": assertion, "next": "/" }),
        )
        .await
    }
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_saved_passkey_signs_in_until_the_owner_wants_the_email_again() {
    let Some(rig) = rig().await else { return };
    let anna = address("anna", "dealer.example");
    let cookie = rig.sign_in(&anna).await;
    let viewer = rig.viewer_id(&anna).await;
    let mut key = SoftPasskey::new(true);
    let id = rig.register_passkey(&cookie, &mut key).await;

    let ok = rig.passkey_sign_in(&mut key, &id, viewer).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    let session = format!("_up_page={}", ok.cookie("_up_page").unwrap());
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&session))
            .await
            .status,
        StatusCode::OK
    );

    // The re-check applies at the next passkey sign-in, never to a session.
    sqlx::query(
        "UPDATE status_page_viewers SET email_verified_at = now() - interval '40 days' \
         WHERE id = $1",
    )
    .bind(viewer)
    .execute(&rig.pool)
    .await
    .unwrap();
    rig.set_access(true, &["dealer.example"], true, Some(30))
        .await;
    let due = rig.passkey_sign_in(&mut key, &id, viewer).await;
    assert_eq!(due.status, StatusCode::FORBIDDEN);
    assert!(due.body.contains("PAGE_EMAIL_RECHECK"));
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&session))
            .await
            .status,
        StatusCode::OK
    );

    // Passkeys off: both ceremonies refused, the saved one kept for later.
    rig.set_access(true, &["dealer.example"], false, None).await;
    assert_eq!(
        rig.post_json("/access/passkey/login/start", None, json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        rig.post_json("/access/passkey/register/start", Some(&session), json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    rig.set_access(true, &["dealer.example"], true, None).await;
    let back = rig.passkey_sign_in(&mut key, &id, viewer).await;
    assert_eq!(back.status, StatusCode::OK, "{}", back.body);
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_passkey_from_another_page_names_nobody_here() {
    let Some(rig) = rig().await else { return };
    let Some(other) = self::rig().await else {
        return;
    };
    let anna = address("anna", "dealer.example");
    let cookie = other.sign_in(&anna).await;
    let viewer = other.viewer_id(&anna).await;
    let mut key = SoftPasskey::new(true);
    let id = other.register_passkey(&cookie, &mut key).await;

    // The same authenticator, asked on this page's host for the other page's
    // credential: the host differs, so the browser would refuse; forge it.
    let started = rig
        .post_json("/access/passkey/login/start", None, json!({}))
        .await;
    let body: Value = serde_json::from_str(&started.body).unwrap();
    let mut options = body["options"].clone();
    options["publicKey"]["allowCredentials"] = json!([{ "type": "public-key", "id": id }]);
    options["publicKey"]["rpId"] = json!(other.host);
    let options: RequestChallengeResponse = serde_json::from_value(options).unwrap();
    let mut assertion = key.do_authentication(other.origin(), options).unwrap();
    assertion.response.user_handle = Some(viewer.as_bytes().to_vec());
    let refused = rig
        .post_json(
            "/access/passkey/login/finish",
            None,
            json!({ "handle": body["handle"], "credential": assertion }),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert!(refused.cookie("_up_page").is_none());
    other.cleanup().await;
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn made_up_addresses_cannot_spend_the_mail_a_known_viewer_needs() {
    let Some(rig) = rig().await else { return };
    let anna = address("anna", "dealer.example");
    rig.sign_in(&anna).await;
    // A day's page budget already spent on addresses nobody signed in with.
    sqlx::query(
        "INSERT INTO status_page_access_codes \
             (status_page_id, org_id, email, token_hash, code_hash, nonce_hash, expires_at, sent_at) \
         SELECT $1, $2, 'x' || g || '@dealer.example', md5(random()::text || g), 'c', 'n', \
                now() + interval '15 minutes', now() \
         FROM generate_series(1, 500) g",
    )
    .bind(rig.page.page.0)
    .bind(rig.page.org.0)
    .execute(&rig.pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE status_page_access_codes SET sent_at = sent_at - interval '2 minutes' \
         WHERE status_page_id = $1 AND email = $2",
    )
    .bind(rig.page.page.0)
    .bind(&anna)
    .execute(&rig.pool)
    .await
    .unwrap();

    let before = rig.mail.sent().len();
    let newcomer = address("newcomer", "dealer.example");
    rig.request_code(&newcomer).await;
    rig.request_code(&anna).await;
    assert!(
        rig.mailed_after(&anna, before).await.is_some(),
        "a known viewer still gets mail"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rig.mail.sent()[before..]
            .iter()
            .all(|m| m.to.address != newcomer),
        "a new address waits for the budget"
    );
    let (rows,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM status_page_access_codes WHERE status_page_id = $1 AND email = $2",
    )
    .bind(rig.page.page.0)
    .bind(&newcomer)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(rows, 0, "a refused request writes no row");
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_shorter_session_length_ends_older_sessions_too() {
    let Some(rig) = rig().await else { return };
    let cookie = rig.sign_in(&address("anna", "dealer.example")).await;
    sqlx::query(
        "UPDATE status_page_sessions SET created_at = now() - interval '8 days' \
         WHERE status_page_id = $1",
    )
    .bind(rig.page.page.0)
    .execute(&rig.pool)
    .await
    .unwrap();
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&cookie)).await.status,
        StatusCode::OK
    );

    let mut tx = rig.pool.begin().await.unwrap();
    settings::replace_in_tx(
        &mut tx,
        rig.page.org,
        rig.page.page,
        &PageAccess {
            settings: PageAccessSettings {
                protected: true,
                session_days: Some(7),
                ..Default::default()
            },
            rules: rules(&["dealer.example"]),
        },
        Some(rig.owner),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    rig.gate.invalidate(rig.page.page).await;
    assert_eq!(
        rig.get("/api/public/v1/status", Some(&cookie)).await.status,
        StatusCode::UNAUTHORIZED
    );
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_subscription_typed_with_an_international_domain_follows_its_viewer() {
    let Some(rig) = rig().await else { return };
    rig.set_access(false, &["bücher.de"], true, None).await;
    sqlx::query(
        "INSERT INTO status_page_subscribers (status_page_id, org_id, channel, target, verified_at) \
         VALUES ($1, $2, 'email', 'anna@bücher.de', now())",
    )
    .bind(rig.page.page.0)
    .bind(rig.page.org.0)
    .execute(&rig.pool)
    .await
    .unwrap();
    rig.set_access(true, &["bücher.de"], true, None).await;
    let viewer = viewers::record_verified(&rig.pool, rig.page, "anna@xn--bcher-kva.de")
        .await
        .unwrap()
        .unwrap();
    let (claimed,): (Option<Uuid>,) =
        sqlx::query_as("SELECT viewer_id FROM status_page_subscribers WHERE status_page_id = $1")
            .bind(rig.page.page.0)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(claimed, Some(viewer.id));

    // Subscribing as oneself reuses that row rather than adding a second one.
    uptimepage::storage::subscribers::subscribe_viewer(
        &rig.pool,
        rig.page,
        viewer.id,
        "anna@xn--bcher-kva.de",
    )
    .await
    .unwrap();
    let (rows,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM status_page_subscribers WHERE status_page_id = $1")
            .bind(rig.page.page.0)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(rows, 1);

    viewers::block(&rig.pool, rig.page.org, rig.page.page, viewer.id, rig.owner)
        .await
        .unwrap();
    let (left,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM status_page_subscribers WHERE status_page_id = $1")
            .bind(rig.page.page.0)
            .fetch_one(&rig.pool)
            .await
            .unwrap();
    assert_eq!(left, 0);
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn the_code_from_an_earlier_mail_still_works_after_a_resend() {
    let Some(rig) = rig().await else { return };
    let email = address("anna", "dealer.example");
    let (_, nonce) = rig.request_code(&email).await;
    let (first, _) = rig.mailed(&email).await.unwrap();
    // Past the one-mail-a-minute window, then ask again from the same tab.
    sqlx::query(
        "UPDATE status_page_access_codes SET sent_at = sent_at - interval '2 minutes' \
         WHERE status_page_id = $1 AND email = $2",
    )
    .bind(rig.page.page.0)
    .bind(&email)
    .execute(&rig.pool)
    .await
    .unwrap();
    let before = rig.mail.sent().len();
    let again = rig
        .post_form(
            "/access/request",
            Some(&format!("_up_page_code={nonce}")),
            &[("email", email.as_str())],
        )
        .await;
    assert_eq!(again.status, StatusCode::OK);
    let (second, _) = rig.mailed_after(&email, before).await.unwrap();
    assert_ne!(first, second);

    let done = rig
        .post_form(
            "/access/code",
            Some(&format!("_up_page_code={nonce}")),
            &[("code", &first)],
        )
        .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    // The newer one went with it: one sign-in per request.
    let late = rig
        .post_form(
            "/access/code",
            Some(&format!("_up_page_code={nonce}")),
            &[("code", &second)],
        )
        .await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
    rig.cleanup().await;
}

#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_private_page_the_plan_no_longer_sells_takes_no_seat_from_public_ones() {
    let Some(rig) = rig().await else { return };
    // Two more pages in the org, both public; the private one is the pick.
    for name in ["public-a", "public-b"] {
        sqlx::query(
            "INSERT INTO status_pages (org_id, slug, name, enabled) VALUES ($1, $2, $3, true)",
        )
        .bind(rig.page.org.0)
        .bind(unique_slug(name))
        .bind(name)
        .execute(&rig.pool)
        .await
        .unwrap();
    }
    sqlx::query("UPDATE status_pages SET plan_keep = true WHERE id = $1")
        .bind(rig.page.page.0)
        .execute(&rig.pool)
        .await
        .unwrap();
    let mut plan = uptimepage::domain::Plan::clone(
        &*uptimepage::quotas::QuotaService::new(
            &common::test_config(|_| {}),
            Some(rig.pool.clone()),
        )
        .limit_for_org(rig.page.org)
        .await
        .unwrap(),
    );
    plan.private_pages_enabled = false;
    plan.max_status_pages = 2;
    let account = uptimepage::storage::accounts::account_for_org(&rig.pool, rig.page.org)
        .await
        .unwrap();
    uptimepage::quotas::holds::reconcile_account(
        &rig.pool,
        account,
        uptimepage::quotas::holds::PlanSource::Fixed(Arc::new(plan)),
        None,
    )
    .await
    .unwrap();
    let held: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM status_pages WHERE org_id = $1 AND plan_hold_at IS NOT NULL",
    )
    .bind(rig.page.org.0)
    .fetch_all(&rig.pool)
    .await
    .unwrap();
    assert_eq!(held, vec![("Autohaus Weber".to_owned(),)]);
    rig.cleanup().await;
}
