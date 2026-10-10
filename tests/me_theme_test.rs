//! Integration coverage for `/api/v1/me/theme`. Asserts the GET / PATCH pair
//! persists to `users.theme`, emits the `sm_app_theme` cookie, leaves the
//! marketing pick alone, and rejects unknown variants at deserialise time. An
//! app page load without the cookie gets it from the account, never the pick.
//!
//! Run via:
//!     docker compose -f compose.dev.yml up -d postgres
//!     DATABASE_URL=postgres://monitor:monitor@localhost:5432/monitor \
//!         cargo +1.95 nextest run --test it --run-ignored all -E 'test(/^me_theme_test::/)'

use crate::common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{
    body_json, build_test_app_with_pg, drop_test_db, fresh_test_db, json_request, open_test_pool,
    with_session,
};
use tower::ServiceExt;
use uptimepage::domain::UserId;
use uuid::Uuid;

use crate::common::MIGRATOR;

async fn fresh_pg() -> Option<(String, String)> {
    fresh_test_db("me_theme").await
}

async fn seed_user(pool: &sqlx::PgPool, email: &str) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO users (email, display_name, terms_version, privacy_version) \
         VALUES ($1, 'u', 'v1', 'v1') RETURNING id",
    )
    .bind(email)
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn me_theme_get_patch_round_trip() {
    let Some((db, name)) = fresh_pg().await else {
        return;
    };
    let pool = open_test_pool(&db).await;
    MIGRATOR.run(&pool).await.unwrap();

    let user = seed_user(&pool, "themer@example.test").await;
    let (router, _) = build_test_app_with_pg(pool.clone(), |_| {}).await;
    let router = with_session(router, UserId(user), None, None);

    let resp = router
        .clone()
        .oneshot(
            Request::get("/api/v1/me/theme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["theme"], "system");

    let resp = router
        .clone()
        .oneshot({
            let mut req = json_request(
                "PATCH",
                "/api/v1/me/theme",
                serde_json::json!({"theme": "terminal"}),
            );
            req.headers_mut()
                .insert("x-requested-with", "uptimepage".parse().unwrap());
            req
        })
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        set_cookies
            .iter()
            .any(|c| c.starts_with("sm_app_theme=terminal")),
        "Set-Cookie sm_app_theme=terminal missing from {set_cookies:?}"
    );
    let body = body_json(resp).await;
    assert_eq!(body["theme"], "terminal");

    let (stored,): (String,) = sqlx::query_as("SELECT theme FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, "terminal");

    pool.close().await;
    drop_test_db(&name).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn a_theme_chosen_in_the_app_leaves_the_website_pick() {
    let Some((db, name)) = fresh_pg().await else {
        return;
    };
    let pool = open_test_pool(&db).await;
    MIGRATOR.run(&pool).await.unwrap();

    let user = seed_user(&pool, "themer-pick@example.test").await;
    let (router, _) = build_test_app_with_pg(pool.clone(), |_| {}).await;
    let router = with_session(router, UserId(user), None, None);

    let resp = router
        .oneshot({
            let mut req = json_request(
                "PATCH",
                "/api/v1/me/theme",
                serde_json::json!({"theme": "nord"}),
            );
            req.headers_mut()
                .insert("x-requested-with", "uptimepage".parse().unwrap());
            req.headers_mut()
                .insert("cookie", "sm_theme_pick=dark".parse().unwrap());
            req
        })
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .all(|c| !c.starts_with("sm_theme_pick=")),
        "the pick is the website's"
    );

    let (stored,): (String,) = sqlx::query_as("SELECT theme FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, "nord");

    pool.close().await;
    drop_test_db(&name).await;
}

fn app_page(cookie: Option<&str>) -> Request<Body> {
    let mut req = Request::get("/").header("accept", "text/html");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    req.body(Body::empty()).unwrap()
}

fn theme_mirror(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("sm_app_theme="))
        .map(str::to_owned)
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn an_app_page_without_the_theme_mirror_issues_it_from_the_account() {
    let Some((db, name)) = fresh_pg().await else {
        return;
    };
    let pool = open_test_pool(&db).await;
    MIGRATOR.run(&pool).await.unwrap();

    let user = seed_user(&pool, "themer-mirror@example.test").await;
    sqlx::query("UPDATE users SET theme = 'terminal' WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let (router, _) = build_test_app_with_pg(pool.clone(), |_| {}).await;
    let router = with_session(router, UserId(user), None, None);

    let resp = router
        .clone()
        .oneshot(app_page(Some("sm_theme_pick=dark")))
        .await
        .unwrap();
    let mirror = theme_mirror(&resp).expect("mirror issued");
    assert!(mirror.starts_with("sm_app_theme=terminal;"), "{mirror}");
    let (stored,): (String,) = sqlx::query_as("SELECT theme FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        stored, "terminal",
        "the website pick never reaches an account"
    );

    let resp = router
        .oneshot(app_page(Some("sm_app_theme=terminal")))
        .await
        .unwrap();
    assert_eq!(theme_mirror(&resp), None);

    pool.close().await;
    drop_test_db(&name).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn me_theme_patch_rejects_unknown_variant() {
    let Some((db, name)) = fresh_pg().await else {
        return;
    };
    let pool = open_test_pool(&db).await;
    MIGRATOR.run(&pool).await.unwrap();

    let user = seed_user(&pool, "themer-bad@example.test").await;
    let (router, _) = build_test_app_with_pg(pool.clone(), |_| {}).await;
    let router = with_session(router, UserId(user), None, None);

    let resp = router
        .oneshot({
            let mut req = json_request(
                "PATCH",
                "/api/v1/me/theme",
                serde_json::json!({"theme": "garbage"}),
            );
            req.headers_mut()
                .insert("x-requested-with", "uptimepage".parse().unwrap());
            req
        })
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let (stored,): (String,) = sqlx::query_as("SELECT theme FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, "system", "DB must be untouched on bad input");

    pool.close().await;
    drop_test_db(&name).await;
}
