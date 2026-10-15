use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header, header::HeaderName};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use moka::sync::Cache;
use parking_lot::Mutex;

use crate::error::{AppError, codes};

/// `POST /targets/bulk`, `POST /targets/bulk-action`,
/// `POST /targets/{id}/duplicate` and the incident and maintenance update
/// routes accept an optional `Idempotency-Key` header. The server replays the
/// prior successful response for 24h, keyed by
/// `(caller credential, header value, method + path, body hash)`, and refuses
/// a second request with that key while the first is still running.
pub const TTL: Duration = Duration::from_secs(24 * 3600);
pub const HEADER_NAME: HeaderName = HeaderName::from_static("idempotency-key");

/// Longer keys are refused: the key is held in the cache and the in-flight set.
pub const MAX_KEY_LEN: usize = 255;
/// Total cached bytes before LRU eviction (weighed by key and body size).
const MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
struct CachedResponse {
    status: u16,
    content_type: Option<HeaderValue>,
    /// Where a created resource lives, which a client may read off a replay.
    location: Option<HeaderValue>,
    body: Bytes,
}

/// Response cache keyed by `(caller credential, idempotency-key, route + body hash)`,
/// bounded by a 24h TTL and a total-bytes weigher, plus the keys whose first
/// request is still running.
pub struct IdempotencyCache {
    cache: Cache<String, CachedResponse>,
    in_flight: Mutex<HashSet<String>>,
}

impl IdempotencyCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(TTL)
                .weigher(|k: &String, v: &CachedResponse| {
                    (k.len() + v.body.len()).min(u32::MAX as usize) as u32
                })
                .max_capacity(MAX_CACHE_BYTES)
                .build(),
            in_flight: Mutex::new(HashSet::new()),
        }
    }

    /// Claims `key` for one running request; `None` while another holds it.
    fn claim(self: &Arc<Self>, key: &str) -> Option<InFlight> {
        self.in_flight
            .lock()
            .insert(key.to_owned())
            .then(|| InFlight {
                cache: Arc::clone(self),
                key: key.to_owned(),
            })
    }

    fn lookup(&self, key: &str) -> Option<CachedResponse> {
        self.cache.get(key)
    }

    fn store(&self, key: String, value: CachedResponse) {
        self.cache.insert(key, value);
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Releases its key when the request ends, however it ends.
struct InFlight {
    cache: Arc<IdempotencyCache>,
    key: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.cache.in_flight.lock().remove(&self.key);
    }
}

/// What one mounted layer needs: the shared store, the body limit of the
/// routes it guards, and the name of the session cookie that is a caller's
/// credential in a browser.
#[derive(Clone)]
pub struct Idempotency {
    cache: Arc<IdempotencyCache>,
    max_body: usize,
    session_cookie: Arc<str>,
}

impl Idempotency {
    pub fn new(cache: Arc<IdempotencyCache>, max_body: usize, session_cookie: &str) -> Self {
        Self {
            cache,
            max_body,
            session_cookie: session_cookie.into(),
        }
    }
}

/// The caller's credential: the bearer token, or the session cookie alone,
/// so another cookie changing between a request and its retry does not make
/// the retry a stranger.
fn caller_hash(req: &Request, session_cookie: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    req.headers()
        .get(header::AUTHORIZATION)
        .map(|v| v.as_bytes())
        .unwrap_or_default()
        .hash(&mut hasher);
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(name, _)| *name == session_cookie)
        .map(|(_, value)| value)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

/// axum middleware: if `Idempotency-Key` is set, replay the cached response
/// for the `(caller, key, body-hash)` tuple — or capture a successful
/// downstream response and cache it. Pass-through when the header is absent.
/// Mount it inside the token middleware and the rate limiter, so a replay is
/// counted like the request it answers and a revoked token gets none. A
/// session is checked by the handler, which a replay skips: it returns only
/// what that session was already sent.
pub async fn middleware(State(idem): State<Idempotency>, req: Request, next: Next) -> Response {
    let key_header = req
        .headers()
        .get(&HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let Some(key_header) = key_header else {
        return next.run(req).await;
    };
    if key_header.is_empty() || key_header.len() > MAX_KEY_LEN {
        return AppError::bad_request_field(
            codes::INVALID_IDEMPOTENCY_KEY,
            format!("Idempotency-Key must be 1 to {MAX_KEY_LEN} characters"),
            "Idempotency-Key",
        )
        .into_response();
    }
    let cache = &idem.cache;

    // Scope the key to the caller's credential, so two tenants reusing the
    // same Idempotency-Key never collide.
    let caller_hash = caller_hash(&req, &idem.session_cookie);

    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, idem.max_body).await {
        Ok(b) => b,
        Err(_) => {
            return AppError::payload_too_large(
                codes::INVALID_JSON,
                format!("request body exceeds {} bytes", idem.max_body),
            )
            .into_response();
        }
    };

    // The route is part of the request: one body sent to two monitors'
    // `/duplicate` is two requests, not a retry.
    let mut hasher = DefaultHasher::new();
    parts.method.as_str().hash(&mut hasher);
    parts.uri.path().hash(&mut hasher);
    body_bytes.hash(&mut hasher);
    let cache_key = format!("{caller_hash:016x}:{key_header}:{:016x}", hasher.finish());

    if let Some(cached) = cache.lookup(&cache_key) {
        return rebuild_response(cached);
    }
    // Two requests with one key at once would both miss the cache and both
    // run; the second is told to retry, which then replays the first.
    let Some(_claim) = cache.claim(&cache_key) else {
        return AppError::conflict(
            codes::IDEMPOTENCY_IN_PROGRESS,
            "a request with this Idempotency-Key is still running; retry it once that one answers",
        )
        .into_response();
    };
    if let Some(cached) = cache.lookup(&cache_key) {
        return rebuild_response(cached);
    }

    let req = Request::from_parts(parts, Body::from(body_bytes));
    let resp = next.run(req).await;
    // An error changed nothing, so there is nothing to protect from a retry,
    // and replaying a 429 or a 5xx would refuse the retry the key exists for.
    if !resp.status().is_success() {
        return resp;
    }

    // The handler built this body in memory, so it is read whole: a size cap
    // here would turn a committed success into an error the client retries.
    let (resp_parts, resp_body) = resp.into_parts();
    let resp_bytes = match axum::body::to_bytes(resp_body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response body unreadable",
            )
                .into_response_local();
        }
    };
    cache.store(
        cache_key,
        CachedResponse {
            status: resp_parts.status.as_u16(),
            content_type: resp_parts.headers.get(header::CONTENT_TYPE).cloned(),
            location: resp_parts.headers.get(header::LOCATION).cloned(),
            body: resp_bytes.clone(),
        },
    );

    Response::from_parts(resp_parts, Body::from(resp_bytes))
}

fn rebuild_response(cached: CachedResponse) -> Response {
    let mut resp = Response::new(Body::from(cached.body));
    *resp.status_mut() = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);
    if let Some(ct) = cached.content_type {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    if let Some(location) = cached.location {
        resp.headers_mut().insert(header::LOCATION, location);
    }
    resp
}

// Local helper trait to keep error path concise without importing axum's response prelude.
trait IntoResponseLocal {
    fn into_response_local(self) -> Response;
}

impl IntoResponseLocal for (StatusCode, &'static str) {
    fn into_response_local(self) -> Response {
        let mut resp = Response::new(Body::from(self.1));
        *resp.status_mut() = self.0;
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::middleware::from_fn_with_state;
    use axum::routing::post;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    /// A route that answers its nth call with `statuses[n]`, behind the cache.
    fn app(statuses: &'static [StatusCode]) -> (Router, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let router = Router::new()
            .route(
                "/bulk",
                post(move || {
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    async move { statuses.get(n).copied().unwrap_or(StatusCode::IM_A_TEAPOT) }
                }),
            )
            .layer(from_fn_with_state(
                Idempotency::new(Arc::new(IdempotencyCache::new()), 1024, "_sm_session"),
                middleware,
            ));
        (router, calls)
    }

    async fn send(app: &Router) -> StatusCode {
        let req = Request::post("/bulk")
            .header(&HEADER_NAME, "retry-1")
            .body(Body::from("{}"))
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_retry_after_an_error_runs_again_and_only_a_success_replays() {
        let (app, calls) = app(&[
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::CREATED,
        ]);
        assert_eq!(send(&app).await, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(send(&app).await, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(send(&app).await, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(send(&app).await, StatusCode::CREATED);
        assert_eq!(send(&app).await, StatusCode::CREATED);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    /// A route that creates something at `/made/{n}` on its nth call, behind
    /// the cache with a 1 KiB body limit.
    fn creating_app() -> (Router, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let router = Router::new()
            .route(
                "/bulk",
                post(move || {
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    async move {
                        (
                            StatusCode::CREATED,
                            [(header::LOCATION, format!("/made/{n}"))],
                        )
                    }
                }),
            )
            .layer(from_fn_with_state(
                Idempotency::new(Arc::new(IdempotencyCache::new()), 1024, "_sm_session"),
                middleware,
            ));
        (router, calls)
    }

    fn keyed(key: &str, cookie: &str, body: String) -> Request {
        Request::post("/bulk")
            .header(&HEADER_NAME, key)
            .header(header::COOKIE, cookie)
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn a_replay_keeps_its_location_and_survives_other_cookies_changing() {
        let (app, calls) = creating_app();
        let first = app
            .clone()
            .oneshot(keyed(
                "k",
                "_sm_session=abc; sm_app_theme=dark",
                "{}".into(),
            ))
            .await
            .unwrap();
        assert_eq!(first.headers()[header::LOCATION], "/made/0");
        let retry = app
            .clone()
            .oneshot(keyed(
                "k",
                "sm_app_theme=light; _sm_session=abc",
                "{}".into(),
            ))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::CREATED);
        assert_eq!(retry.headers()[header::LOCATION], "/made/0", "replayed");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        app.clone()
            .oneshot(keyed("k", "_sm_session=other", "{}".into()))
            .await
            .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "another session is another caller"
        );
    }

    #[tokio::test]
    async fn an_overlong_key_and_an_oversized_body_are_refused() {
        let (app, calls) = creating_app();
        let long = "k".repeat(MAX_KEY_LEN + 1);
        let resp = app
            .clone()
            .oneshot(keyed(&long, "", "{}".into()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = app
            .clone()
            .oneshot(keyed("k", "", "x".repeat(2048)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "neither reached the handler"
        );
    }

    #[tokio::test]
    async fn a_second_request_while_the_first_runs_is_refused_then_replays() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let (e, r, c) = (entered.clone(), release.clone(), calls.clone());
        let app = Router::new()
            .route(
                "/bulk",
                post(move || {
                    let (e, r, c) = (e.clone(), r.clone(), c.clone());
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        e.notify_one();
                        r.notified().await;
                        StatusCode::CREATED
                    }
                }),
            )
            .layer(from_fn_with_state(
                Idempotency::new(Arc::new(IdempotencyCache::new()), 1024, "_sm_session"),
                middleware,
            ));

        let first = tokio::spawn({
            let app = app.clone();
            async move { send(&app).await }
        });
        entered.notified().await;
        let resp = app
            .clone()
            .oneshot(
                Request::post("/bulk")
                    .header(&HEADER_NAME, "retry-1")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("IDEMPOTENCY_IN_PROGRESS"),
            "{body:?}"
        );

        release.notify_one();
        assert_eq!(first.await.unwrap(), StatusCode::CREATED);
        assert_eq!(send(&app).await, StatusCode::CREATED, "replayed");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the handler ran once");
    }
}
