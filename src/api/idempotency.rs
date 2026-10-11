use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header, header::HeaderName};
use axum::middleware::Next;
use axum::response::Response;
use moka::sync::Cache;

/// `POST /targets/bulk`, `POST /targets/bulk-action` and
/// `POST /targets/{id}/duplicate` accept an optional `Idempotency-Key` header.
/// The server replays the prior successful response for 24h, keyed by
/// `(caller credential, header value, method + path, body hash)`.
pub const TTL: Duration = Duration::from_secs(24 * 3600);
pub const HEADER_NAME: HeaderName = HeaderName::from_static("idempotency-key");

const MAX_BODY: usize = 8 * 1024 * 1024;
/// Total cached response bytes before LRU eviction (weighed by body size).
const MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
struct CachedResponse {
    status: u16,
    content_type: Option<HeaderValue>,
    body: Bytes,
}

/// Response cache keyed by `(caller credential, idempotency-key, route + body hash)`,
/// bounded by a 24h TTL and a total-bytes weigher.
pub struct IdempotencyCache {
    cache: Cache<String, CachedResponse>,
}

impl IdempotencyCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(TTL)
                .weigher(|_k, v: &CachedResponse| v.body.len().min(u32::MAX as usize) as u32)
                .max_capacity(MAX_CACHE_BYTES)
                .build(),
        }
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

/// axum middleware: if `Idempotency-Key` is set, replay the cached response
/// for the `(caller, key, body-hash)` tuple — or capture a successful
/// downstream response and cache it. Pass-through when the header is absent.
pub async fn middleware(
    State(cache): State<Arc<IdempotencyCache>>,
    req: Request,
    next: Next,
) -> Response {
    let key_header = req
        .headers()
        .get(&HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let Some(key_header) = key_header else {
        return next.run(req).await;
    };

    // Scope the key to the caller's credential — bearer token or session
    // cookie — so two tenants reusing the same Idempotency-Key never collide.
    let mut caller_hasher = DefaultHasher::new();
    for name in [header::AUTHORIZATION, header::COOKIE] {
        req.headers()
            .get(&name)
            .map(|v| v.as_bytes())
            .unwrap_or_default()
            .hash(&mut caller_hasher);
    }
    let caller_hash = caller_hasher.finish();

    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            // Body too large or read failure — delegate downstream so the
            // handler returns its usual 413 / 400 instead of swallowing it.
            return next.run(Request::from_parts(parts, Body::empty())).await;
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
    let content_type = resp_parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .cloned();

    cache.store(
        cache_key,
        CachedResponse {
            status: resp_parts.status.as_u16(),
            content_type,
            body: resp_bytes.clone(),
        },
    );

    Response::from_parts(resp_parts, Body::from(resp_bytes))
}

fn rebuild_response(cached: CachedResponse) -> Response {
    let mut resp = Response::new(Body::from(cached.body));
    *resp.status_mut() = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);
    if let Some(ct) = cached.content_type {
        resp.headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, ct);
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
                Arc::new(IdempotencyCache::new()),
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
}
