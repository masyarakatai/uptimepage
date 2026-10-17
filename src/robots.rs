//! Crawl directives for responses that have no `<head>` to carry a robots meta
//! tag: feeds, badges, JSON, and the polled HTML partials. [`mark_private`]
//! goes on every private response, full pages included: no meta tag sets
//! `Cache-Control`.

use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderName, HeaderValue};
use axum::response::Response;

pub const X_ROBOTS_TAG: HeaderName = HeaderName::from_static("x-robots-tag");

pub const NOINDEX: HeaderValue = HeaderValue::from_static("noindex");

/// Out of the index, but crawlable through to the page that should rank.
pub const NOINDEX_FOLLOW: HeaderValue = HeaderValue::from_static("noindex,follow");

/// Matches what `share/base.html` puts in its own head.
pub const NOINDEX_NOFOLLOW: HeaderValue = HeaderValue::from_static("noindex, nofollow");

/// A private response is the visitor's alone: no shared cache keeps it, and
/// no search engine indexes it.
pub fn mark_private(resp: &mut Response) {
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    resp.headers_mut().insert(X_ROBOTS_TAG, NOINDEX);
}
