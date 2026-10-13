//! Viewer sessions on a private page's host. The cookie carries 32 random
//! bytes and the row only their SHA-256, as for the app's own sessions.

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::{PageRef, PageSessionMethod};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct CreatedSession {
    /// The raw cookie value; never stored.
    pub cookie: String,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn create(
    pool: &PgPool,
    page: PageRef,
    viewer: Uuid,
    session_days: Option<i32>,
    ip_hash: Option<&str>,
    user_agent_hash: Option<&str>,
) -> Result<CreatedSession> {
    let cookie = crate::security::token_hash::generate_raw_token();
    let expires_at = session_days.map(|d| Utc::now() + Duration::days(i64::from(d)));
    sqlx::query(
        "INSERT INTO status_page_sessions \
             (id_hash, status_page_id, org_id, method, viewer_id, expires_at, ip_hash, \
              user_agent_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(crate::security::sha256_hex(&cookie))
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(PageSessionMethod::Email.as_db_str())
    .bind(viewer)
    .bind(expires_at)
    .bind(ip_hash)
    .bind(user_agent_hash)
    .execute(pool)
    .await
    .context("page_sessions::create")?;
    Ok(CreatedSession { cookie, expires_at })
}

/// A live session and the viewer behind it. Whether the viewer may still
/// open the page is the gate's call: it holds the page's current list.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActiveSession {
    pub id_hash: String,
    pub created_at: DateTime<Utc>,
    pub viewer_id: Uuid,
    pub email: String,
    pub blocked: bool,
}

pub async fn lookup(pool: &PgPool, page: PageRef, cookie: &str) -> Result<Option<ActiveSession>> {
    sqlx::query_as(
        "SELECT s.id_hash, s.created_at, v.id AS viewer_id, v.email::text AS email, \
                v.blocked_at IS NOT NULL AS blocked \
         FROM status_page_sessions s \
         JOIN status_page_viewers v \
              ON v.id = s.viewer_id AND v.status_page_id = s.status_page_id \
         WHERE s.id_hash = $1 AND s.status_page_id = $2 AND s.org_id = $3 \
           AND (s.expires_at IS NULL OR s.expires_at > now())",
    )
    .bind(crate::security::sha256_hex(cookie))
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(pool)
    .await
    .context("page_sessions::lookup")
    .map_err(Into::into)
}

pub async fn touch(pool: &PgPool, page: PageRef, id_hash: &str) -> Result<()> {
    sqlx::query(
        "UPDATE status_page_sessions SET last_used_at = now() \
         WHERE id_hash = $1 AND status_page_id = $2 AND org_id = $3",
    )
    .bind(id_hash)
    .bind(page.page.0)
    .bind(page.org.0)
    .execute(pool)
    .await
    .context("page_sessions::touch")?;
    Ok(())
}

/// Sign-out. The viewer, if any, for the trail.
pub async fn delete(pool: &PgPool, page: PageRef, cookie: &str) -> Result<Option<Uuid>> {
    let row: Option<(Option<Uuid>,)> = sqlx::query_as(
        "DELETE FROM status_page_sessions \
         WHERE id_hash = $1 AND status_page_id = $2 AND org_id = $3 \
         RETURNING viewer_id",
    )
    .bind(crate::security::sha256_hex(cookie))
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(pool)
    .await
    .context("page_sessions::delete")?;
    Ok(row.and_then(|(v,)| v))
}
