//! Sessions on a private page's host: a viewer's after an email sign-in, or an
//! anonymous one after the page password. The cookie carries 32 random bytes
//! and the row only their SHA-256, as for the app's own sessions.

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::domain::{OrgId, PageRef, PageSessionMethod, StatusPageId};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct CreatedSession {
    /// The raw cookie value; never stored.
    pub cookie: String,
    pub expires_at: Option<DateTime<Utc>>,
    /// The length it was opened for, which the cookie's own lifetime follows.
    pub session_days: Option<i32>,
}

/// How a session came to be and whom it names: an email session names its
/// viewer, a password session nobody.
#[derive(Debug, Clone, Copy)]
pub enum Opener {
    Email(Uuid),
    Password,
}

impl Opener {
    fn method(self) -> PageSessionMethod {
        match self {
            Self::Email(_) => PageSessionMethod::Email,
            Self::Password => PageSessionMethod::Password,
        }
    }

    fn viewer(self) -> Option<Uuid> {
        match self {
            Self::Email(viewer) => Some(viewer),
            Self::Password => None,
        }
    }
}

pub async fn create<'c, E: PgExecutor<'c>>(
    executor: E,
    page: PageRef,
    opener: Opener,
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
    .bind(opener.method().as_db_str())
    .bind(opener.viewer())
    .bind(expires_at)
    .bind(ip_hash)
    .bind(user_agent_hash)
    .execute(executor)
    .await
    .context("page_sessions::create")?;
    Ok(CreatedSession {
        cookie,
        expires_at,
        session_days,
    })
}

/// A live session, and the viewer behind it when it has one. Whether it may
/// still open the page is the gate's call: it holds the page's settings.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub id_hash: String,
    pub created_at: DateTime<Utc>,
    pub method: PageSessionMethod,
    /// `None` for a password session.
    pub viewer: Option<SessionViewer>,
}

#[derive(Debug, Clone)]
pub struct SessionViewer {
    pub id: Uuid,
    pub email: String,
    pub blocked: bool,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id_hash: String,
    created_at: DateTime<Utc>,
    method: String,
    viewer_id: Option<Uuid>,
    email: Option<String>,
    blocked: Option<bool>,
}

pub async fn lookup(pool: &PgPool, page: PageRef, cookie: &str) -> Result<Option<ActiveSession>> {
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.id_hash, s.created_at, s.method, v.id AS viewer_id, v.email::text AS email, \
                v.blocked_at IS NOT NULL AS blocked \
         FROM status_page_sessions s \
         LEFT JOIN status_page_viewers v \
              ON v.id = s.viewer_id AND v.status_page_id = s.status_page_id \
         WHERE s.id_hash = $1 AND s.status_page_id = $2 AND s.org_id = $3 \
           AND (s.expires_at IS NULL OR s.expires_at > now())",
    )
    .bind(crate::security::sha256_hex(cookie))
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(pool)
    .await
    .context("page_sessions::lookup")?;
    Ok(row.and_then(|r| {
        let viewer = match (r.viewer_id, r.email) {
            (Some(id), Some(email)) => Some(SessionViewer {
                id,
                email,
                blocked: r.blocked.unwrap_or(true),
            }),
            _ => None,
        };
        Some(ActiveSession {
            id_hash: r.id_hash,
            created_at: r.created_at,
            method: PageSessionMethod::from_db_str(&r.method)?,
            viewer,
        })
    }))
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
pub async fn delete<'c, E: PgExecutor<'c>>(
    executor: E,
    page: PageRef,
    cookie: &str,
) -> Result<Option<Uuid>> {
    let row: Option<(Option<Uuid>,)> = sqlx::query_as(
        "DELETE FROM status_page_sessions \
         WHERE id_hash = $1 AND status_page_id = $2 AND org_id = $3 \
         RETURNING viewer_id",
    )
    .bind(crate::security::sha256_hex(cookie))
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(executor)
    .await
    .context("page_sessions::delete")?;
    Ok(row.and_then(|(v,)| v))
}

/// Every session one way in opened on the page; how many there were.
pub async fn end_by_method<'c, E: PgExecutor<'c>>(
    executor: E,
    org: OrgId,
    page: StatusPageId,
    method: PageSessionMethod,
) -> Result<u64> {
    let res = sqlx::query(
        "DELETE FROM status_page_sessions \
         WHERE status_page_id = $1 AND org_id = $2 AND method = $3",
    )
    .bind(page.0)
    .bind(org.0)
    .bind(method.as_db_str())
    .execute(executor)
    .await
    .context("page_sessions::end_by_method")?;
    Ok(res.rows_affected())
}
