//! The sign-in trail of a private page, and the days each viewer came back.

use anyhow::Context;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::domain::{AccessEventKind, AccessEventMethod, OrgId, PageRef, StatusPageId, UserId};
use crate::error::Result;

/// One row of the trail. An attempt from an address the list does not cover
/// names no viewer and carries no address.
#[derive(Debug, Clone, Copy)]
pub struct NewEvent<'a> {
    pub page: PageRef,
    pub viewer: Option<Uuid>,
    pub kind: AccessEventKind,
    pub method: Option<AccessEventMethod>,
    pub failure_reason: Option<&'a str>,
    pub actor: Option<UserId>,
    pub ip_hash: Option<&'a str>,
    pub user_agent_hash: Option<&'a str>,
}

impl<'a> NewEvent<'a> {
    pub fn new(page: PageRef, kind: AccessEventKind) -> Self {
        Self {
            page,
            viewer: None,
            kind,
            method: None,
            failure_reason: None,
            actor: None,
            ip_hash: None,
            user_agent_hash: None,
        }
    }
}

pub async fn record<'c, E: PgExecutor<'c>>(executor: E, e: NewEvent<'_>) -> Result<()> {
    sqlx::query(
        "INSERT INTO status_page_access_events \
             (status_page_id, org_id, viewer_id, kind, method, failure_reason, actor_id, \
              ip_hash, user_agent_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(e.page.page.0)
    .bind(e.page.org.0)
    .bind(e.viewer)
    .bind(e.kind.as_db_str())
    .bind(e.method.map(AccessEventMethod::as_db_str))
    .bind(e.failure_reason)
    .bind(e.actor.map(|u| u.0))
    .bind(e.ip_hash)
    .bind(e.user_agent_hash)
    .execute(executor)
    .await
    .context("page_access::events::record")?;
    Ok(())
}

/// Best effort: a lost trail row must not fail the sign-in it describes.
pub async fn record_quietly<'c, E: PgExecutor<'c>>(executor: E, e: NewEvent<'_>) {
    if let Err(err) = record(executor, e).await {
        tracing::warn!(error = %err, kind = e.kind.as_db_str(), "page access event not recorded");
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EventRow {
    pub occurred_at: DateTime<Utc>,
    pub kind: String,
    pub method: Option<String>,
    pub failure_reason: Option<String>,
    /// The member who blocked or unblocked, when they still have an account.
    pub actor_email: Option<String>,
}

/// A viewer's trail and visit days, newest first, for the owner's history
/// drawer. Org- and page-scoped so a crafted id reads nothing of another page.
pub async fn history<'c, E>(
    executor: E,
    org: OrgId,
    page: StatusPageId,
    viewer: Uuid,
    limit: i64,
) -> Result<Vec<EventRow>>
where
    E: PgExecutor<'c>,
{
    sqlx::query_as(
        "SELECT e.occurred_at, e.kind, e.method, e.failure_reason, u.email::text AS actor_email \
         FROM status_page_access_events e \
         LEFT JOIN users u ON u.id = e.actor_id \
         WHERE e.org_id = $1 AND e.status_page_id = $2 AND e.viewer_id = $3 \
         ORDER BY e.occurred_at DESC LIMIT $4",
    )
    .bind(org.0)
    .bind(page.0)
    .bind(viewer)
    .bind(limit)
    .fetch_all(executor)
    .await
    .context("page_access::events::history")
    .map_err(Into::into)
}

pub async fn visit_days<'c, E>(
    executor: E,
    org: OrgId,
    page: StatusPageId,
    viewer: Uuid,
    since: NaiveDate,
) -> Result<Vec<NaiveDate>>
where
    E: PgExecutor<'c>,
{
    let rows: Vec<(NaiveDate,)> = sqlx::query_as(
        "SELECT day FROM status_page_viewer_days \
         WHERE org_id = $1 AND status_page_id = $2 AND viewer_id = $3 AND day >= $4 \
         ORDER BY day DESC",
    )
    .bind(org.0)
    .bind(page.0)
    .bind(viewer)
    .bind(since)
    .fetch_all(executor)
    .await
    .context("page_access::events::visit_days")?;
    Ok(rows.into_iter().map(|(d,)| d).collect())
}
