//! The people who signed in to a private page.

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::{AccessEventKind, OrgId, PageRef, StatusPageId, UserId, normalize_email};
use crate::error::Result;
use crate::storage::orgs::record_audit_tx;

use super::events::{self, NewEvent};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Viewer {
    pub id: Uuid,
    pub email: String,
    pub email_verified_at: DateTime<Utc>,
    pub blocked_at: Option<DateTime<Utc>>,
}

const VIEWER_COLUMNS: &str = "id, email::text AS email, email_verified_at, blocked_at";

/// After an address proved itself by email: creates the viewer or stamps the
/// proof, and claims the subscription that address already held. `None` for
/// a blocked viewer, whom no proof lets back in.
pub async fn record_verified(pool: &PgPool, page: PageRef, email: &str) -> Result<Option<Viewer>> {
    let mut tx = pool
        .begin()
        .await
        .context("viewers::record_verified begin")?;
    let viewer: Option<Viewer> = sqlx::query_as(&format!(
        "INSERT INTO status_page_viewers (status_page_id, org_id, email, email_verified_at) \
         VALUES ($1, $2, $3, now()) \
         ON CONFLICT (status_page_id, email) DO UPDATE SET email_verified_at = now() \
         WHERE status_page_viewers.blocked_at IS NULL \
         RETURNING {VIEWER_COLUMNS}"
    ))
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(email)
    .fetch_optional(&mut *tx)
    .await
    .context("viewers::record_verified upsert")?;
    if let Some(v) = &viewer {
        let ids = subscriptions_of(&mut tx, page.org, page.page, email).await?;
        sqlx::query(
            "UPDATE status_page_subscribers SET viewer_id = $3, updated_at = now() \
             WHERE status_page_id = $1 AND org_id = $2 AND id = ANY($4) AND viewer_id IS NULL",
        )
        .bind(page.page.0)
        .bind(page.org.0)
        .bind(v.id)
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .context("viewers::record_verified claim subscription")?;
    }
    tx.commit()
        .await
        .context("viewers::record_verified commit")?;
    Ok(viewer)
}

/// The page's email subscriptions held by `email`, compared in the spelling
/// viewers are stored in: a subscription from before the page went private
/// keeps the address as typed, an international domain included.
async fn subscriptions_of(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org: OrgId,
    page: StatusPageId,
    email: &str,
) -> Result<Vec<Uuid>> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, target FROM status_page_subscribers \
         WHERE status_page_id = $1 AND org_id = $2 AND channel = 'email'",
    )
    .bind(page.0)
    .bind(org.0)
    .fetch_all(&mut **tx)
    .await
    .context("viewers::subscriptions_of")?;
    Ok(rows
        .into_iter()
        .filter(|(_, target)| normalize_email(target).as_deref() == Some(email))
        .map(|(id, _)| id)
        .collect())
}

pub async fn get(pool: &PgPool, page: PageRef, id: Uuid) -> Result<Option<Viewer>> {
    sqlx::query_as(&format!(
        "SELECT {VIEWER_COLUMNS} FROM status_page_viewers \
         WHERE id = $1 AND status_page_id = $2 AND org_id = $3"
    ))
    .bind(id)
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(pool)
    .await
    .context("viewers::get")
    .map_err(Into::into)
}

pub async fn find_by_email(pool: &PgPool, page: PageRef, email: &str) -> Result<Option<Viewer>> {
    sqlx::query_as(&format!(
        "SELECT {VIEWER_COLUMNS} FROM status_page_viewers \
         WHERE status_page_id = $1 AND org_id = $2 AND email = $3"
    ))
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(email)
    .fetch_optional(pool)
    .await
    .context("viewers::find_by_email")
    .map_err(Into::into)
}

/// The visit stamps, behind the caller's debounce: `last_seen_at`, and the
/// day row that says who still reads the page when sessions never end.
pub async fn touch(pool: &PgPool, page: PageRef, viewer: Uuid) -> Result<()> {
    sqlx::query(
        "WITH seen AS ( \
             UPDATE status_page_viewers SET last_seen_at = now() \
             WHERE id = $1 AND status_page_id = $2 AND org_id = $3 \
             RETURNING id \
         ) \
         INSERT INTO status_page_viewer_days (viewer_id, day, status_page_id, org_id) \
         SELECT id, (now() AT TIME ZONE 'UTC')::date, $2, $3 FROM seen \
         ON CONFLICT (viewer_id, day) DO NOTHING",
    )
    .bind(viewer)
    .bind(page.page.0)
    .bind(page.org.0)
    .execute(pool)
    .await
    .context("viewers::touch")?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ViewerListing {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub blocked_at: Option<DateTime<Utc>>,
    pub passkeys: i64,
    pub subscribed: bool,
}

/// Every viewer of one page, active first, then by last visit.
pub async fn list_for_page(
    pool: &PgPool,
    org: OrgId,
    page: StatusPageId,
) -> Result<Vec<ViewerListing>> {
    sqlx::query_as(
        "SELECT v.id, v.email::text AS email, v.created_at, v.last_seen_at, v.blocked_at, \
                (SELECT count(*) FROM status_page_viewer_passkeys p \
                  WHERE p.viewer_id = v.id AND p.status_page_id = v.status_page_id) AS passkeys, \
                EXISTS (SELECT 1 FROM status_page_subscribers s \
                         WHERE s.viewer_id = v.id AND s.status_page_id = v.status_page_id \
                           AND s.verified_at IS NOT NULL) AS subscribed \
         FROM status_page_viewers v \
         WHERE v.org_id = $1 AND v.status_page_id = $2 \
         ORDER BY v.blocked_at IS NOT NULL, v.last_seen_at DESC NULLS LAST, v.email",
    )
    .bind(org.0)
    .bind(page.0)
    .fetch_all(pool)
    .await
    .context("viewers::list_for_page")
    .map_err(Into::into)
}

/// Counts for the editor's access card and the pages list.
#[derive(Debug, Clone, Copy, Default, sqlx::FromRow)]
pub struct ViewerCounts {
    pub active: i64,
    pub blocked: i64,
}

pub async fn counts_for_page(
    pool: &PgPool,
    org: OrgId,
    page: StatusPageId,
) -> Result<ViewerCounts> {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE blocked_at IS NULL) AS active, \
                count(*) FILTER (WHERE blocked_at IS NOT NULL) AS blocked \
         FROM status_page_viewers WHERE org_id = $1 AND status_page_id = $2",
    )
    .bind(org.0)
    .bind(page.0)
    .fetch_one(pool)
    .await
    .context("viewers::counts_for_page")
    .map_err(Into::into)
}

pub async fn counts_for_org(
    pool: &PgPool,
    org: OrgId,
) -> Result<std::collections::HashMap<StatusPageId, ViewerCounts>> {
    let rows: Vec<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT status_page_id, \
                count(*) FILTER (WHERE blocked_at IS NULL), \
                count(*) FILTER (WHERE blocked_at IS NOT NULL) \
         FROM status_page_viewers WHERE org_id = $1 GROUP BY status_page_id",
    )
    .bind(org.0)
    .fetch_all(pool)
    .await
    .context("viewers::counts_for_org")?;
    Ok(rows
        .into_iter()
        .map(|(page, active, blocked)| (StatusPageId(page), ViewerCounts { active, blocked }))
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOutcome {
    Changed,
    Unchanged,
    NotFound,
}

/// Blocking ends everything the viewer holds on the page at once: passkeys,
/// sessions, the subscription (claimed or still under their address), and any
/// ceremony in flight. The row stays, which is what keeps a domain rule from
/// letting them straight back in.
pub async fn block(
    pool: &PgPool,
    org: OrgId,
    page: StatusPageId,
    viewer: Uuid,
    actor: UserId,
) -> Result<BlockOutcome> {
    let mut tx = pool.begin().await.context("viewers::block begin")?;
    let blocked: Option<(String,)> = sqlx::query_as(
        "UPDATE status_page_viewers SET blocked_at = now(), blocked_by = $4 \
         WHERE id = $1 AND status_page_id = $2 AND org_id = $3 AND blocked_at IS NULL \
         RETURNING email::text",
    )
    .bind(viewer)
    .bind(page.0)
    .bind(org.0)
    .bind(actor.0)
    .fetch_optional(&mut *tx)
    .await
    .context("viewers::block")?;
    let Some((email,)) = blocked else {
        tx.rollback().await.ok();
        return exists_outcome(pool, org, page, viewer).await;
    };
    for sql in [
        "DELETE FROM status_page_viewer_passkeys \
         WHERE viewer_id = $1 AND status_page_id = $2 AND org_id = $3",
        "DELETE FROM status_page_sessions \
         WHERE viewer_id = $1 AND status_page_id = $2 AND org_id = $3",
        "DELETE FROM status_page_webauthn_states \
         WHERE viewer_id = $1 AND status_page_id = $2 AND org_id = $3",
    ] {
        sqlx::query(sql)
            .bind(viewer)
            .bind(page.0)
            .bind(org.0)
            .execute(&mut *tx)
            .await
            .context("viewers::block cleanup")?;
    }
    let ids = subscriptions_of(&mut tx, org, page, &email).await?;
    sqlx::query(
        "DELETE FROM status_page_subscribers \
         WHERE status_page_id = $2 AND org_id = $3 AND (viewer_id = $1 OR id = ANY($4))",
    )
    .bind(viewer)
    .bind(page.0)
    .bind(org.0)
    .bind(&ids)
    .execute(&mut *tx)
    .await
    .context("viewers::block subscription")?;
    let page_ref = crate::domain::PageRef { page, org };
    events::record(
        &mut *tx,
        NewEvent {
            viewer: Some(viewer),
            actor: Some(actor),
            ..NewEvent::new(page_ref, AccessEventKind::Blocked)
        },
    )
    .await?;
    record_audit_tx(
        &mut tx,
        org,
        Some(actor),
        "status_page.viewer_blocked",
        json!({ "status_page_id": page.0, "viewer_id": viewer, "email": email }),
    )
    .await?;
    tx.commit().await.context("viewers::block commit")?;
    Ok(BlockOutcome::Changed)
}

/// Lifts the block only. What blocking removed stays removed: the viewer
/// signs in again by email and saves a new passkey.
pub async fn unblock(
    pool: &PgPool,
    org: OrgId,
    page: StatusPageId,
    viewer: Uuid,
    actor: UserId,
) -> Result<BlockOutcome> {
    let mut tx = pool.begin().await.context("viewers::unblock begin")?;
    let lifted: Option<(String,)> = sqlx::query_as(
        "UPDATE status_page_viewers SET blocked_at = NULL, blocked_by = NULL \
         WHERE id = $1 AND status_page_id = $2 AND org_id = $3 AND blocked_at IS NOT NULL \
         RETURNING email::text",
    )
    .bind(viewer)
    .bind(page.0)
    .bind(org.0)
    .fetch_optional(&mut *tx)
    .await
    .context("viewers::unblock")?;
    let Some((email,)) = lifted else {
        tx.rollback().await.ok();
        return exists_outcome(pool, org, page, viewer).await;
    };
    events::record(
        &mut *tx,
        NewEvent {
            viewer: Some(viewer),
            actor: Some(actor),
            ..NewEvent::new(PageRef { page, org }, AccessEventKind::Unblocked)
        },
    )
    .await?;
    record_audit_tx(
        &mut tx,
        org,
        Some(actor),
        "status_page.viewer_unblocked",
        json!({ "status_page_id": page.0, "viewer_id": viewer, "email": email }),
    )
    .await?;
    tx.commit().await.context("viewers::unblock commit")?;
    Ok(BlockOutcome::Changed)
}

async fn exists_outcome(
    pool: &PgPool,
    org: OrgId,
    page: StatusPageId,
    viewer: Uuid,
) -> Result<BlockOutcome> {
    let (exists,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM status_page_viewers \
                        WHERE id = $1 AND status_page_id = $2 AND org_id = $3)",
    )
    .bind(viewer)
    .bind(page.0)
    .bind(org.0)
    .fetch_one(pool)
    .await
    .context("viewers::exists")?;
    Ok(if exists {
        BlockOutcome::Unchanged
    } else {
        BlockOutcome::NotFound
    })
}
