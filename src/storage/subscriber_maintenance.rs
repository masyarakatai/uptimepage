//! Maintenance-window fan-out to confirmed subscribers. Mirrors the incident
//! delivery log. The automatic notices dedup on `(subscriber, window, phase)`:
//! a `scheduled` announcement when the window is known and a `completed`
//! notice when it ends. An update a person posts dedups on
//! `(subscriber, update)`, like an incident update.

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::Locale;
use crate::error::Result;
use crate::storage::admin::not_held_sql;
use crate::storage::status_pages::{
    PAGE_CUSTOM_DOMAIN_PUBLISHED, PAGE_PLAN_JOIN, PAGE_PUBLIC_NAME, PAGE_SERVED,
};
use crate::storage::subscribers::{
    CLAIM_ORPHAN_MINUTES, FANOUT_LOOKBACK_HOURS, FANOUT_MAX_ATTEMPTS,
};

/// Whether window `mw` shows on subscriber `s`'s page: through one of the
/// page's components that is not held and is in the window, or was in it
/// before the window dropped it, or because the page kept the window after
/// its monitor left the page. A dropped or kept monitor makes the window
/// history, so the page hears only what was said once it ended (`said_at`
/// on or after its end).
fn shown_on_page_sql(said_at: &str) -> String {
    format!(
        "(EXISTS (
             SELECT 1 FROM status_page_components c
             JOIN maintenance_window_components mwc
               ON mwc.target_id = c.target_id AND mwc.org_id = c.org_id
             WHERE c.status_page_id = s.status_page_id AND c.org_id = s.org_id
               AND mwc.maintenance_id = mw.id
               AND {not_held})
         OR EXISTS (
             SELECT 1 FROM maintenance_status_pages kept
             WHERE kept.maintenance_id = mw.id AND kept.org_id = mw.org_id
               AND kept.status_page_id = s.status_page_id
               AND mw.ends_at <= now() AND {said_at} >= mw.ends_at)
         OR EXISTS (
             SELECT 1 FROM status_page_components c
             JOIN maintenance_window_departures d
               ON d.target_id = c.target_id AND d.org_id = c.org_id
             WHERE c.status_page_id = s.status_page_id AND c.org_id = s.org_id
               AND d.maintenance_id = mw.id
               AND {not_held}
               AND mw.ends_at <= now() AND {said_at} >= mw.ends_at))",
        not_held = not_held_sql("c.target_id"),
    )
}

#[derive(Debug, sqlx::FromRow)]
pub struct PendingMaintenance {
    pub subscriber_id: Uuid,
    pub maintenance_id: Uuid,
    pub org_id: Uuid,
    pub channel: String,
    pub target: String,
    pub phase: String,
    pub title: String,
    pub description: Option<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub page_name: String,
    public_locale: String,
    pub slug: String,
    pub custom_domain: Option<String>,
    pub custom_domain_published: bool,
    pub signing_secret: Option<String>,
}

impl PendingMaintenance {
    pub fn locale(&self) -> Locale {
        Locale::from_db(&self.public_locale)
    }
}

/// Verified subscribers with a maintenance window their page shows whose
/// `scheduled`/`completed` phase hasn't been sent. `event_at`
/// — the window's creation for `scheduled`, its end for `completed` — gates the
/// lookback and the subscribed-since check so neither phase resurrects history.
/// The candidate subquery keeps only windows ending inside the lookback or still
/// ahead, so a tick never joins the whole history; `event_at` then picks the phase.
pub async fn list_pending(pool: &PgPool, limit: i64) -> Result<Vec<PendingMaintenance>> {
    let sql = format!(
        "SELECT subscriber_id, maintenance_id, org_id, channel, target, phase, title,
                description, starts_at, ends_at, page_name, public_locale, slug, custom_domain,
                custom_domain_published, signing_secret
         FROM (
             SELECT s.id AS subscriber_id, mw.id AS maintenance_id, s.org_id, s.channel, s.target,
                    s.verified_at,
                    mw.title, mw.description, mw.starts_at, mw.ends_at, mw.created_at,
                    {PAGE_PUBLIC_NAME} AS page_name,
                    sp.public_locale,
                    sp.slug::text AS slug,
                    sp.custom_domain::text AS custom_domain,
                    {PAGE_CUSTOM_DOMAIN_PUBLISHED} AS custom_domain_published,
                    s.config ->> 'signing_secret' AS signing_secret,
                    CASE WHEN mw.ends_at <= now() THEN 'completed' ELSE 'scheduled' END AS phase,
                    CASE WHEN mw.ends_at <= now() THEN mw.ends_at ELSE mw.created_at END AS event_at
             FROM status_page_subscribers s
             JOIN status_pages sp ON sp.id = s.status_page_id
             {PAGE_PLAN_JOIN}
             JOIN maintenance_windows mw ON mw.org_id = s.org_id
             WHERE s.channel IN ('email', 'webhook') AND s.verified_at IS NOT NULL
               AND mw.deleted_at IS NULL
               AND mw.ends_at >= now() - make_interval(hours => $2)
               AND {PAGE_SERVED}
               AND {SHOWN_ON_PAGE}
         ) cand
         WHERE event_at >= verified_at
           AND event_at >= now() - make_interval(hours => $2)
           AND NOT EXISTS (
               SELECT 1 FROM status_page_subscriber_deliveries n
               WHERE n.subscriber_id = cand.subscriber_id
                 AND n.event_kind = 'maintenance'
                 AND n.event_ref = cand.maintenance_id
                 AND n.phase = cand.phase
                 AND (n.status = 'sent'
                   OR (n.status = 'queued' AND n.created_at > now() - make_interval(mins => $3))
                   OR (n.status = 'failed' AND n.attempts >= $4)))
         ORDER BY starts_at
         LIMIT $1",
        SHOWN_ON_PAGE = shown_on_page_sql("mw.ends_at"),
    );
    let rows = sqlx::query_as::<_, PendingMaintenance>(&sql)
        .bind(limit)
        .bind(FANOUT_LOOKBACK_HOURS as i32)
        .bind(CLAIM_ORPHAN_MINUTES as i32)
        .bind(FANOUT_MAX_ATTEMPTS)
        .fetch_all(pool)
        .await
        .context("subscriber_maintenance::list_pending")?;
    Ok(rows)
}

/// An update posted to a window, owed to one subscriber.
#[derive(Debug, sqlx::FromRow)]
pub struct PendingMaintenanceUpdate {
    pub subscriber_id: Uuid,
    pub update_id: Uuid,
    pub maintenance_id: Uuid,
    pub org_id: Uuid,
    pub channel: String,
    pub target: String,
    pub phase: String,
    pub message: String,
    pub title: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub page_name: String,
    public_locale: String,
    pub slug: String,
    pub custom_domain: Option<String>,
    pub custom_domain_published: bool,
    pub signing_secret: Option<String>,
}

impl PendingMaintenanceUpdate {
    pub fn locale(&self) -> Locale {
        Locale::from_db(&self.public_locale)
    }
}

/// Verified subscribers owed an update posted to a window that is not
/// cancelled and that their page shows, through one of its components or
/// because the page kept the window after its monitor left. Reads from the
/// updates inside the lookback, so a tick never walks the whole history, and
/// skips an update posted before the subscriber confirmed.
pub async fn list_pending_updates(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<PendingMaintenanceUpdate>> {
    let sql = format!(
        "SELECT s.id AS subscriber_id, u.id AS update_id, mw.id AS maintenance_id, s.org_id,
                s.channel, s.target, u.phase, u.message, mw.title, mw.starts_at, mw.ends_at,
                {PAGE_PUBLIC_NAME} AS page_name,
                sp.public_locale,
                sp.slug::text AS slug,
                sp.custom_domain::text AS custom_domain,
                {PAGE_CUSTOM_DOMAIN_PUBLISHED} AS custom_domain_published,
                s.config ->> 'signing_secret' AS signing_secret
         FROM maintenance_updates u
         JOIN maintenance_windows mw ON mw.id = u.maintenance_id AND mw.org_id = u.org_id
         JOIN status_page_subscribers s ON s.org_id = u.org_id
         JOIN status_pages sp ON sp.id = s.status_page_id
         {PAGE_PLAN_JOIN}
         WHERE u.posted_at >= now() - make_interval(hours => $2)
           AND mw.deleted_at IS NULL
           AND s.channel IN ('email', 'webhook') AND s.verified_at IS NOT NULL
           AND u.posted_at >= s.verified_at
           AND {PAGE_SERVED}
           AND {SHOWN_ON_PAGE}
           AND NOT EXISTS (
               SELECT 1 FROM status_page_subscriber_deliveries n
               WHERE n.subscriber_id = s.id
                 AND n.event_kind = 'maintenance_update'
                 AND n.event_ref = u.id
                 AND n.phase = ''
                 AND (n.status = 'sent'
                   OR (n.status = 'queued' AND n.created_at > now() - make_interval(mins => $3))
                   OR (n.status = 'failed' AND n.attempts >= $4)))
         ORDER BY u.posted_at
         LIMIT $1",
        SHOWN_ON_PAGE = shown_on_page_sql("u.posted_at"),
    );
    let rows = sqlx::query_as::<_, PendingMaintenanceUpdate>(&sql)
        .bind(limit)
        .bind(FANOUT_LOOKBACK_HOURS as i32)
        .bind(CLAIM_ORPHAN_MINUTES as i32)
        .bind(FANOUT_MAX_ATTEMPTS)
        .fetch_all(pool)
        .await
        .context("subscriber_maintenance::list_pending_updates")?;
    Ok(rows)
}
