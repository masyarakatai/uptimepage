//! A page's access settings and list: read by the gate on every request to a
//! private page, written with the page edit they arrive in.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use serde_json::json;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::{
    AccessRule, AccessRuleKind, OrgId, PageAccess, PageAccessSettings, PageRef, StatusPageId,
    UserId, normalize_email,
};
use crate::error::Result;
use crate::storage::orgs::record_audit_tx;

#[derive(sqlx::FromRow)]
struct SettingsRow {
    status_page_id: Uuid,
    protected: bool,
    email_enabled: bool,
    passkeys_enabled: bool,
    recheck_days: Option<i32>,
    session_days: Option<i32>,
}

impl From<&SettingsRow> for PageAccessSettings {
    fn from(r: &SettingsRow) -> Self {
        Self {
            protected: r.protected,
            email_enabled: r.email_enabled,
            passkeys_enabled: r.passkeys_enabled,
            recheck_days: r.recheck_days,
            session_days: r.session_days,
        }
    }
}

const SETTINGS_COLUMNS: &str =
    "status_page_id, protected, email_enabled, passkeys_enabled, recheck_days, session_days";

/// `None` for a page never made private.
pub async fn load(pool: &PgPool, page: PageRef) -> Result<Option<PageAccess>> {
    let row: Option<SettingsRow> = sqlx::query_as(&format!(
        "SELECT {SETTINGS_COLUMNS} FROM status_page_access \
         WHERE status_page_id = $1 AND org_id = $2"
    ))
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(pool)
    .await
    .context("page_access::load")?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(PageAccess {
        settings: (&row).into(),
        rules: rules(pool, page.org, page.page).await?,
    }))
}

/// Every page of the org that has settings, for the pages list.
pub async fn load_for_org(pool: &PgPool, org: OrgId) -> Result<HashMap<StatusPageId, PageAccess>> {
    let rows: Vec<SettingsRow> = sqlx::query_as(&format!(
        "SELECT {SETTINGS_COLUMNS} FROM status_page_access WHERE org_id = $1"
    ))
    .bind(org.0)
    .fetch_all(pool)
    .await
    .context("page_access::load_for_org")?;
    let mut out: HashMap<StatusPageId, PageAccess> = rows
        .iter()
        .map(|r| {
            (
                StatusPageId(r.status_page_id),
                PageAccess {
                    settings: r.into(),
                    rules: Vec::new(),
                },
            )
        })
        .collect();
    let rules: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT status_page_id, kind, value::text FROM status_page_access_rules \
         WHERE org_id = $1 ORDER BY kind, value",
    )
    .bind(org.0)
    .fetch_all(pool)
    .await
    .context("page_access::load_for_org rules")?;
    for (page, kind, value) in rules {
        if let (Some(access), Some(kind)) = (
            out.get_mut(&StatusPageId(page)),
            AccessRuleKind::from_db_str(&kind),
        ) {
            access.rules.push(AccessRule { kind, value });
        }
    }
    Ok(out)
}

async fn rules<'c, E: PgExecutor<'c>>(
    executor: E,
    org: OrgId,
    page: StatusPageId,
) -> Result<Vec<AccessRule>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, value::text FROM status_page_access_rules \
         WHERE status_page_id = $1 AND org_id = $2 ORDER BY kind, value",
    )
    .bind(page.0)
    .bind(org.0)
    .fetch_all(executor)
    .await
    .context("page_access::rules")?;
    Ok(rows
        .into_iter()
        .filter_map(|(kind, value)| {
            AccessRuleKind::from_db_str(&kind).map(|kind| AccessRule { kind, value })
        })
        .collect())
}

/// What one write changed, for the audit row and the caller's follow-ups.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AccessChange {
    pub became_private: bool,
    pub became_public: bool,
    pub added: Vec<AccessRule>,
    pub removed: Vec<AccessRule>,
    /// Names of the settings whose value moved.
    pub settings: Vec<&'static str>,
    /// Subscriptions the list no longer covers, removed with the write.
    pub subscribers_removed: u64,
}

impl AccessChange {
    pub fn is_empty(&self) -> bool {
        !self.became_private
            && !self.became_public
            && self.added.is_empty()
            && self.removed.is_empty()
            && self.settings.is_empty()
    }
}

/// Replace a page's settings and list, in the transaction of the page edit
/// they arrive with. The caller has already written the page row, which holds
/// its lock, so two edits of one page cannot interleave here.
///
/// A private page keeps only the subscriptions its list covers: webhooks go,
/// since nobody signs in as one, and so does every address the list does not
/// let in. Going public ends every viewer session; the viewers, their
/// passkeys and the list stay for the next time.
pub async fn replace_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    org: OrgId,
    page: StatusPageId,
    new: &PageAccess,
    actor: Option<UserId>,
) -> Result<AccessChange> {
    let before: Option<SettingsRow> = sqlx::query_as(&format!(
        "SELECT {SETTINGS_COLUMNS} FROM status_page_access \
         WHERE status_page_id = $1 AND org_id = $2 FOR UPDATE"
    ))
    .bind(page.0)
    .bind(org.0)
    .fetch_optional(&mut **tx)
    .await
    .context("page_access::replace before")?;
    let old_settings = before.as_ref().map(PageAccessSettings::from);
    let old_rules: HashSet<AccessRule> = rules(&mut **tx, org, page).await?.into_iter().collect();
    let new_rules: HashSet<AccessRule> = new.rules.iter().cloned().collect();
    let s = new.settings;

    sqlx::query(
        "INSERT INTO status_page_access \
             (status_page_id, org_id, protected, email_enabled, passkeys_enabled, \
              recheck_days, session_days) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (status_page_id) DO UPDATE SET \
             protected = EXCLUDED.protected, email_enabled = EXCLUDED.email_enabled, \
             passkeys_enabled = EXCLUDED.passkeys_enabled, \
             recheck_days = EXCLUDED.recheck_days, session_days = EXCLUDED.session_days, \
             updated_at = now() \
         WHERE status_page_access.org_id = EXCLUDED.org_id",
    )
    .bind(page.0)
    .bind(org.0)
    .bind(s.protected)
    .bind(s.email_enabled)
    .bind(s.passkeys_enabled)
    .bind(s.recheck_days)
    .bind(s.session_days)
    .execute(&mut **tx)
    .await
    .context("page_access::replace settings")?;

    let mut removed: Vec<AccessRule> = old_rules.difference(&new_rules).cloned().collect();
    let mut added: Vec<AccessRule> = new_rules.difference(&old_rules).cloned().collect();
    removed.sort_by(|a, b| a.value.cmp(&b.value));
    added.sort_by(|a, b| a.value.cmp(&b.value));
    if !removed.is_empty() {
        let (kinds, values) = columns(&removed);
        sqlx::query(
            "DELETE FROM status_page_access_rules \
             WHERE status_page_id = $1 AND org_id = $2 \
               AND (kind, value) IN (SELECT k, v::citext FROM UNNEST($3::text[], $4::text[]) AS u(k, v))",
        )
        .bind(page.0)
        .bind(org.0)
        .bind(&kinds)
        .bind(&values)
        .execute(&mut **tx)
        .await
        .context("page_access::replace remove rules")?;
    }
    if !added.is_empty() {
        let (kinds, values) = columns(&added);
        sqlx::query(
            "INSERT INTO status_page_access_rules (status_page_id, org_id, kind, value, created_by) \
             SELECT $1, $2, k, v, $5 FROM UNNEST($3::text[], $4::text[]) AS u(k, v) \
             ON CONFLICT (status_page_id, kind, value) DO NOTHING",
        )
        .bind(page.0)
        .bind(org.0)
        .bind(&kinds)
        .bind(&values)
        .bind(actor.map(|u| u.0))
        .execute(&mut **tx)
        .await
        .context("page_access::replace add rules")?;
    }

    let was_private = old_settings.is_some_and(|o| o.protected);
    let mut change = AccessChange {
        became_private: s.protected && !was_private,
        became_public: was_private && !s.protected,
        added,
        removed,
        settings: changed_settings(old_settings.unwrap_or_default(), s),
        subscribers_removed: 0,
    };
    if change.became_public {
        sqlx::query("DELETE FROM status_page_sessions WHERE status_page_id = $1 AND org_id = $2")
            .bind(page.0)
            .bind(org.0)
            .execute(&mut **tx)
            .await
            .context("page_access::replace end sessions")?;
    }
    // Only when the list can have narrowed: an unchanged private page keeps
    // the subscriptions an earlier write already checked.
    if s.protected && (change.became_private || !change.removed.is_empty()) {
        change.subscribers_removed = prune_subscribers(tx, org, page, new).await?;
    }
    if !change.is_empty() {
        record_audit_tx(
            tx,
            org,
            actor,
            "status_page.access_updated",
            json!({
                "status_page_id": page.0,
                "protected": s.protected,
                "settings": change.settings,
                "rules_added": change.added,
                "rules_removed": change.removed,
                "subscribers_removed": change.subscribers_removed,
            }),
        )
        .await?;
    }
    Ok(change)
}

fn columns(rules: &[AccessRule]) -> (Vec<&'static str>, Vec<&str>) {
    rules
        .iter()
        .map(|r| (r.kind.as_db_str(), r.value.as_str()))
        .unzip()
}

fn changed_settings(old: PageAccessSettings, new: PageAccessSettings) -> Vec<&'static str> {
    [
        ("protected", old.protected != new.protected),
        ("email_enabled", old.email_enabled != new.email_enabled),
        (
            "passkeys_enabled",
            old.passkeys_enabled != new.passkeys_enabled,
        ),
        ("recheck_days", old.recheck_days != new.recheck_days),
        ("session_days", old.session_days != new.session_days),
    ]
    .into_iter()
    .filter_map(|(name, moved)| moved.then_some(name))
    .collect()
}

async fn prune_subscribers(
    tx: &mut Transaction<'_, Postgres>,
    org: OrgId,
    page: StatusPageId,
    access: &PageAccess,
) -> Result<u64> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, channel, target FROM status_page_subscribers \
         WHERE status_page_id = $1 AND org_id = $2",
    )
    .bind(page.0)
    .bind(org.0)
    .fetch_all(&mut **tx)
    .await
    .context("page_access::prune read")?;
    let gone: Vec<Uuid> = rows
        .into_iter()
        .filter(|(_, channel, target)| {
            channel != "email" || !normalize_email(target).is_some_and(|e| access.admits(&e))
        })
        .map(|(id, _, _)| id)
        .collect();
    if gone.is_empty() {
        return Ok(0);
    }
    let res = sqlx::query(
        "DELETE FROM status_page_subscribers \
         WHERE status_page_id = $1 AND org_id = $2 AND id = ANY($3)",
    )
    .bind(page.0)
    .bind(org.0)
    .bind(&gone)
    .execute(&mut **tx)
    .await
    .context("page_access::prune delete")?;
    Ok(res.rows_affected())
}
