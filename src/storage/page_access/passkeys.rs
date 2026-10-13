//! Viewer passkeys and the ceremony state behind them. Same shape as the app's
//! own `webauthn_credentials`, keyed by viewer and bound to the page host the
//! passkey was minted on.

use anyhow::Context;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_rs::prelude::{CredentialID, Passkey};

use crate::domain::{AccessEventKind, AccessEventMethod, PageRef};
use crate::error::{AppError, Result};
use crate::storage::passkeys::{CEREMONY_TTL_SECONDS, MAX_PER_USER};

use super::events::{self, NewEvent};

/// The passkeys a viewer can use on this host, for the exclusion list and the
/// assertion check.
pub async fn for_viewer(
    pool: &PgPool,
    page: PageRef,
    viewer: Uuid,
    rp_id: &str,
) -> Result<Vec<Passkey>> {
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
        "SELECT credential FROM status_page_viewer_passkeys \
         WHERE viewer_id = $1 AND status_page_id = $2 AND org_id = $3 AND rp_id = $4",
    )
    .bind(viewer)
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(rp_id)
    .fetch_all(pool)
    .await
    .context("viewer_passkeys::for_viewer")?;
    rows.into_iter()
        .map(|(v,)| {
            serde_json::from_value(v)
                .map_err(|e| AppError::Other(anyhow::anyhow!("decode viewer passkey: {e}")))
        })
        .collect()
}

pub fn credential_ids(keys: &[Passkey]) -> Vec<CredentialID> {
    keys.iter().map(|k| k.cred_id().clone()).collect()
}

/// Stores a passkey, capped per viewer on this host. The cap is checked under
/// a per-viewer lock so two ceremonies finishing together cannot both pass it.
pub async fn insert(
    pool: &PgPool,
    page: PageRef,
    viewer: Uuid,
    passkey: &Passkey,
    rp_id: &str,
    ip_hash: Option<&str>,
    user_agent_hash: Option<&str>,
) -> Result<()> {
    let credential = serde_json::to_value(passkey)
        .map_err(|e| AppError::Other(anyhow::anyhow!("encode viewer passkey: {e}")))?;
    let mut tx = pool
        .begin()
        .await
        .context("viewer_passkeys::insert begin")?;
    crate::storage::locks::advisory_xact_lock(&mut *tx, &format!("page_viewer:{viewer}"))
        .await
        .context("viewer_passkeys::insert lock")?;
    let (held,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM status_page_viewer_passkeys \
         WHERE viewer_id = $1 AND status_page_id = $2 AND org_id = $3 AND rp_id = $4",
    )
    .bind(viewer)
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(rp_id)
    .fetch_one(&mut *tx)
    .await
    .context("viewer_passkeys::insert count")?;
    if held >= MAX_PER_USER {
        return Err(AppError::bad_request(
            "TOO_MANY_PASSKEYS",
            format!("you already saved {MAX_PER_USER} passkeys for this page"),
        ));
    }
    sqlx::query(
        "INSERT INTO status_page_viewer_passkeys \
             (viewer_id, status_page_id, org_id, credential_id, credential, rp_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(viewer)
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(AsRef::<[u8]>::as_ref(passkey.cred_id()))
    .bind(&credential)
    .bind(rp_id)
    .execute(&mut *tx)
    .await
    .context("viewer_passkeys::insert")?;
    events::record(
        &mut *tx,
        NewEvent {
            viewer: Some(viewer),
            method: Some(AccessEventMethod::Passkey),
            ip_hash,
            user_agent_hash,
            ..NewEvent::new(page, AccessEventKind::PasskeyAdded)
        },
    )
    .await?;
    tx.commit()
        .await
        .context("viewer_passkeys::insert commit")?;
    Ok(())
}

/// The viewer a credential belongs to on this page and host. A passkey from
/// another page, or minted on another host, names nobody here.
pub async fn owner_of(
    pool: &PgPool,
    page: PageRef,
    credential_id: &[u8],
    rp_id: &str,
) -> Result<Option<Uuid>> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT viewer_id FROM status_page_viewer_passkeys \
         WHERE credential_id = $1 AND status_page_id = $2 AND org_id = $3 AND rp_id = $4",
    )
    .bind(credential_id)
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(rp_id)
    .fetch_optional(pool)
    .await
    .context("viewer_passkeys::owner_of")?;
    Ok(row.map(|(v,)| v))
}

/// The counter and backup flags live inside the stored credential, so a
/// successful assertion writes the whole value back.
pub async fn record_use(pool: &PgPool, page: PageRef, passkey: &Passkey) -> Result<()> {
    let credential = serde_json::to_value(passkey)
        .map_err(|e| AppError::Other(anyhow::anyhow!("encode viewer passkey: {e}")))?;
    sqlx::query(
        "UPDATE status_page_viewer_passkeys SET credential = $4, last_used_at = now() \
         WHERE credential_id = $1 AND status_page_id = $2 AND org_id = $3",
    )
    .bind(AsRef::<[u8]>::as_ref(passkey.cred_id()))
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(&credential)
    .execute(pool)
    .await
    .context("viewer_passkeys::record_use")?;
    Ok(())
}

/// Stores a ceremony's state under a hashed handle. `viewer` names the
/// registrant; a sign-in has none until the authenticator names one.
pub async fn put_state<S: serde::Serialize>(
    pool: &PgPool,
    page: PageRef,
    handle: &str,
    viewer: Option<Uuid>,
    state: &S,
) -> Result<()> {
    let encoded = serde_json::to_value(state)
        .map_err(|e| AppError::Other(anyhow::anyhow!("encode ceremony state: {e}")))?;
    sqlx::query(
        "INSERT INTO status_page_webauthn_states \
             (state_hash, status_page_id, org_id, viewer_id, state, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(crate::security::sha256_hex(handle))
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(viewer)
    .bind(&encoded)
    .bind(Utc::now() + Duration::seconds(CEREMONY_TTL_SECONDS))
    .execute(pool)
    .await
    .context("viewer_passkeys::put_state")?;
    Ok(())
}

/// A consumed ceremony. The registrant is read before the state is decoded,
/// so a handle answered at the other ceremony is refused as spent rather than
/// failing to decode.
pub struct TakenState {
    pub viewer: Option<Uuid>,
    state: serde_json::Value,
}

impl TakenState {
    pub fn decode<S: serde::de::DeserializeOwned>(self) -> Result<S> {
        serde_json::from_value(self.state)
            .map_err(|e| AppError::Other(anyhow::anyhow!("decode ceremony state: {e}")))
    }
}

/// Deleted as it is read, so a replayed answer finds nothing.
pub async fn take_state(pool: &PgPool, page: PageRef, handle: &str) -> Result<Option<TakenState>> {
    let row: Option<(Option<Uuid>, serde_json::Value)> = sqlx::query_as(
        "DELETE FROM status_page_webauthn_states \
         WHERE state_hash = $1 AND status_page_id = $2 AND org_id = $3 AND expires_at > now() \
         RETURNING viewer_id, state",
    )
    .bind(crate::security::sha256_hex(handle))
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(pool)
    .await
    .context("viewer_passkeys::take_state")?;
    Ok(row.map(|(viewer, state)| TakenState { viewer, state }))
}

pub async fn purge_expired_states(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query("DELETE FROM status_page_webauthn_states WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
