//! The sign-in mail of a private page: a link and a code, as for the app's own
//! magic links, but in their own table and scoped to one page.

use anyhow::Context;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::PageRef;
use crate::error::Result;
use crate::security::sha256_hex;
use crate::security::sign_in_code::{
    RedeemedVia, code_is_well_formed, generate_code, normalize_code,
};
use crate::security::token_hash::generate_raw_token;
use crate::storage::locks::advisory_xact_lock;

pub const CODE_TTL_MINUTES: i64 = 15;
/// One mail per address per page inside this window, whoever asks.
pub const SEND_WINDOW_SECONDS: i32 = 60;
/// Codes only reach addresses the owner listed, so these bound what a script
/// can make a customer's own staff receive, and what one page can send.
pub const PER_ADDRESS_DAILY_CAP: i64 = 10;
pub const PER_PAGE_DAILY_CAP: i64 = 500;
pub const PER_IP_DAILY_CAP: i64 = 20;
/// Kept past expiry so "did anyone open this, and how" stays answerable.
const RETENTION_DAYS: i32 = 7;

#[derive(Debug, Clone)]
pub struct CreatedCode {
    pub id: Uuid,
    /// For the link in the mail; never stored.
    pub token: String,
    /// Printed in the same mail; never stored.
    pub code: String,
}

/// Writes the sign-in mail's row with its send already claimed, or refuses
/// and writes nothing: one mail per address per page inside the window, ten a
/// day per address, and for an address that has not signed in here before, a
/// daily budget per page and per requesting IP. A viewer the page already
/// knows never competes for that budget, so made-up addresses at a listed
/// domain cannot use it up and lock the real people out.
///
/// Serialised on the address, so parallel requests elect one sender. Claimed
/// before the send so nothing walks through the SMTP round trip; a failed send
/// hands the window back with [`release_send`].
pub async fn create_claimed(
    pool: &PgPool,
    page: PageRef,
    email: &str,
    nonce: &str,
    ip_hash: Option<&str>,
    known_viewer: bool,
) -> Result<Option<CreatedCode>> {
    let token = generate_raw_token();
    let code = generate_code();
    let mut tx = pool
        .begin()
        .await
        .context("page_access_codes::create_claimed begin")?;
    advisory_xact_lock(
        &mut *tx,
        &format!("page_access_send:{}:{}", page.page.0, email.to_lowercase()),
    )
    .await
    .context("page_access_codes::create_claimed lock")?;
    let row: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO status_page_access_codes \
             (status_page_id, org_id, email, token_hash, code_hash, nonce_hash, expires_at, \
              ip_hash, sent_at) \
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, now() \
         WHERE NOT EXISTS ( \
                 SELECT 1 FROM status_page_access_codes \
                 WHERE status_page_id = $1 AND email = $3 \
                   AND sent_at > now() - make_interval(secs => $9)) \
           AND (SELECT count(*) FROM status_page_access_codes \
                WHERE status_page_id = $1 AND email = $3 \
                  AND sent_at > now() - interval '24 hours') < $10 \
           AND ($11 OR ( \
                (SELECT count(*) FROM status_page_access_codes \
                 WHERE status_page_id = $1 AND sent_at > now() - interval '24 hours') < $12 \
                AND (SELECT count(*) FROM status_page_access_codes \
                     WHERE status_page_id = $1 AND ip_hash = $8 \
                       AND sent_at > now() - interval '24 hours') < $13)) \
         RETURNING id",
    )
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(email)
    .bind(sha256_hex(&token))
    .bind(sha256_hex(&code))
    .bind(sha256_hex(nonce))
    .bind(Utc::now() + Duration::minutes(CODE_TTL_MINUTES))
    .bind(ip_hash)
    .bind(SEND_WINDOW_SECONDS)
    .bind(PER_ADDRESS_DAILY_CAP)
    .bind(known_viewer)
    .bind(PER_PAGE_DAILY_CAP)
    .bind(PER_IP_DAILY_CAP)
    .fetch_optional(&mut *tx)
    .await
    .context("page_access_codes::create_claimed")?;
    tx.commit()
        .await
        .context("page_access_codes::create_claimed commit")?;
    Ok(row.map(|(id,)| CreatedCode { id, token, code }))
}

pub async fn release_send(pool: &PgPool, page: PageRef, id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE status_page_access_codes SET sent_at = NULL \
         WHERE id = $1 AND status_page_id = $2 AND org_id = $3",
    )
    .bind(id)
    .bind(page.page.0)
    .bind(page.org.0)
    .execute(pool)
    .await
    .context("page_access_codes::release_send")?;
    Ok(())
}

/// Retires the address's earlier unused mails on this page once a newer one
/// went out. Strictly older only, so two sends that raced keep one live.
pub async fn supersede_others(pool: &PgPool, page: PageRef, email: &str, keep: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE status_page_access_codes SET superseded_at = now() \
         WHERE status_page_id = $1 AND org_id = $2 AND email = $3 AND id <> $4 \
           AND used_at IS NULL AND superseded_at IS NULL \
           AND (created_at, id) < (SELECT created_at, id FROM status_page_access_codes WHERE id = $4)",
    )
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(email)
    .bind(keep)
    .execute(pool)
    .await
    .context("page_access_codes::supersede_others")?;
    Ok(())
}

const LIVE: &str = "used_at IS NULL AND superseded_at IS NULL AND sent_at IS NOT NULL \
                    AND expires_at > now()";

/// The address a live link was sent to, without spending it: the confirm page
/// a mail scanner prefetches must leave the link working.
pub async fn peek_link(pool: &PgPool, page: PageRef, token: &str) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(&format!(
        "SELECT email::text FROM status_page_access_codes \
         WHERE token_hash = $1 AND status_page_id = $2 AND org_id = $3 AND {LIVE}"
    ))
    .bind(sha256_hex(token))
    .bind(page.page.0)
    .bind(page.org.0)
    .fetch_optional(pool)
    .await
    .context("page_access_codes::peek_link")?;
    Ok(row.map(|(e,)| e))
}

/// Spends a live link and returns its address. `None` for anything else, and
/// callers do not say which.
pub async fn consume_link(pool: &PgPool, page: PageRef, token: &str) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(&format!(
        "UPDATE status_page_access_codes SET used_at = now(), redeemed_via = $4 \
         WHERE token_hash = $1 AND status_page_id = $2 AND org_id = $3 AND {LIVE} \
         RETURNING email::text"
    ))
    .bind(sha256_hex(token))
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(RedeemedVia::Link.as_str())
    .fetch_optional(pool)
    .await
    .context("page_access_codes::consume_link")?;
    Ok(row.map(|(e,)| e))
}

/// One answer for spent, unmatched, expired and wrong-browser, so entering
/// codes cannot probe.
#[derive(Debug, PartialEq, Eq)]
pub enum CodeOutcome {
    Ok(String),
    Refused,
    /// Not a code at all, so nothing was spent.
    Malformed,
}

/// One attempt between all the codes this browser was sent, so a resend
/// buys no extra guesses and the code from an earlier mail that arrived last
/// still works. A hit signs in and spends the rest; a well-formed miss spends
/// them all and leaves the links in those mails working. One statement, so
/// parallel guesses get one attempt between them.
pub async fn consume_code(
    pool: &PgPool,
    page: PageRef,
    nonce: &str,
    code: &str,
) -> Result<CodeOutcome> {
    let normalized = normalize_code(code);
    if !code_is_well_formed(&normalized) {
        return Ok(CodeOutcome::Malformed);
    }
    let spent: Vec<(bool, String)> = sqlx::query_as(
        "UPDATE status_page_access_codes SET \
             code_spent_at = now(), \
             used_at = CASE WHEN code_hash = $4 THEN now() END, \
             redeemed_via = CASE WHEN code_hash = $4 THEN $5 END \
         WHERE nonce_hash = $1 AND status_page_id = $2 AND org_id = $3 \
           AND code_spent_at IS NULL AND used_at IS NULL AND sent_at IS NOT NULL \
           AND expires_at > now() \
         RETURNING code_hash = $4, email::text",
    )
    .bind(sha256_hex(nonce))
    .bind(page.page.0)
    .bind(page.org.0)
    .bind(sha256_hex(&normalized))
    .bind(RedeemedVia::Code.as_str())
    .fetch_all(pool)
    .await
    .context("page_access_codes::consume_code")?;
    Ok(spent
        .into_iter()
        .find_map(|(hit, email)| hit.then_some(email))
        .map_or(CodeOutcome::Refused, CodeOutcome::Ok))
}

pub async fn purge_old(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "DELETE FROM status_page_access_codes \
         WHERE expires_at < now() - make_interval(days => $1)",
    )
    .bind(RETENTION_DAYS)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
