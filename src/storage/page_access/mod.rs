//! Private status pages: who may open one, how they proved it, and the trail
//! of who did. Every query is scoped to one page and its org.

pub mod codes;
pub mod events;
pub mod passkeys;
pub mod sessions;
pub mod settings;
pub mod viewers;

use sqlx::PgPool;

/// Spent sign-in state: ceremonies past their TTL, and sign-in mails past the
/// days they are kept for.
pub async fn purge_spent(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(passkeys::purge_expired_states(pool).await? + codes::purge_old(pool).await?)
}
