//! Hashing and checking a private status page's shared password. argon2 is
//! slow on purpose, so it runs on the blocking pool, and only a few at once:
//! a burst of sign-ins queues here instead of taking every blocking thread.
//! An owner setting a password has permits of its own, so it never waits
//! behind a burst of visitors.

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Semaphore;

use crate::error::{AppError, Result};

static CHECKS: Semaphore = Semaphore::const_new(4);
static SETS: Semaphore = Semaphore::const_new(2);

pub async fn hash(password: SecretString) -> Result<String> {
    limited(&SETS, move || {
        super::token_hash::hash(password.expose_secret())
    })
    .await
    .map_err(|e| AppError::Other(e.context("page password hash")))?
}

/// `false` for a wrong password and for a hash that cannot be read.
pub async fn verify(presented: SecretString, hash: String) -> bool {
    limited(&CHECKS, move || {
        super::token_hash::verify(presented.expose_secret(), &hash)
    })
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "page password check did not run");
        false
    })
}

/// `work` on the blocking pool under one of `permits`. The permit goes into
/// the task, so a caller that stops waiting still holds it until the work
/// ends.
async fn limited<T: Send + 'static>(
    permits: &'static Semaphore,
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    let permit = permits.acquire().await?;
    Ok(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hashed_password_checks_only_against_itself() {
        let h = hash(SecretString::from("open sesame")).await.unwrap();
        assert!(verify(SecretString::from("open sesame"), h.clone()).await);
        assert!(!verify(SecretString::from("open sesame "), h.clone()).await);
        assert!(!verify(SecretString::from("x"), "not a hash".into()).await);
    }

    #[tokio::test]
    async fn a_caller_that_gives_up_keeps_the_permit_until_the_work_ends() {
        static ONE: Semaphore = Semaphore::const_new(1);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let caller = tokio::spawn(limited(&ONE, move || wait.recv().ok()));
        while ONE.available_permits() == 1 {
            tokio::task::yield_now().await;
        }
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(ONE.available_permits(), 0);

        release.send(()).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), ONE.acquire())
            .await
            .expect("permit back once the work ended");
    }
}
