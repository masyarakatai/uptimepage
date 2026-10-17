//! The embedded migrations as a booting build runs them.

use crate::common::{MIGRATOR, drop_test_db, fresh_test_db, open_test_pool};

/// Rolling back starts an older image on a database a newer one migrated
/// further.
#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn a_build_boots_on_migrations_a_newer_build_applied() {
    let Some((url, test_db)) = fresh_test_db("migrator").await else {
        return;
    };
    let pool = open_test_pool(&url).await;
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES ($1, 'from a newer build', true, decode('00', 'hex'), 0)",
    )
    .bind(i64::MAX)
    .execute(&pool)
    .await
    .unwrap();
    let ran = MIGRATOR.run(&pool).await;
    pool.close().await;
    drop_test_db(&test_db).await;
    ran.unwrap();
}
