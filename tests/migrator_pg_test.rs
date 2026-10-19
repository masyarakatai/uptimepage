//! The embedded migrations as a booting build runs them.

use std::time::Duration;

use serde_json::{Value, json};
use uptimepage::domain::{
    AlertBinding, ChannelConfig, CheckSpec, ExpectedStatus, NewNotificationChannel, NewTarget,
    SlackConfig, TargetAlerts, TargetUpdate, WriteSource,
};
use uptimepage::storage::{
    NotificationChannelStore, PgNotificationChannelStore, PostgresTargetStore, TargetStore,
    create_org_with_owner,
};
use uuid::Uuid;

use crate::common::{
    MIGRATOR, default_http_check, drop_test_db, fresh_test_db, make_user, open_test_pool,
    unique_slug,
};

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

/// Migration 100 copies the JSON bindings into `target_channels` and freezes
/// the column; its down migration rebuilds the JSON from what the table holds
/// by then, changes made after the migration included.
#[tokio::test]
#[ignore = "needs live Postgres (DATABASE_URL)"]
async fn channel_bindings_survive_the_migration_both_ways() {
    let Some((url, test_db)) = fresh_test_db("bindings_migration").await else {
        return;
    };
    let pool = open_test_pool(&url).await;
    let user = make_user(&pool, "mig").await;
    let org = create_org_with_owner(&pool, user, &unique_slug("mig"), "M")
        .await
        .unwrap()
        .unwrap()
        .id;
    let stranger = make_user(&pool, "mig2").await;
    let other = create_org_with_owner(&pool, stranger, &unique_slug("mig2"), "O")
        .await
        .unwrap()
        .unwrap()
        .id;
    let channels = PgNotificationChannelStore::new(pool.clone(), None);
    let targets = PostgresTargetStore::from_pool(pool.clone(), None);
    let channel = |org, name: &'static str| {
        channels.create(
            org,
            NewNotificationChannel {
                name: name.into(),
                config: ChannelConfig::Slack(SlackConfig {
                    webhook_url: format!("https://hooks.slack.com/services/T/B/{name}"),
                    mention: None,
                }),
                enabled: true,
                auto_bind_tags: Vec::new(),
                acknowledge_button: true,
                resolve_button: false,
            },
            WriteSource::Ui,
            i64::MAX,
            None,
        )
    };
    let c = channel(org, "c").await.unwrap().id;
    let d = channel(org, "d").await.unwrap().id;
    let e = channel(org, "e").await.unwrap().id;
    let theirs = channel(other, "theirs").await.unwrap().id;
    let target = |name: &str, bound: &[Uuid]| NewTarget {
        name: name.into(),
        check: CheckSpec::Http(default_http_check(
            url::Url::parse("https://example.com/").unwrap(),
            ExpectedStatus::Exact(200),
        )),
        interval: Duration::from_secs(30),
        enabled: true,
        tags: vec![],
        alerts: TargetAlerts(
            bound
                .iter()
                .map(|&channel_id| AlertBinding { channel_id })
                .collect(),
        ),
        region_policy: Default::default(),
        alert_confirmations: 2,
        notify_recovery: true,
        renotify_interval_secs: 3600,
        recovery_period_secs: None,
        group_name: None,
        owner_user_id: None,
        regions: None,
    };
    let create = |new| targets.create(org, new, WriteSource::Ui, i64::MAX, i64::MAX);
    let t1 = create(target("t1", &[c, d])).await.unwrap().id;
    let t2 = create(target("t2", &[e])).await.unwrap().id;

    // Changed after the migration, so only the table knows.
    let reorder = TargetUpdate {
        alerts: Some(TargetAlerts(vec![
            AlertBinding { channel_id: d },
            AlertBinding { channel_id: c },
        ])),
        ..Default::default()
    };
    targets.update(org, t1, reorder, None, None).await.unwrap();
    assert!(channels.delete(org, e, None).await.unwrap());

    let frozen = sqlx::query("UPDATE targets SET alerts = $1 WHERE id = $2")
        .bind(json!([{ "channel_id": c }]))
        .bind(t1)
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(frozen.to_string().contains("read-only"), "{frozen}");

    MIGRATOR.undo(&pool, 99).await.unwrap();
    let alerts = async |id: Uuid| -> Value {
        sqlx::query_scalar("SELECT alerts FROM targets WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert_eq!(
        alerts(t1).await,
        json!([{ "channel_id": d }, { "channel_id": c }])
    );
    assert_eq!(alerts(t2).await, json!([]));
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('target_channels')::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(table, None);

    // Back up from JSON that also names a deleted channel, another org's
    // channel and a repeat: only the live, own ones are copied, first place wins.
    sqlx::query("UPDATE targets SET alerts = $1 WHERE id = $2")
        .bind(json!([
            { "channel_id": d },
            { "channel_id": e },
            { "channel_id": theirs },
            { "channel_id": d },
            { "channel_id": c }
        ]))
        .bind(t1)
        .execute(&pool)
        .await
        .unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let rows: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT channel_id, position FROM target_channels WHERE target_id = $1 ORDER BY position",
    )
    .bind(t1)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows, vec![(d, 0), (c, 4)]);

    pool.close().await;
    drop_test_db(&test_db).await;
}
