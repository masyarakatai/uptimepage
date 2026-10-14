//! Past maintenance on a status page: which windows the page's history and
//! archive list, and the merged incident + maintenance paging.
//!
//! Needs Postgres and ClickHouse (the page snapshot reads both):
//!
//!     DATABASE_URL=postgres://monitor:monitor@127.0.0.1:5432/<db> \
//!     CLICKHOUSE_URL=http://127.0.0.1:8123 \
//!       cargo nextest run --test it --run-ignored all -E 'test(/^maintenance_history_test::/)'

use crate::common;

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use sqlx::PgPool;
use uptimepage::domain::{
    CheckSpec, ExpectedStatus, NewStatusPage, NewStatusPageComponent, NewTarget, OrgId, PageRef,
    WriteSource,
};
use uptimepage::pagination::HistoryCursor;
use uptimepage::public_status::history::{HistoryEntry, merge};
use uptimepage::public_status::{
    AggregatorConfig, IncidentListQuery, MaintenanceListQuery, OrgAggregator, OrgPublicSource,
    PageCache, PublicSource,
};
use uptimepage::storage::{PgStatusPageStore, PostgresTargetStore, StatusPageStore, TargetStore};
use url::Url;
use uuid::Uuid;

use crate::common::default_http_check;

async fn seed_org(pool: &PgPool) -> OrgId {
    let slug = format!("mh-{}", Uuid::now_v7().simple());
    let (id,): (Uuid,) = sqlx::query_as(
        "WITH a AS (INSERT INTO accounts DEFAULT VALUES RETURNING id) \
         INSERT INTO organizations (slug, name, account_id) \
         SELECT $1, 'Maintenance history', a.id FROM a RETURNING id",
    )
    .bind(&slug[..30])
    .fetch_one(pool)
    .await
    .expect("insert org");
    OrgId(id)
}

async fn seed_target(pool: &PgPool, org: OrgId, name: &str) -> Uuid {
    let store = PostgresTargetStore::from_pool(pool.clone(), None);
    let url = Url::parse("https://example.com/").unwrap();
    let target = NewTarget {
        name: name.into(),
        check: CheckSpec::Http(default_http_check(url, ExpectedStatus::Exact(200))),
        interval: Duration::from_secs(30),
        enabled: true,
        tags: vec![],
        alerts: Default::default(),
        region_policy: Default::default(),
        alert_confirmations: 2,
        notify_recovery: true,
        renotify_interval_secs: 3600,
        recovery_period_secs: None,
        group_name: None,
        owner_user_id: None,
        regions: None,
    };
    store
        .create(org, target, WriteSource::Ui, i64::MAX, i64::MAX)
        .await
        .expect("create target")
        .id
}

async fn seed_page(pool: &PgPool, org: OrgId, target: Uuid) -> uptimepage::domain::StatusPageId {
    let store = PgStatusPageStore::new(pool.clone());
    let slug = format!("mhpage{}", Uuid::now_v7().simple());
    let page = store
        .create(
            org,
            NewStatusPage {
                access: None,
                slug: slug[..30].to_owned(),
                name: "History".into(),
                enabled: true,
            },
            WriteSource::Ui,
            i64::MAX,
            None,
        )
        .await
        .expect("create page")
        .expect("within page cap");
    store
        .add_component(
            org,
            page.id,
            NewStatusPageComponent {
                target_id: target,
                public_name: Some("Public API".into()),
                public_description: None,
                public_group: None,
                sort_order: 0,
                detail_link_enabled: false,
            },
            i64::MAX,
            None,
        )
        .await
        .expect("add component");
    page.id
}

/// A window from `start_h` to `end_h` hours from now on `targets`.
async fn seed_window(
    pool: &PgPool,
    org: OrgId,
    title: &str,
    start_h: i32,
    end_h: i32,
    targets: &[Uuid],
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO maintenance_windows (org_id, title, description, starts_at, ends_at)
         VALUES ($1, $2, 'planned', now() + make_interval(hours => $3),
                 now() + make_interval(hours => $4))
         RETURNING id",
    )
    .bind(org.0)
    .bind(title)
    .bind(start_h)
    .bind(end_h)
    .fetch_one(pool)
    .await
    .expect("insert window");
    for target in targets {
        sqlx::query(
            "INSERT INTO maintenance_window_components (org_id, maintenance_id, target_id)
             VALUES ($1, $2, $3)",
        )
        .bind(org.0)
        .bind(id)
        .bind(target)
        .execute(pool)
        .await
        .expect("insert window component");
    }
    id
}

async fn seed_incident(pool: &PgPool, org: OrgId, target: Uuid, start_h: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO incidents (org_id, target_id, started_at, ended_at, status_at_start, visibility)
         VALUES ($1, $2, now() + make_interval(hours => $3),
                 now() + make_interval(hours => $3, mins => 5), 'down', 'public')
         RETURNING id",
    )
    .bind(org.0)
    .bind(target)
    .bind(start_h)
    .fetch_one(pool)
    .await
    .expect("insert incident")
}

async fn with_org_cleanup<F>(pool: &PgPool, org: OrgId, f: F)
where
    F: std::future::Future<Output = ()>,
{
    let result = AssertUnwindSafe(f).catch_unwind().await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org.0)
        .execute(pool)
        .await;
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

fn titles(windows: &[uptimepage::domain::PublicMaintenance]) -> Vec<&str> {
    windows.iter().map(|w| w.title.as_str()).collect()
}

#[tokio::test]
#[ignore = "requires DATABASE_URL + CLICKHOUSE_URL"]
async fn a_page_lists_the_windows_that_ran_on_its_components() {
    let Some(pool) = common::pg_pool_from_env().await else {
        return;
    };
    let Some(ch) = common::ch_client_from_env().await else {
        return;
    };
    let org = seed_org(&pool).await;
    with_org_cleanup(&pool, org, async {
        let on_page = seed_target(&pool, org, "mh-on-page").await;
        let elsewhere = seed_target(&pool, org, "mh-elsewhere").await;
        let page = seed_page(&pool, org, on_page).await;

        seed_window(&pool, org, "both", -48, -47, &[on_page, elsewhere]).await;
        seed_window(&pool, org, "ended", -72, -71, &[on_page]).await;
        seed_window(&pool, org, "old", -40 * 24, -40 * 24 + 1, &[on_page]).await;
        seed_window(&pool, org, "running", -1, 1, &[on_page]).await;
        seed_window(&pool, org, "upcoming", 24, 25, &[on_page]).await;
        seed_window(&pool, org, "other page", -24, -23, &[elsewhere]).await;
        let cancelled = seed_window(&pool, org, "cancelled", -30, -29, &[on_page]).await;
        sqlx::query("UPDATE maintenance_windows SET deleted_at = now() WHERE id = $1")
            .bind(cancelled)
            .execute(&pool)
            .await
            .unwrap();

        let agg = Arc::new(OrgAggregator::new(
            pool.clone(),
            ch,
            AggregatorConfig::default(),
            None,
        ));
        let (snapshot, _, _, _) = agg.build(page, org).await.expect("build");
        assert_eq!(
            titles(&snapshot.recent_maintenance),
            ["both", "ended"],
            "ended in the last 30 days, newest first"
        );
        assert!(!snapshot.recent_maintenance_has_more);
        assert_eq!(
            snapshot.recent_maintenance[0].affected_component_names,
            ["Public API"],
            "only this page's components, by their public name"
        );

        let cfg = uptimepage::config::PublicStatusConfig::default();
        let source = OrgPublicSource::new(agg, PageCache::new(&cfg), pool.clone());
        let page_ref = PageRef { page, org };
        let list = |ended_only, limit, cursor| MaintenanceListQuery {
            limit,
            cursor,
            ended_only,
        };

        let past = source
            .list_maintenance(page_ref, list(true, 100, None))
            .await
            .unwrap();
        assert_eq!(titles(&past.items), ["both", "ended", "old"]);
        assert!(past.next_cursor.is_none());

        let started = source
            .list_maintenance(page_ref, list(false, 100, None))
            .await
            .unwrap();
        assert_eq!(titles(&started.items), ["running", "both", "ended", "old"]);

        let mut walked = Vec::new();
        let mut cursor = None;
        loop {
            let one = source
                .list_maintenance(page_ref, list(false, 1, cursor))
                .await
                .unwrap();
            walked.extend(one.items.into_iter().map(|w| w.title));
            match one.next_cursor {
                Some(next) => cursor = Some(HistoryCursor::decode(&next).unwrap()),
                None => break,
            }
        }
        assert_eq!(walked, ["running", "both", "ended", "old"]);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL + CLICKHOUSE_URL"]
async fn the_merged_history_pages_through_both_kinds_without_a_gap() {
    let Some(pool) = common::pg_pool_from_env().await else {
        return;
    };
    let Some(ch) = common::ch_client_from_env().await else {
        return;
    };
    let org = seed_org(&pool).await;
    with_org_cleanup(&pool, org, async {
        let target = seed_target(&pool, org, "mh-merge").await;
        let page = seed_page(&pool, org, target).await;
        let mut expected: Vec<(i32, Uuid)> = Vec::new();
        for h in [-2, -5, -9, -13] {
            expected.push((h, seed_incident(&pool, org, target, h).await));
        }
        for h in [-3, -4, -10, -20] {
            let id = seed_window(&pool, org, &format!("w{h}"), h, h + 1, &[target]).await;
            expected.push((h, id));
        }
        expected.sort_by_key(|(h, _)| std::cmp::Reverse(*h));
        let expected: Vec<Uuid> = expected.into_iter().map(|(_, id)| id).collect();

        let agg = Arc::new(OrgAggregator::new(
            pool.clone(),
            ch,
            AggregatorConfig::default(),
            None,
        ));
        let cfg = uptimepage::config::PublicStatusConfig::default();
        let source = OrgPublicSource::new(agg, PageCache::new(&cfg), pool.clone());
        let page_ref = PageRef { page, org };

        let mut walked: Vec<Uuid> = Vec::new();
        let mut cursor: Option<HistoryCursor> = None;
        let mut pages = 0;
        loop {
            let incidents = source
                .list_incidents(
                    page_ref,
                    IncidentListQuery {
                        limit: 3,
                        cursor,
                        ongoing_only: false,
                    },
                )
                .await
                .unwrap();
            let windows = source
                .list_maintenance(
                    page_ref,
                    MaintenanceListQuery {
                        limit: 3,
                        cursor,
                        ended_only: false,
                    },
                )
                .await
                .unwrap();
            let merged = merge(incidents, windows, 3);
            pages += 1;
            walked.extend(merged.entries.iter().map(|e| match e {
                HistoryEntry::Incident(i) => i.id,
                HistoryEntry::Maintenance(m) => m.id,
            }));
            match merged.next_cursor {
                Some(next) => cursor = Some(HistoryCursor::decode(&next).unwrap()),
                None => break,
            }
        }
        assert_eq!(walked, expected, "every row once, newest first");
        assert_eq!(pages, 3);
    })
    .await;
}
