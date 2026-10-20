use std::sync::Arc;
use std::time::Duration;

use metrics::gauge;
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

use crate::domain::CheckResult;
use crate::metric_names;
use crate::scheduler::TargetRegistry;
use crate::worker::WorkerPool;

/// `pg_pool` is present on the control plane and absent on a probe-only agent
/// (no database connection), so the agent never registers the pool gauges.
pub fn spawn(
    pool: Arc<WorkerPool>,
    registry: Arc<TargetRegistry>,
    pg_pool: Option<PgPool>,
    result_tx: &mpsc::Sender<CheckResult>,
    sample_interval: Duration,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    // WeakSender so the sampler doesn't keep the result channel alive past
    // shutdown — the batcher's rx-drop fallback path needs the channel to
    // close once all real senders are gone.
    let queue_capacity = result_tx.max_capacity();
    let tx = result_tx.downgrade();
    tokio::spawn(run(
        pool,
        registry,
        pg_pool,
        tx,
        queue_capacity,
        sample_interval,
        shutdown,
    ))
}

async fn run(
    pool: Arc<WorkerPool>,
    registry: Arc<TargetRegistry>,
    pg_pool: Option<PgPool>,
    result_tx: mpsc::WeakSender<CheckResult>,
    queue_capacity: usize,
    sample_interval: Duration,
    shutdown: CancellationToken,
) {
    let mut ticker = interval(sample_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let g_in_flight = gauge!(metric_names::WORKERS_IN_FLIGHT);
    let g_breakers_open = gauge!(metric_names::BREAKERS_OPEN);
    let g_targets = gauge!(metric_names::TARGETS_TOTAL);
    let g_queue_depth = gauge!(metric_names::RESULT_QUEUE_DEPTH);
    let g_singleflight_slots = gauge!(metric_names::RDAP_SINGLEFLIGHT_SLOTS);
    let g_resident = gauge!(metric_names::PROCESS_RESIDENT_BYTES);

    // Register the pool gauges only when a database is wired, so the probe-only
    // agent's exposition stays free of pool series it can't populate.
    let pool_gauges = pg_pool.map(|pg_pool| PoolGauges {
        pg_pool,
        size: gauge!(metric_names::PG_POOL_SIZE),
        idle: gauge!(metric_names::PG_POOL_IDLE),
        in_use: gauge!(metric_names::PG_POOL_IN_USE),
    });

    let singleflight = pool.domain_expiry_runtime().singleflight.clone();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {
                g_in_flight.set(pool.in_flight() as f64);
                g_breakers_open.set(pool.open_breakers() as f64);
                g_targets.set(registry.len() as f64);
                let depth = match result_tx.upgrade() {
                    Some(tx) => queue_capacity.saturating_sub(tx.capacity()),
                    None => 0,
                };
                g_queue_depth.set(depth as f64);
                g_singleflight_slots.set(singleflight.len() as f64);

                if let Some(bytes) = resident_bytes() {
                    g_resident.set(bytes as f64);
                }

                if let Some(pool_gauges) = &pool_gauges {
                    pool_gauges.sample();
                }
            }
        }
    }
}

/// Pre-registered Postgres pool gauges plus the pool they read.
struct PoolGauges {
    pg_pool: PgPool,
    size: metrics::Gauge,
    idle: metrics::Gauge,
    in_use: metrics::Gauge,
}

impl PoolGauges {
    fn sample(&self) {
        let pg_size = self.pg_pool.size() as usize;
        let pg_idle = self.pg_pool.num_idle();
        self.size.set(pg_size as f64);
        self.idle.set(pg_idle as f64);
        self.in_use.set(pg_size.saturating_sub(pg_idle) as f64);
    }
}

/// Resident set size in bytes, sourced from `/proc/self/status` on Linux.
/// `None` on platforms without procfs — the gauge simply stays at its last
/// value (typically zero) and Grafana series for non-Linux dev runs are
/// absent rather than misleading.
#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    // VmRSS is reported in kB per kernel convention; multiply to bytes so
    // the metric is unit-clean for Grafana's bytes formatter.
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn resident_bytes() -> Option<u64> {
    None
}
