use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::worker::WorkerPool;

/// Stops probing without losing a result. The scheduler stops first so no
/// check starts, the checks already running report, and only then does the
/// batcher flush and close its channel. Stopped together, the batcher would
/// close the channel on every check still running.
pub async fn stop_probing(
    stop: &CancellationToken,
    scheduler: JoinHandle<()>,
    pool: &WorkerPool,
    settle_for: Duration,
    flush: CancellationToken,
    batcher: JoinHandle<()>,
) {
    stop.cancel();
    let _ = scheduler.await;
    let tasks = pool.tasks();
    tasks.close();
    let settled = tokio::time::timeout(settle_for, tasks.wait()).await;
    if settled.is_err() {
        tracing::warn!(
            pending = tasks.len(),
            "checks still running at shutdown, their results are lost"
        );
    }
    flush.cancel();
    let _ = batcher.await;
}
