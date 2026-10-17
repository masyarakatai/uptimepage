use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::{DashMap, DashSet};
use metrics::{Counter, counter, histogram};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::task::TaskTracker;

use uuid::Uuid;

use crate::config::CircuitBreakerConfig;
use crate::domain::{CheckResult, CheckSpec, CheckStatus, OrgId, Target};
use crate::http_client::HttpClients;
use crate::metric_names;
use crate::worker::circuit_breaker::{BreakerState, CircuitBreaker};
use crate::worker::host_throttle::{HostPermit, HostThrottle, Throttled};
use crate::worker::sweep::sweep_idle;

// Hot-path counters resolved once. `counter!` rebuilds the label set on
// every call — at high QPS that's a per-check allocation we don't need.
// `host_throttle_waits_total{kind=rdap}` is incremented by the
// domain_expiry executor since RDAP no longer pre-throttles at the pool
// level.
static HOST_THROTTLE_WAITS_HOST: LazyLock<Counter> =
    LazyLock::new(|| counter!(metric_names::HOST_THROTTLE_WAITS, "kind" => "host"));
static HOST_THROTTLE_DROPS_C: LazyLock<Counter> =
    LazyLock::new(|| counter!(metric_names::HOST_THROTTLE_DROPS));
static CHECKS_SKIPPED_IN_FLIGHT_C: LazyLock<Counter> =
    LazyLock::new(|| counter!(metric_names::CHECKS_SKIPPED_IN_FLIGHT));

pub struct CheckTask {
    pub target: Arc<Target>,
    /// Owning tenant of `target`. Threaded so a check result fans out to the
    /// alert engine with the org needed for tenant-scoped channel resolution.
    pub org_id: OrgId,
    /// Pre-computed throttle key from `ScheduledTarget::build`. `None` for
    /// check kinds the throttle skips (DNS, DomainExpiry — RDAP path).
    pub host_key: Option<crate::worker::host_throttle::HostKey>,
    /// Pre-computed RDAP TLD for DomainExpiry checks.
    pub rdap_tld: Option<Arc<str>>,
}

/// Sink for completed CheckResults into the storage mpsc. Notifications are
/// driven separately by the incident writer reading the result stream, so the
/// hot path no longer fans out per-result alert signals.
#[derive(Clone)]
pub struct ResultFanout {
    storage: mpsc::Sender<CheckResult>,
    storage_dropped: Arc<AtomicU64>,
}

impl ResultFanout {
    pub fn new(storage: mpsc::Sender<CheckResult>) -> Self {
        Self {
            storage,
            storage_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn queue_depth(&self) -> u64 {
        let max = self.storage.max_capacity();
        max.saturating_sub(self.storage.capacity()) as u64
    }

    pub fn dropped(&self) -> u64 {
        self.storage_dropped.load(Ordering::Relaxed)
    }

    pub fn note_storage_dropped(&self) {
        self.storage_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn dispatch(&self, result: CheckResult) {
        if let Err(err) = self.storage.try_send(result) {
            tracing::warn!(?err, "result channel full or closed");
            counter!(metric_names::STORAGE_DROPPED, "reason" => "queue_full").increment(1);
            self.note_storage_dropped();
        }
    }
}

pub struct WorkerPool {
    semaphore: Arc<Semaphore>,
    max_concurrent: usize,
    http_clients: Arc<HttpClients>,
    /// One per monitor, so a skipped check repeats that monitor's own last
    /// timeout and one monitor never gates another.
    breakers: Arc<DashMap<Uuid, Arc<CircuitBreaker>>>,
    breaker_cfg: CircuitBreakerConfig,
    fanout: ResultFanout,
    host_throttle: Arc<HostThrottle>,
    domain_expiry: Arc<crate::worker::domain_expiry::DomainExpiryRuntime>,
    /// Heartbeat ping state read by the passive executor. Owned here (not
    /// injected) so the pool and web ingest path share one instance. A split
    /// would silently evaluate stale anchors.
    heartbeat: Arc<crate::worker::heartbeat::HeartbeatRuntime>,
    /// Manual monitor states, shared with the set path for the same reason.
    manual: Arc<crate::worker::manual::ManualRuntime>,
    /// Target ids whose probe is mid-flight. Drop-guard backed (see
    /// `InFlightGuard`) so panics also release. Bounds duplicate probes when
    /// a slow check outlasts its cadence.
    in_flight: Arc<DashSet<Uuid>>,
    /// Browser-flow engine; `None` on nodes that don't run flow.
    flow_engine: Option<Arc<crate::worker::flow::engine::CdpEngine>>,
    /// Where a flow run's trace and page snapshot go. `None` leaves the run
    /// unrecorded, which costs history and nothing else.
    flow_runs: Option<Arc<dyn crate::storage::traits::FlowRunSink>>,
    tasks: TaskTracker,
}

impl WorkerPool {
    pub fn new(
        max_concurrent: usize,
        http_clients: HttpClients,
        breaker_cfg: CircuitBreakerConfig,
        fanout: ResultFanout,
        host_throttle: Arc<HostThrottle>,
        domain_expiry: Arc<crate::worker::domain_expiry::DomainExpiryRuntime>,
    ) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
            http_clients: Arc::new(http_clients),
            breakers: Arc::new(DashMap::new()),
            breaker_cfg,
            fanout,
            host_throttle,
            domain_expiry,
            heartbeat: Arc::new(crate::worker::heartbeat::HeartbeatRuntime::default()),
            manual: Arc::new(crate::worker::manual::ManualRuntime::default()),
            in_flight: Arc::new(DashSet::new()),
            flow_engine: None,
            flow_runs: None,
            tasks: TaskTracker::new(),
        }
    }

    /// Builder-style so pools without flow keep the shorter `new` signature.
    pub fn with_flow_engine(
        mut self,
        engine: Option<Arc<crate::worker::flow::engine::CdpEngine>>,
    ) -> Self {
        self.flow_engine = engine;
        self
    }

    pub fn with_flow_runs(
        mut self,
        sink: Option<Arc<dyn crate::storage::traits::FlowRunSink>>,
    ) -> Self {
        self.flow_runs = sink;
        self
    }

    pub fn host_throttle(&self) -> Arc<HostThrottle> {
        self.host_throttle.clone()
    }

    pub fn domain_expiry_runtime(&self) -> Arc<crate::worker::domain_expiry::DomainExpiryRuntime> {
        self.domain_expiry.clone()
    }

    /// Lets the interactive (test / check-now) executor reuse the same engine.
    pub fn flow_engine(&self) -> Option<Arc<crate::worker::flow::engine::CdpEngine>> {
        self.flow_engine.clone()
    }

    pub fn heartbeat_runtime(&self) -> Arc<crate::worker::heartbeat::HeartbeatRuntime> {
        self.heartbeat.clone()
    }

    pub fn manual_runtime(&self) -> Arc<crate::worker::manual::ManualRuntime> {
        self.manual.clone()
    }

    pub fn passive_runtimes(&self) -> crate::worker::PassiveRuntimes {
        crate::worker::PassiveRuntimes {
            heartbeat: self.heartbeat.clone(),
            manual: self.manual.clone(),
        }
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub fn in_flight(&self) -> usize {
        self.max_concurrent
            .saturating_sub(self.semaphore.available_permits())
    }

    /// Every check this pool started, with the flow run it recorded.
    pub fn tasks(&self) -> &TaskTracker {
        &self.tasks
    }

    pub fn open_breakers(&self) -> usize {
        self.breakers
            .iter()
            .filter(|e| e.value().state() == BreakerState::Open)
            .count()
    }

    pub fn result_queue_depth(&self) -> u64 {
        self.fanout.queue_depth()
    }

    pub fn dropped_results(&self) -> u64 {
        self.fanout.dropped()
    }

    pub fn http_clients(&self) -> Arc<HttpClients> {
        self.http_clients.clone()
    }

    /// Drop breakers whose only strong reference is the map and that hold
    /// no live count or belong to a monitor this node no longer schedules.
    /// Run from the scheduler tick to bound the breaker map.
    pub fn sweep_breakers(&self, scheduled: impl Fn(&Uuid) -> bool) -> usize {
        sweep_idle(&self.breakers, |id, b| b.is_idle() || !scheduled(id))
    }

    /// Drops the monitor's breaker: what it counted no longer applies.
    pub fn forget_breaker(&self, target_id: Uuid) {
        self.breakers.remove(&target_id);
    }

    /// A check-now the target answered in time shows it reachable again, so
    /// its scheduled checks probe instead of repeating the old timeout. A body
    /// timeout keeps its status code, so the code alone is no answer.
    pub fn note_check_now(&self, target_id: Uuid, result: &CheckResult) {
        let answered = result.status == CheckStatus::Up || result.response_code.is_some();
        if answered && !CircuitBreaker::counts(result) {
            self.forget_breaker(target_id);
        }
    }

    pub fn dispatch(&self, task: CheckTask) {
        // Passive fast path: an evaluation is a synchronous map read with no
        // spawn, permit, breaker, or throttle. Kept out of the probe pipeline
        // so the machinery below needs no passive special case.
        let passive = match &task.target.check {
            CheckSpec::Heartbeat(h) => {
                Some(Some(crate::worker::heartbeat::execute_heartbeat_check(
                    task.target.id,
                    task.org_id.0,
                    h,
                    &self.heartbeat,
                )))
            }
            CheckSpec::Manual(_) => Some(crate::worker::manual::execute_manual_check(
                task.target.id,
                task.org_id.0,
                &self.manual,
            )),
            _ => None,
        };
        if let Some(result) = passive {
            if let Some(result) = result {
                record_metrics(&result);
                self.fanout.dispatch(result);
            }
            return;
        }
        // Skip-if-in-flight: scheduler ticks every `interval`, but a slow
        // check (or a user-configured timeout > interval) can outlast its
        // cadence. Without this guard, two probes for the same target race —
        // duplicate ClickHouse rows at near-identical timestamps, double
        // host-throttle consumption, ambiguous alert ordering.
        if !self.in_flight.insert(task.target.id) {
            CHECKS_SKIPPED_IN_FLIGHT_C.increment(1);
            return;
        }
        let in_flight_guard = InFlightGuard {
            set: self.in_flight.clone(),
            id: task.target.id,
        };

        let permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!(target_id = %task.target.id, "worker pool saturated, dropping task");
                counter!(metric_names::STORAGE_DROPPED, "reason" => "pool_saturated").increment(1);
                self.fanout.note_storage_dropped();
                return;
            }
        };

        let clients = self.http_clients.clone();
        let breakers = self.breakers.clone();
        let breaker_cfg = self.breaker_cfg;
        let fanout = self.fanout.clone();
        let throttle = self.host_throttle.clone();
        let domain_expiry = self.domain_expiry.clone();
        let flow_engine = self.flow_engine.clone();
        let flow_runs = self.flow_runs.clone();
        let org_id = task.org_id;
        let tasks = self.tasks.clone();

        self.tasks.spawn(async move {
            let _permit = permit;
            let _in_flight_guard = in_flight_guard;

            // No entry is a closed breaker with nothing counted.
            let breaker = breakers.get(&task.target.id).map(|b| b.clone());
            if let Some(skipped) = breaker.as_ref().and_then(|b| b.skip()) {
                counter!(metric_names::CHECK_ERRORS, "kind" => "circuit_open").increment(1);
                fanout.dispatch(skipped);
                return;
            }

            let host_permit = match acquire_host_slot(&throttle, &task) {
                Ok(p) => p,
                Err(Throttled) => {
                    HOST_THROTTLE_DROPS_C.increment(1);
                    return;
                }
            };

            let deps = crate::worker::WorkerDeps {
                http: &clients,
                domain_expiry: &domain_expiry,
                flow: flow_engine.as_deref(),
            };
            let (result, flow_run) = crate::worker::execute_recorded(
                task.target.id,
                org_id.0,
                &task.target.check,
                &deps,
            )
            .await;
            match breaker {
                Some(breaker) => breaker.record(&result),
                None if CircuitBreaker::counts(&result) => {
                    get_or_init_breaker(&breakers, task.target.id, breaker_cfg).record(&result)
                }
                None => {}
            }
            record_metrics(&result);
            drop(host_permit);
            fanout.dispatch(result);
            // Detached so the permit is released on the verdict, not on the
            // telemetry write behind it.
            if let (Some(sink), Some(run)) = (flow_runs, flow_run) {
                tasks.spawn(async move { sink.write_runs(&[run]).await });
            }
        });
    }
}

struct InFlightGuard {
    set: Arc<DashSet<Uuid>>,
    id: Uuid,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.set.remove(&self.id);
    }
}

fn acquire_host_slot(
    throttle: &HostThrottle,
    task: &CheckTask,
) -> Result<Option<HostPermit>, Throttled> {
    // RDAP/DomainExpiry no longer pre-throttles here — the executor owns
    // that path so it can fall back to the sticky last-good cache instead
    // of letting the pool synthesize a Degraded row. `rdap_tld` is still
    // pre-computed on `ScheduledTarget` for the executor's use.
    if task.rdap_tld.is_some() {
        return Ok(None);
    }
    if let Some(key) = task.host_key.as_ref() {
        HOST_THROTTLE_WAITS_HOST.increment(1);
        return throttle.acquire(key).map(Some);
    }
    Ok(None)
}

fn get_or_init_breaker(
    breakers: &DashMap<Uuid, Arc<CircuitBreaker>>,
    target_id: Uuid,
    cfg: CircuitBreakerConfig,
) -> Arc<CircuitBreaker> {
    if let Some(b) = breakers.get(&target_id) {
        return b.clone();
    }
    breakers
        .entry(target_id)
        .or_insert_with(|| Arc::new(CircuitBreaker::new(cfg)))
        .clone()
}

fn record_metrics(result: &CheckResult) {
    counter!(metric_names::CHECKS_TOTAL, "status" => result.status.as_str()).increment(1);
    histogram!(metric_names::CHECK_DURATION_MS).record(result.duration_ms as f64);
}
