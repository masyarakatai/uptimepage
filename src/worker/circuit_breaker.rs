use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU32, Ordering};

use chrono::Utc;
use metrics::counter;
use parking_lot::Mutex;

use crate::config::CircuitBreakerConfig;
use crate::domain::{CheckResult, is_timeout_error};
use crate::metric_names;

fn record_transition(from: BreakerState, to: BreakerState) {
    counter!(metric_names::BREAKER_STATE_CHANGES, "from" => from.as_label(), "to" => to.as_label())
        .increment(1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BreakerState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

impl BreakerState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Open,
            2 => Self::HalfOpen,
            _ => Self::Closed,
        }
    }

    fn as_label(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// One monitor's breaker. The pool never runs two checks of one monitor at
/// once, so half-open needs no slot count: the next check is the probe.
pub struct CircuitBreaker {
    state: AtomicU8,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    opened_at: AtomicI64,
    /// The timeout that opened the breaker, repeated by every skipped check.
    opened_by: Mutex<Option<CheckResult>>,
    cfg: CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn new(cfg: CircuitBreakerConfig) -> Self {
        Self {
            state: AtomicU8::new(BreakerState::Closed as u8),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            opened_at: AtomicI64::new(0),
            opened_by: Mutex::new(None),
            cfg,
        }
    }

    pub fn state(&self) -> BreakerState {
        BreakerState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// The result to record instead of probing while the breaker is open and
    /// cooling down: the monitor's timeout that opened it, marked as reused so
    /// it keeps its real cause. `None` means probe; after the cooldown that
    /// probe is the half-open one.
    pub fn skip(&self) -> Option<CheckResult> {
        if self.state() != BreakerState::Open {
            return None;
        }
        if self.cooldown_elapsed() {
            self.try_transition_to_half_open();
            return None;
        }
        self.opened_by
            .lock()
            .as_ref()
            .map(CheckResult::repeated_by_breaker)
    }

    /// Safe for the sweep to drop: closed with nothing counted, so dropping it
    /// never changes when the breaker opens.
    pub fn is_idle(&self) -> bool {
        self.state() == BreakerState::Closed && self.failure_count.load(Ordering::Acquire) == 0
    }

    fn cooldown_elapsed(&self) -> bool {
        let now = Utc::now().timestamp();
        let opened = self.opened_at.load(Ordering::Acquire);
        now - opened >= self.cfg.open_duration_secs as i64
    }

    fn try_transition_to_half_open(&self) {
        if self
            .state
            .compare_exchange(
                BreakerState::Open as u8,
                BreakerState::HalfOpen as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.success_count.store(0, Ordering::Release);
            record_transition(BreakerState::Open, BreakerState::HalfOpen);
        }
    }

    /// Only a timeout counts: it held a worker for the whole budget. Any
    /// answer, even a failing one, is cheap to repeat.
    pub fn counts(result: &CheckResult) -> bool {
        result.error.as_deref().is_some_and(is_timeout_error)
    }

    pub fn record(&self, result: &CheckResult) {
        let timed_out = Self::counts(result);
        match self.state() {
            BreakerState::Closed => {
                if timed_out {
                    let fails = self.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
                    if fails >= self.cfg.failure_threshold {
                        self.trip_open(result);
                    }
                } else {
                    self.failure_count.store(0, Ordering::Release);
                }
            }
            BreakerState::HalfOpen => {
                if timed_out {
                    self.trip_open(result);
                } else {
                    let succ = self.success_count.fetch_add(1, Ordering::AcqRel) + 1;
                    if succ >= self.cfg.success_threshold {
                        self.close();
                    }
                }
            }
            BreakerState::Open => {}
        }
    }

    fn trip_open(&self, cause: &CheckResult) {
        let prev = BreakerState::from_u8(self.state.load(Ordering::Acquire));
        if prev == BreakerState::Open {
            return;
        }
        *self.opened_by.lock() = Some(cause.clone());
        self.state
            .store(BreakerState::Open as u8, Ordering::Release);
        self.opened_at
            .store(Utc::now().timestamp(), Ordering::Release);
        self.failure_count.store(0, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
        record_transition(prev, BreakerState::Open);
    }

    fn close(&self) {
        let prev = BreakerState::from_u8(self.state.load(Ordering::Acquire));
        if prev == BreakerState::Closed {
            return;
        }
        self.state
            .store(BreakerState::Closed as u8, Ordering::Release);
        self.failure_count.store(0, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
        *self.opened_by.lock() = None;
        record_transition(prev, BreakerState::Closed);
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::domain::{
        CheckStatus, ErrorClass, NetworkPath, classify_check_error, humanize_check_error,
    };

    fn cfg() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            open_duration_secs: 0,
        }
    }

    fn cooling() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            open_duration_secs: 60,
            ..cfg()
        }
    }

    fn timeout() -> CheckResult {
        CheckResult::error(Uuid::nil(), Uuid::nil(), "connect timeout")
    }

    fn failed(status: CheckStatus, reason: &str) -> CheckResult {
        CheckResult {
            status,
            error: Some(reason.into()),
            ..timeout()
        }
    }

    fn up() -> CheckResult {
        CheckResult {
            status: CheckStatus::Up,
            error: None,
            ..timeout()
        }
    }

    fn opened(cfg: CircuitBreakerConfig) -> CircuitBreaker {
        let cb = CircuitBreaker::new(cfg);
        for _ in 0..cfg.failure_threshold {
            cb.record(&timeout());
        }
        assert_eq!(cb.state(), BreakerState::Open);
        cb
    }

    #[test]
    fn closed_stays_closed_on_success() {
        let cb = CircuitBreaker::new(cfg());
        assert!(cb.skip().is_none());
        cb.record(&up());
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn trips_open_after_threshold_timeouts() {
        let cb = CircuitBreaker::new(cooling());
        for _ in 0..3 {
            assert!(cb.skip().is_none());
            cb.record(&timeout());
        }
        assert_eq!(cb.state(), BreakerState::Open);
        assert!(cb.skip().is_some());
    }

    #[test]
    fn a_target_that_answers_never_opens_it() {
        let cb = CircuitBreaker::new(cfg());
        for _ in 0..10 {
            cb.record(&failed(CheckStatus::Down, "unexpected status 502"));
            cb.record(&failed(CheckStatus::Down, "connection refused"));
            cb.record(&failed(CheckStatus::Down, "body match failed"));
            cb.record(&failed(CheckStatus::Error, "dns: lookup failed"));
        }
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn an_answer_between_timeouts_starts_the_count_over() {
        let cb = CircuitBreaker::new(cfg());
        cb.record(&timeout());
        cb.record(&timeout());
        cb.record(&failed(CheckStatus::Down, "unexpected status 502"));
        cb.record(&timeout());
        cb.record(&timeout());
        assert_eq!(cb.state(), BreakerState::Closed);
        cb.record(&timeout());
        assert_eq!(cb.state(), BreakerState::Open);
    }

    #[test]
    fn every_timeout_kind_counts() {
        for reason in [
            "timeout",
            "connect timeout",
            "no response",
            "body timeout",
            "dns: lookup timed out",
            "no echo reply from 192.0.2.1 within 2000ms",
        ] {
            let cb = CircuitBreaker::new(cfg());
            for _ in 0..3 {
                cb.record(&failed(CheckStatus::Error, reason));
            }
            assert_eq!(cb.state(), BreakerState::Open, "{reason}");
        }
    }

    #[test]
    fn a_counted_timeout_keeps_it_out_of_the_sweep_until_an_answer() {
        let cb = CircuitBreaker::new(cfg());
        assert!(cb.is_idle());
        cb.record(&timeout());
        assert!(!cb.is_idle());
        cb.record(&up());
        assert!(cb.is_idle());
    }

    #[test]
    fn an_open_breaker_is_never_idle() {
        assert!(!opened(cooling()).is_idle());
    }

    #[test]
    fn after_the_cooldown_the_next_check_probes() {
        let cb = opened(cfg());
        assert!(cb.skip().is_none());
        assert_eq!(cb.state(), BreakerState::HalfOpen);
    }

    #[test]
    fn half_open_closes_on_success_threshold() {
        let cb = opened(cfg());
        assert!(cb.skip().is_none());
        cb.record(&up());
        assert!(cb.skip().is_none());
        cb.record(&failed(CheckStatus::Down, "unexpected status 502"));
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_reopens_on_timeout() {
        let cb = opened(cfg());
        assert!(cb.skip().is_none());
        cb.record(&timeout());
        assert_eq!(cb.state(), BreakerState::Open);
    }

    #[test]
    fn a_skipped_check_repeats_the_timeout_that_opened_it() {
        let cb = CircuitBreaker::new(cooling());
        let target = Uuid::now_v7();
        let mut last = CheckResult::error(target, Uuid::nil(), "connect timeout");
        last.network = Some(NetworkPath {
            tried_ips: vec!["192.0.2.1".parse().unwrap()],
            ..NetworkPath::default()
        });
        for _ in 0..3 {
            cb.record(&last);
        }

        let skipped = cb.skip().expect("open and cooling down");
        assert_eq!(skipped.target_id, target);
        assert_eq!(skipped.status, last.status);
        assert_eq!(skipped.network, last.network);
        assert_eq!(skipped.duration_ms, 0);
        assert!(skipped.is_served_stale());
        let error = skipped.error.as_deref().unwrap();
        assert_eq!(humanize_check_error(error), "couldn't connect (timed out)");
        assert_eq!(classify_check_error(error), ErrorClass::CircuitOpen);
    }
}
