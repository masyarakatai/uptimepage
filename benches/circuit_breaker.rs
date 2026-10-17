use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use uptimepage::config::CircuitBreakerConfig;
use uptimepage::domain::{CheckResult, CheckStatus};
use uptimepage::worker::circuit_breaker::CircuitBreaker;
use uuid::Uuid;

// Thresholds set high to keep the breaker in the Closed state across the bench,
// isolating allow/record hot-path cost from state-transition cost.
fn cfg() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold: 1_000_000,
        success_threshold: 1_000_000,
        open_duration_secs: 60,
    }
}

fn bench_skip_closed(c: &mut Criterion) {
    let cb = CircuitBreaker::new(cfg());
    c.bench_function("breaker_skip_closed", |b| {
        b.iter(|| black_box(cb.skip()));
    });
}

fn result(status: CheckStatus, error: Option<&str>) -> CheckResult {
    CheckResult {
        status,
        error: error.map(str::to_owned),
        ..CheckResult::error(Uuid::nil(), Uuid::nil(), "")
    }
}

fn bench_record_success(c: &mut Criterion) {
    let cb = CircuitBreaker::new(cfg());
    let up = result(CheckStatus::Up, None);
    c.bench_function("breaker_record_success", |b| {
        b.iter(|| cb.record(black_box(&up)));
    });
}

fn bench_record_failure(c: &mut Criterion) {
    let cb = CircuitBreaker::new(cfg());
    let timeout = result(CheckStatus::Error, Some("connect timeout"));
    c.bench_function("breaker_record_failure", |b| {
        b.iter(|| cb.record(black_box(&timeout)));
    });
}

criterion_group!(
    benches,
    bench_skip_closed,
    bench_record_success,
    bench_record_failure
);
criterion_main!(benches);
