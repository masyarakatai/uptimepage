//! The network path a failed HTTP check carries, end to end against loopback
//! DNS and HTTP servers.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::StatusCode;
use axum::http::header::LOCATION;
use axum::routing::get;
use uptimepage::domain::{CheckResult, CheckStatus, DnsAnswer, ExpectedStatus, HttpCheck};
use uptimepage::http_client::HttpClients;
use uptimepage::worker::execute_http_check;
use url::Url;
use uuid::Uuid;

use crate::common::{
    MockDns, default_http_check, spawn_mock_dns, spawn_mock_dns_with_aliases, spawn_router,
    test_client, test_client_with_dns,
};

const HOST: &str = "app.example.test";
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn http_check(url: &str) -> HttpCheck {
    default_http_check(Url::parse(url).unwrap(), ExpectedStatus::Exact(200))
}

async fn run(check: &HttpCheck, client: &HttpClients) -> CheckResult {
    execute_http_check(Uuid::now_v7(), Uuid::nil(), check, client).await
}

async fn answering(status: StatusCode) -> std::net::SocketAddr {
    spawn_router(Router::new().route("/", get(move || async move { status }))).await
}

#[tokio::test]
async fn a_down_check_reports_the_resolvers_own_ttl_not_the_probes_capped_one() {
    let dns = spawn_mock_dns(&[(HOST, Ipv4Addr::LOCALHOST, 2340)], false).await;
    let addr = answering(StatusCode::NOT_FOUND).await;
    let client = test_client_with_dns(dns.addr);

    let result = run(
        &http_check(&format!("http://{HOST}:{}/", addr.port())),
        &client,
    )
    .await;

    assert_eq!(result.status, CheckStatus::Down);
    let network = result.network.expect("network path");
    assert_eq!(network.remote_ip, Some(LOOPBACK));
    assert_eq!(
        network.dns,
        Some(DnsAnswer {
            resolver: dns.addr.ip(),
            addresses: vec![LOOPBACK],
            ttl_secs: 2340,
        }),
        "the probe's own cache caps TTLs at 30 s in tests"
    );
}

/// A down check of `host` against `dns`, and the fresh DNS answer it carries.
async fn down_dns_answer(dns: &MockDns, host: &str) -> DnsAnswer {
    let addr = answering(StatusCode::NOT_FOUND).await;
    let client = test_client_with_dns(dns.addr);
    let result = run(
        &http_check(&format!("http://{host}:{}/", addr.port())),
        &client,
    )
    .await;
    assert_eq!(result.status, CheckStatus::Down);
    result.network.and_then(|n| n.dns).expect("dns answer")
}

const TWO_DAYS: u32 = 172_800;

#[tokio::test]
async fn a_ttl_longer_than_a_day_comes_through_whole() {
    let dns = spawn_mock_dns(&[(HOST, Ipv4Addr::LOCALHOST, TWO_DAYS)], false).await;
    let answer = down_dns_answer(&dns, HOST).await;
    assert!(
        (TWO_DAYS..=TWO_DAYS + 2).contains(&answer.ttl_secs),
        "{}",
        answer.ttl_secs
    );
}

/// What changes when a hostname moves is its alias, so its TTL is the one
/// reported, whole, not the target's or a day-capped one.
#[tokio::test]
async fn an_alias_reports_its_own_ttl_from_a_full_chain_answer() {
    let dns = spawn_mock_dns_with_aliases(
        &[(HOST, Ipv4Addr::LOCALHOST, 60)],
        &[("www.example.test", HOST, TWO_DAYS)],
        false,
    )
    .await;
    let answer = down_dns_answer(&dns, "www.example.test").await;
    assert_eq!(answer.addresses, vec![LOOPBACK]);
    assert!(
        (TWO_DAYS..=TWO_DAYS + 2).contains(&answer.ttl_secs),
        "{}",
        answer.ttl_secs
    );
}

#[tokio::test]
async fn only_a_failed_check_asks_dns_again_and_a_host_is_asked_once() {
    let up_dns = spawn_mock_dns(&[(HOST, Ipv4Addr::LOCALHOST, 600)], false).await;
    let up = answering(StatusCode::OK).await;
    let up_result = run(
        &http_check(&format!("http://{HOST}:{}/", up.port())),
        &test_client_with_dns(up_dns.addr),
    )
    .await;
    assert_eq!(up_result.status, CheckStatus::Up);
    assert!(up_result.network.is_none());
    let probe_queries = up_dns.queries();
    assert!(probe_queries > 0);

    let down_dns = spawn_mock_dns(&[(HOST, Ipv4Addr::LOCALHOST, 600)], false).await;
    let down = answering(StatusCode::NOT_FOUND).await;
    let client = test_client_with_dns(down_dns.addr);
    let check = http_check(&format!("http://{HOST}:{}/", down.port()));

    run(&check, &client).await;
    assert_eq!(
        down_dns.queries(),
        2 * probe_queries,
        "one lookup for the probe, one past its cache"
    );
    run(&check, &client).await;
    assert_eq!(
        down_dns.queries(),
        2 * probe_queries,
        "both answers are still held for the next check"
    );
}

#[tokio::test]
async fn a_resolver_that_never_answers_reads_as_a_dns_timeout() {
    let dns = spawn_mock_dns(&[], true).await;
    let mut check = http_check(&format!("http://{HOST}:9/"));
    check.timeout = Duration::from_millis(300);

    let client = test_client_with_dns(dns.addr);
    let started = Instant::now();
    let result = run(&check, &client).await;

    assert_eq!(result.error.as_deref(), Some("dns: lookup timed out"));
    assert_eq!(result.dns_ms, None);
    assert!(result.network.is_none(), "nothing was reached or answered");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the extra lookup stays inside the check's own timeout: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_degraded_check_names_its_server_without_asking_dns_again() {
    let dns = spawn_mock_dns(&[(HOST, Ipv4Addr::LOCALHOST, 600)], false).await;
    let addr = answering(StatusCode::SERVICE_UNAVAILABLE).await;

    let result = run(
        &http_check(&format!("http://{HOST}:{}/", addr.port())),
        &test_client_with_dns(dns.addr),
    )
    .await;

    assert_eq!(result.status, CheckStatus::Degraded);
    let network = result.network.expect("network path");
    assert_eq!(network.remote_ip, Some(LOOPBACK));
    assert_eq!(network.dns, None);
}

#[tokio::test]
async fn a_connect_failure_after_a_redirect_names_that_hop_and_what_it_tried() {
    let app = Router::new().route(
        "/",
        get(|| async { (StatusCode::FOUND, [(LOCATION, "http://127.0.0.1:1/next")]) }),
    );
    let addr = spawn_router(app).await;
    let mut check = http_check(&format!("http://{addr}/"));
    check.follow_redirects = true;
    check.max_redirects = 5;

    let result = run(&check, &test_client()).await;

    assert_eq!(result.status, CheckStatus::Error);
    let network = result.network.expect("network path");
    assert_eq!(network.hop_url.as_deref(), Some("http://127.0.0.1:1/next"));
    assert_eq!(network.tried_ips, vec![LOOPBACK]);
    assert_eq!(
        network.remote_ip, None,
        "the first hop's server did not decide this result"
    );
}
