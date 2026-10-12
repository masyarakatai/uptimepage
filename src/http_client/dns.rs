use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, Record};
use hickory_resolver::{Resolver, TokioResolver};
use metrics::{Histogram, histogram};

use crate::config::DnsConfig;
use crate::domain::DnsAnswer;
use crate::error::Result;
use crate::metric_names;

pub struct HickoryDnsResolver {
    inner: Arc<TokioResolver>,
    fresh: Option<FreshAnswers>,
    dns_ms: Histogram,
}

impl HickoryDnsResolver {
    pub fn new(cfg: &DnsConfig) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = cfg.cache_size as u64;
        opts.positive_max_ttl = Some(Duration::from_secs(cfg.positive_ttl_secs));
        opts.negative_max_ttl = Some(Duration::from_secs(cfg.negative_ttl_secs));
        opts.attempts = 2;
        opts.timeout = Duration::from_secs(3);
        opts.try_tcp_on_error = true;

        let servers: Vec<SocketAddr> = cfg
            .servers
            .iter()
            .map(|s| parse_resolver_addr(s))
            .collect::<anyhow::Result<_>>()?;
        let fresh = servers
            .first()
            .copied()
            .map(FreshAnswers::new)
            .transpose()?;
        let name_servers = servers
            .into_iter()
            .map(|addr| {
                let mut udp = ConnectionConfig::udp();
                udp.port = addr.port();
                NameServerConfig::new(addr.ip(), true, vec![udp])
            })
            .collect();

        let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);

        let resolver =
            Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                .with_options(opts)
                .build()
                .context("failed to build hickory resolver")?;

        Ok(Self {
            inner: Arc::new(resolver),
            fresh,
            dns_ms: histogram!(metric_names::CHECK_DNS_MS),
        })
    }

    pub async fn resolve_addrs(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let start = Instant::now();
        let lookup: LookupIp = self.inner.lookup_ip(host).await?;
        self.dns_ms.record(start.elapsed().as_millis() as f64);
        Ok(lookup.iter().collect())
    }

    /// Asks the first configured server past this resolver's cache, which cuts
    /// every TTL down to its own cap. `None` when that server cannot answer
    /// within `budget`, and for a single-label name, which public DNS never
    /// serves. With no budget left the lookup still starts, so the next check
    /// of the host finds the answer held.
    pub async fn fresh_answer(&self, host: &str, budget: Duration) -> Option<DnsAnswer> {
        let fresh = self.fresh.as_ref()?;
        if !host.trim_end_matches('.').contains('.') {
            return None;
        }
        let query = {
            let fresh = fresh.clone();
            let host = host.to_owned();
            async move { fresh.query(&host).await }
        };
        fresh.get(host, budget, query).await
    }

    /// Underlying `hickory_resolver::TokioResolver`. Exposed so the DNS
    /// monitor probe can issue arbitrary-record-type queries through the
    /// same cached, shared resolver used for HTTP/TCP/TLS host lookups —
    /// no second connection pool, no second hosts file parse.
    pub fn inner(&self) -> &TokioResolver {
        &self.inner
    }
}

/// Short enough that an unreachable resolver cannot hold a failed check for
/// the rest of its timeout.
const FRESH_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const FRESH_HOLD: Duration = Duration::from_secs(60);
/// RFC 2181's ceiling. Hickory reads the bound through `u32` and silently falls
/// back to a day for anything larger, so a bigger "no limit" brings the cap back.
const MAX_DNS_TTL: Duration = Duration::from_secs(i32::MAX as u64);
/// A zero-TTL record would otherwise send every failing check to the resolver.
const FRESH_HOLD_FLOOR: Duration = Duration::from_secs(10);

type HeldAnswer = Option<(DnsAnswer, tokio::time::Instant)>;

/// Holds each host's answer for its TTL, between 10 s and a minute, so a
/// monitor that stays down sends one extra query per host per hold however
/// often it is checked. A failed query is held a minute: an unreachable
/// resolver then costs one timeout a minute rather than one per check.
#[derive(Clone)]
struct FreshAnswers {
    upstream: SocketAddr,
    resolver: TokioResolver,
    cache: moka::future::Cache<String, HeldAnswer>,
}

/// Never past the record's own TTL: during a move to a short TTL, the cache
/// would otherwise keep showing an answer the resolver itself has dropped.
struct HoldFor;

impl moka::Expiry<String, HeldAnswer> for HoldFor {
    fn expire_after_create(
        &self,
        _: &String,
        held: &HeldAnswer,
        _: std::time::Instant,
    ) -> Option<Duration> {
        Some(match held {
            Some((answer, _)) => {
                Duration::from_secs(answer.ttl_secs.into()).clamp(FRESH_HOLD_FLOOR, FRESH_HOLD)
            }
            None => FRESH_HOLD,
        })
    }
}

impl FreshAnswers {
    fn new(upstream: SocketAddr) -> anyhow::Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = FRESH_QUERY_TIMEOUT;
        opts.attempts = 1;
        opts.try_tcp_on_error = true;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.cache_size = 0;
        // Hickory clamps every answer's TTL even with no cache, to a day unless
        // told otherwise; the upstream's own TTL is the point of this lookup.
        opts.positive_max_ttl = Some(MAX_DNS_TTL);
        let config = single_server(upstream);
        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .context("failed to build uncached resolver")?;
        Ok(Self {
            upstream,
            resolver,
            cache: moka::future::Cache::builder()
                .max_capacity(10_000)
                .expire_after(HoldFor)
                .build(),
        })
    }

    async fn query(&self, host: &str) -> Option<DnsAnswer> {
        let lookup = self.resolver.lookup_ip(host).await.ok()?;
        Some(DnsAnswer {
            resolver: self.upstream.ip(),
            addresses: lookup.iter().collect(),
            ttl_secs: owner_ttl(lookup.as_lookup().answers(), host)?,
        })
    }

    /// The lookup fills the cache from its own task, so a check out of budget
    /// stops waiting without cancelling it: the answer, or the failure, is
    /// still held for the checks that follow.
    async fn get(
        &self,
        host: &str,
        budget: Duration,
        query: impl Future<Output = Option<DnsAnswer>> + Send + 'static,
    ) -> Option<DnsAnswer> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let held = match self.cache.get(&key).await {
            Some(held) => held,
            None => {
                let cache = self.cache.clone();
                let fill = tokio::spawn(async move {
                    let held = async {
                        query
                            .await
                            .map(|answer| (answer, tokio::time::Instant::now()))
                    };
                    cache.get_with(key, held).await
                });
                tokio::time::timeout(budget, fill).await.ok()?.ok()?
            }
        };
        let (mut answer, at) = held?;
        let age = u32::try_from(at.elapsed().as_secs()).unwrap_or(u32::MAX);
        answer.ttl_secs = answer.ttl_secs.saturating_sub(age);
        Some(answer)
    }
}

/// Shortest TTL among the records for `host` itself, ahead of any alias it
/// points to: that record is what changes when a hostname moves, and a
/// dual-stack host can hold its A and AAAA records for different times.
fn owner_ttl(records: &[Record], host: &str) -> Option<u32> {
    let mut owner = Name::from_str_relaxed(host).ok()?;
    owner.set_fqdn(true);
    records
        .iter()
        .filter(|r| r.name == owner)
        .map(|r| r.ttl)
        .min()
}

/// Build a one-shot resolver pointed at a single `ip` or `ip:port`
/// nameserver, with the given query timeout. Used by the DNS monitor
/// probe when the check specifies a custom resolver — bypasses the
/// shared system resolver so the probe measures *that* resolver's view.
pub fn build_single_resolver(addr: &str, timeout: Duration) -> anyhow::Result<TokioResolver> {
    let cfg = single_server(parse_resolver_addr(addr)?);
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 1;
    opts.try_tcp_on_error = true;
    Resolver::builder_with_config(cfg, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .context("failed to build single-server resolver")
}

fn single_server(sock: SocketAddr) -> ResolverConfig {
    let mut udp = ConnectionConfig::udp();
    let mut tcp = ConnectionConfig::tcp();
    udp.port = sock.port();
    tcp.port = sock.port();
    let ns = NameServerConfig::new(sock.ip(), true, vec![udp, tcp]);
    ResolverConfig::from_parts(None, vec![], vec![ns])
}

/// `"1.1.1.1"` / `"1.1.1.1:53"` / `"[::1]:53"` → `SocketAddr` (port 53
/// default). Shared with the API validator so what passes validation
/// is *exactly* what the probe will pass to the resolver.
pub fn parse_resolver_addr(s: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(sock) = s.parse::<SocketAddr>() {
        return Ok(sock);
    }
    let ip: IpAddr = s
        .parse()
        .with_context(|| format!("invalid resolver address: {s}"))?;
    Ok(SocketAddr::new(ip, 53))
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::rr::RData;
    use hickory_resolver::proto::rr::rdata::{A, CNAME};

    use moka::Expiry;

    use super::*;

    fn answer(ttl_secs: u32) -> DnsAnswer {
        DnsAnswer {
            resolver: "192.0.2.53".parse().unwrap(),
            addresses: vec!["192.0.2.1".parse().unwrap()],
            ttl_secs,
        }
    }

    fn fresh() -> FreshAnswers {
        FreshAnswers::new("192.0.2.53:53".parse().unwrap()).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_outlives_the_budget_still_fills_the_cache() {
        let fresh = fresh();
        let slow = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some(answer(600))
        };
        assert_eq!(
            fresh
                .get("example.com", Duration::from_millis(100), slow)
                .await,
            None
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let unused = async { None };
        assert!(
            fresh
                .get("example.com", Duration::from_secs(1), unused)
                .await
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_host_is_asked_once_and_its_ttl_keeps_counting_down() {
        let fresh = fresh();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let query = || {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(answer(2340))
            }
        };
        let budget = Duration::from_secs(1);

        assert_eq!(
            fresh.get("Example.com.", budget, query()).await,
            Some(answer(2340))
        );
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(
            fresh.get("example.com", budget, query()).await,
            Some(answer(2310))
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_with_no_budget_left_still_starts_the_lookup() {
        let fresh = fresh();
        let quick = async { Some(answer(600)) };
        assert_eq!(fresh.get("example.com", Duration::ZERO, quick).await, None);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let unused = async { None };
        assert!(
            fresh
                .get("example.com", Duration::from_secs(1), unused)
                .await
                .is_some(),
            "the next check finds it held"
        );
    }

    #[tokio::test]
    async fn a_lookup_that_found_nothing_is_held_too() {
        let fresh = fresh();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let query = || {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            }
        };
        let budget = Duration::from_secs(1);
        assert_eq!(fresh.get("example.com", budget, query()).await, None);
        assert_eq!(fresh.get("example.com", budget, query()).await, None);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn an_answer_is_never_held_past_its_own_ttl() {
        let now = tokio::time::Instant::now();
        let hold = |held: HeldAnswer| {
            HoldFor.expire_after_create(&String::new(), &held, std::time::Instant::now())
        };
        assert_eq!(hold(Some((answer(30), now))), Some(Duration::from_secs(30)));
        assert_eq!(hold(Some((answer(0), now))), Some(FRESH_HOLD_FLOOR));
        assert_eq!(hold(Some((answer(3600), now))), Some(FRESH_HOLD));
        assert_eq!(hold(None), Some(FRESH_HOLD));
    }

    #[tokio::test]
    async fn ipv6_servers_are_accepted_with_or_without_a_port() {
        let cfg = DnsConfig {
            cache_size: 16,
            positive_ttl_secs: 300,
            negative_ttl_secs: 60,
            servers: vec![
                "2001:db8::53".into(),
                "[2001:db8::54]:53".into(),
                "192.0.2.53:53".into(),
            ],
        };
        let resolver = HickoryDnsResolver::new(&cfg).unwrap();
        let fresh = resolver.fresh.expect("first server answers fresh lookups");
        assert_eq!(
            fresh.upstream,
            "[2001:db8::53]:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn the_ttl_is_the_queried_names_own_not_its_alias_target() {
        let name = |s: &str| Name::from_str_relaxed(s).unwrap();
        let records = [
            Record::from_rdata(
                name("www.example.com."),
                2340,
                RData::CNAME(CNAME(name("edge.example.net."))),
            ),
            Record::from_rdata(
                name("edge.example.net."),
                60,
                RData::A(A::new(192, 0, 2, 1)),
            ),
        ];
        assert_eq!(owner_ttl(&records, "WWW.example.com"), Some(2340));
        assert_eq!(owner_ttl(&records, "other.example.com"), None);
    }

    #[test]
    fn a_dual_stack_host_reports_its_shorter_lived_family() {
        use hickory_resolver::proto::rr::rdata::AAAA;
        let host = Name::from_str_relaxed("app.example.com.").unwrap();
        let records = [
            Record::from_rdata(
                host.clone(),
                600,
                RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53)),
            ),
            Record::from_rdata(host, 30, RData::A(A::new(192, 0, 2, 1))),
        ];
        assert_eq!(owner_ttl(&records, "app.example.com"), Some(30));
    }
}
