//! Names the server behind an address for operator views.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::future::join_all;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{Name, RData};
use moka::Expiry;
use moka::future::Cache;

const LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);
const TTL: Duration = Duration::from_secs(3600);
const RETRY_AFTER: Duration = Duration::from_secs(300);
const CAPACITY: u64 = 10_000;
const CANDIDATES: usize = 3;

#[derive(Debug)]
pub struct LookupFailed;

#[async_trait]
pub trait Dns: Send + Sync {
    /// Empty when the address has no reverse name.
    async fn reverse(&self, ip: IpAddr) -> Result<Vec<Name>, LookupFailed>;
    /// Empty when the name has no address.
    async fn forward(&self, name: &Name) -> Result<Vec<IpAddr>, LookupFailed>;
}

#[async_trait]
impl Dns for TokioResolver {
    async fn reverse(&self, ip: IpAddr) -> Result<Vec<Name>, LookupFailed> {
        match self.reverse_lookup(Name::from(ip)).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::PTR(ptr) => Some(ptr.0.clone()),
                    _ => None,
                })
                .collect()),
            Err(e) if e.is_nx_domain() || e.is_no_records_found() => Ok(Vec::new()),
            Err(_) => Err(LookupFailed),
        }
    }

    async fn forward(&self, name: &Name) -> Result<Vec<IpAddr>, LookupFailed> {
        match self.lookup_ip(name.clone()).await {
            Ok(lookup) => Ok(lookup.iter().collect()),
            Err(e) if e.is_nx_domain() || e.is_no_records_found() => Ok(Vec::new()),
            Err(_) => Err(LookupFailed),
        }
    }
}

#[derive(Clone)]
enum Answer {
    Named(Arc<str>),
    Unnamed,
    Unknown,
}

/// A lookup that failed is kept briefly: long enough not to repeat it on every
/// page view, short enough that a resolver hiccup does not hide a name for the
/// whole TTL.
struct ByAnswer;

impl Expiry<IpAddr, Answer> for ByAnswer {
    fn expire_after_create(&self, _: &IpAddr, answer: &Answer, _: Instant) -> Option<Duration> {
        Some(match answer {
            Answer::Unknown => RETRY_AFTER,
            Answer::Named(_) | Answer::Unnamed => TTL,
        })
    }
}

pub struct ServerNames {
    dns: Arc<dyn Dns>,
    cache: Cache<IpAddr, Answer>,
}

impl ServerNames {
    pub fn new(dns: Arc<dyn Dns>) -> Self {
        Self {
            dns,
            cache: Cache::builder()
                .max_capacity(CAPACITY)
                .expire_after(ByAnswer)
                .build(),
        }
    }

    /// Verified names for the distinct addresses given, keyed as given. An
    /// address without one is absent from the map.
    pub async fn lookup(&self, ips: impl IntoIterator<Item = IpAddr>) -> HashMap<IpAddr, Arc<str>> {
        let distinct: HashSet<IpAddr> = ips.into_iter().collect();
        join_all(
            distinct.into_iter().map(|ip| async move {
                self.name_of(ip.to_canonical()).await.map(|name| (ip, name))
            }),
        )
        .await
        .into_iter()
        .flatten()
        .collect()
    }

    /// The lookup runs in its own task, which alone writes the cache: past the
    /// timeout the page renders without a name, the task finishes, and a slow
    /// reverse zone is named on a later view.
    async fn name_of(&self, ip: IpAddr) -> Option<Arc<str>> {
        let answer = match self.cache.get(&ip).await {
            Some(answer) => answer,
            None => {
                let dns = Arc::clone(&self.dns);
                let cache = self.cache.clone();
                let lookup = tokio::spawn(async move {
                    cache
                        .get_with(ip, async move { confirmed_name(dns.as_ref(), ip).await })
                        .await
                });
                tokio::time::timeout(LOOKUP_TIMEOUT, lookup)
                    .await
                    .ok()?
                    .ok()?
            }
        };
        match answer {
            Answer::Named(name) => Some(name),
            Answer::Unnamed | Answer::Unknown => None,
        }
    }
}

/// Whoever holds an address can publish any reverse name for it; only the
/// name's owner can point it back.
async fn confirmed_name(dns: &dyn Dns, ip: IpAddr) -> Answer {
    let Ok(names) = dns.reverse(ip).await else {
        return Answer::Unknown;
    };
    let mut forwards: FuturesUnordered<_> = names
        .iter()
        .take(CANDIDATES)
        .map(|name| async move { (name, dns.forward(name).await) })
        .collect();
    let mut unsure = false;
    while let Some((name, forward)) = forwards.next().await {
        match forward {
            Ok(addrs) if addrs.contains(&ip) => {
                return Answer::Named(name.to_ascii().trim_end_matches('.').into());
            }
            Ok(_) => {}
            Err(LookupFailed) => unsure = true,
        }
    }
    if unsure {
        Answer::Unknown
    } else {
        Answer::Unnamed
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct FakeDns {
        reverse: HashMap<IpAddr, Vec<&'static str>>,
        forward: HashMap<&'static str, Vec<IpAddr>>,
        failing: bool,
        failing_forward: Vec<&'static str>,
        slow: Option<Duration>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Dns for FakeDns {
        async fn reverse(&self, ip: IpAddr) -> Result<Vec<Name>, LookupFailed> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(delay) = self.slow {
                tokio::time::sleep(delay).await;
            }
            if self.failing {
                return Err(LookupFailed);
            }
            Ok(self
                .reverse
                .get(&ip)
                .into_iter()
                .flatten()
                .map(|n| Name::from_str(n).unwrap())
                .collect())
        }

        async fn forward(&self, name: &Name) -> Result<Vec<IpAddr>, LookupFailed> {
            if self.failing_forward.contains(&name.to_ascii().as_str()) {
                return Err(LookupFailed);
            }
            Ok(self
                .forward
                .get(name.to_ascii().as_str())
                .cloned()
                .unwrap_or_default())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn a_name_that_points_back_is_shown_without_the_root_dot() {
        let edge = ip("2001:db8::53");
        let dns = FakeDns {
            reverse: HashMap::from([(edge, vec!["edge.example.net."])]),
            forward: HashMap::from([("edge.example.net.", vec![edge])]),
            ..Default::default()
        };
        let names = ServerNames::new(Arc::new(dns)).lookup([edge]).await;
        assert_eq!(names.get(&edge).map(|n| &**n), Some("edge.example.net"));
    }

    #[tokio::test]
    async fn a_reverse_name_owned_by_someone_else_is_not_trusted() {
        let impostor = ip("203.0.113.9");
        let dns = FakeDns {
            reverse: HashMap::from([(impostor, vec!["web01.example.com."])]),
            forward: HashMap::from([("web01.example.com.", vec![ip("198.51.100.20")])]),
            ..Default::default()
        };
        let names = ServerNames::new(Arc::new(dns)).lookup([impostor]).await;
        assert!(names.is_empty(), "{names:?}");
    }

    #[tokio::test]
    async fn each_address_is_looked_up_once_and_then_served_from_cache() {
        let server = ip("198.51.100.20");
        let dns = Arc::new(FakeDns::default());
        let names = ServerNames::new(dns.clone());
        names.lookup([server, server, server]).await;
        names.lookup([server]).await;
        assert_eq!(dns.calls.load(Ordering::SeqCst), 1, "no name is cached too");
    }

    #[tokio::test]
    async fn a_failed_lookup_is_kept_only_for_the_retry_window() {
        let server = ip("198.51.100.20");
        let dns = Arc::new(FakeDns {
            failing: true,
            ..Default::default()
        });
        let names = ServerNames::new(dns.clone());
        assert!(names.lookup([server]).await.is_empty());
        names.lookup([server]).await;
        assert_eq!(dns.calls.load(Ordering::SeqCst), 1);

        let expiry = |answer| ByAnswer.expire_after_create(&server, &answer, Instant::now());
        assert_eq!(expiry(Answer::Unknown), Some(RETRY_AFTER));
        assert_eq!(expiry(Answer::Unnamed), Some(TTL));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_reverse_zone_is_named_on_a_later_view() {
        let edge = ip("2001:db8::53");
        let dns = FakeDns {
            reverse: HashMap::from([(edge, vec!["edge.example.net."])]),
            forward: HashMap::from([("edge.example.net.", vec![edge])]),
            slow: Some(LOOKUP_TIMEOUT * 2),
            ..Default::default()
        };
        let names = ServerNames::new(Arc::new(dns));
        assert!(
            names.lookup([edge]).await.is_empty(),
            "the page does not wait"
        );
        tokio::time::sleep(LOOKUP_TIMEOUT * 2).await;
        assert_eq!(
            names.lookup([edge]).await.get(&edge).map(|n| &**n),
            Some("edge.example.net")
        );
    }

    #[tokio::test]
    async fn an_ipv4_mapped_address_is_looked_up_as_ipv4_and_keyed_as_given() {
        let server = ip("198.51.100.20");
        let mapped = ip("::ffff:198.51.100.20");
        let dns = Arc::new(FakeDns {
            reverse: HashMap::from([(server, vec!["web01.example.com."])]),
            forward: HashMap::from([("web01.example.com.", vec![server])]),
            ..Default::default()
        });
        let names = ServerNames::new(dns.clone()).lookup([mapped, server]).await;
        assert_eq!(names.get(&mapped).map(|n| &**n), Some("web01.example.com"));
        assert_eq!(names.get(&server).map(|n| &**n), Some("web01.example.com"));
        assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_candidate_that_fails_to_resolve_does_not_hide_the_next_one() {
        let edge = ip("2001:db8::53");
        let dns = FakeDns {
            reverse: HashMap::from([(edge, vec!["broken.example.org.", "edge.example.net."])]),
            forward: HashMap::from([("edge.example.net.", vec![edge])]),
            failing_forward: vec!["broken.example.org."],
            ..Default::default()
        };
        let names = ServerNames::new(Arc::new(dns)).lookup([edge]).await;
        assert_eq!(names.get(&edge).map(|n| &**n), Some("edge.example.net"));
    }
}
