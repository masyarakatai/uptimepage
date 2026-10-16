//! The TCP check's failure text, which reaches the customer as their reason.

use crate::common;

use std::time::Duration;

use uptimepage::domain::{CheckStatus, TcpCheck};
use uptimepage::worker::tcp_check::execute_tcp_check;
use uuid::Uuid;

/// The raw `io::Error` reads "Connection refused (os error 61)" here and 111 on
/// Linux, so asserting the exact text is what pins the normalisation.
///
/// Port 1 rather than a bound-then-dropped ephemeral one: the ephemeral port is
/// unowned between the drop and the connect, so a concurrent bind takes it and
/// the connect succeeds instead of being refused. Nothing listens on tcpmux,
/// and reaching a privileged port needs no privilege.
#[tokio::test]
async fn a_refused_connection_reads_the_same_as_it_does_over_http() {
    let check = TcpCheck {
        host: "127.0.0.1".into(),
        port: 1,
        timeout: Duration::from_secs(3),
        ip_version: uptimepage::domain::IpVersion::Any,
    };

    let result =
        execute_tcp_check(Uuid::now_v7(), Uuid::nil(), &check, &common::test_client()).await;

    assert_eq!(result.status, CheckStatus::Down);
    let error = result.error.expect("a refused connect carries a reason");
    assert_eq!(error, "connection refused");
}

/// The DNS leg leaked the resolver's own Display, which prints the query it
/// failed as a brace-formatted struct: `no record found for Query { name:
/// nope.invalid., query_type: A, query_class: IN }`. No error class can name
/// that, so it reached the customer verbatim and counted as `Other`.
///
/// `.invalid` is reserved by RFC 2606 and never resolves, so this needs no
/// network to fail the way it must.
#[tokio::test]
async fn an_unresolvable_host_reads_as_dns_not_as_the_resolver_internals() {
    let check = TcpCheck {
        host: "nope.invalid".into(),
        port: 80,
        timeout: Duration::from_secs(5),
        ip_version: uptimepage::domain::IpVersion::Any,
    };

    let result =
        execute_tcp_check(Uuid::now_v7(), Uuid::nil(), &check, &common::test_client()).await;

    assert_eq!(result.status, CheckStatus::Down);
    let error = result.error.expect("a failed lookup carries a reason");
    assert!(
        error.starts_with("dns: "),
        "expected a dns reason, got {error:?}"
    );
    for leaked in ["Query {", "query_type", "query_class", "RecordType"] {
        assert!(
            !error.contains(leaked),
            "resolver internals reached the customer: {error:?}"
        );
    }

    // Unclassified reasons land in Other, which is what the leak did.
    use uptimepage::domain::check_error::{ErrorClass, classify_check_error};
    assert_ne!(classify_check_error(&error), ErrorClass::Other, "{error:?}");
}

/// A pinned family dials only its own addresses, and a name with none in it
/// fails naming the family rather than falling back to the other one.
#[tokio::test]
async fn a_pinned_family_never_falls_back_to_the_other_one() {
    use uptimepage::domain::IpVersion;
    use uptimepage::domain::check_error::{ErrorClass, classify_check_error};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let dns =
        common::spawn_mock_dns(&[("v4only.example.test", [127, 0, 0, 1].into(), 60)], false).await;
    let client = common::test_client_with_dns(dns.addr);
    let check = |host: &str, ip_version| TcpCheck {
        host: host.into(),
        port,
        timeout: Duration::from_secs(3),
        ip_version,
    };

    for (host, family) in [
        ("v4only.example.test", IpVersion::Any),
        ("v4only.example.test", IpVersion::Ipv4),
        ("127.0.0.1", IpVersion::Ipv4),
    ] {
        let result =
            execute_tcp_check(Uuid::now_v7(), Uuid::nil(), &check(host, family), &client).await;
        assert_eq!(
            result.status,
            CheckStatus::Up,
            "{host} {family:?}: {:?}",
            result.error
        );
    }

    for host in ["v4only.example.test", "127.0.0.1"] {
        let result = execute_tcp_check(
            Uuid::now_v7(),
            Uuid::nil(),
            &check(host, IpVersion::Ipv6),
            &client,
        )
        .await;
        assert_eq!(result.status, CheckStatus::Down, "{host}");
        let error = result.error.expect("a missing family carries a reason");
        assert_eq!(error, "dns: no IPv6 address", "{host}");
        assert_eq!(classify_check_error(&error), ErrorClass::DnsNoRecord);
    }
}
