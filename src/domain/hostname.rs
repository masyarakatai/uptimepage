//! Host names as a DNS lookup sees them.

use std::borrow::Cow;

const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Lower case, no port, no trailing dot, punycode, legal DNS labels. Run on
/// install and on lookup, so a stored domain cannot miss a request spelling it
/// another way.
pub fn normalize(host: &str) -> Option<Cow<'_, str>> {
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.len() > MAX_HOST_LEN {
        return None;
    }
    let ascii = if host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        Cow::Borrowed(host)
    } else {
        // UTS46 maps case as well as IDN, so this is also the uppercase path.
        Cow::Owned(idna::domain_to_ascii(host).ok()?)
    };

    has_legal_labels(&ascii).then_some(ascii)
}

/// `idna::domain_to_ascii` passes `a..b`, `-lead.test` and over-length labels,
/// and the fast path above never calls it at all. Migration 075 enforces the
/// same shape on the stored column.
fn has_legal_labels(host: &str) -> bool {
    let mut labels = 0;
    for label in host.split('.') {
        labels += 1;
        let legal = (1..=MAX_LABEL_LEN).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !legal {
            return false;
        }
    }
    labels >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_leaves_a_canonical_host_borrowed() {
        assert!(matches!(
            normalize("status.acme.test"),
            Some(Cow::Borrowed("status.acme.test"))
        ));
    }

    #[test]
    fn normalize_strips_port_case_and_the_fqdn_dot() {
        for host in [
            "Status.ACME.test",
            "status.acme.test:443",
            "status.acme.test.",
            "STATUS.acme.test.:8443",
        ] {
            assert_eq!(
                normalize(host).as_deref(),
                Some("status.acme.test"),
                "{host}"
            );
        }
    }

    #[test]
    fn normalize_punycodes_an_idn() {
        assert_eq!(
            normalize("stätus.acme.test").as_deref(),
            Some("xn--sttus-hra.acme.test")
        );
        assert_eq!(
            normalize("xn--sttus-hra.acme.test").as_deref(),
            Some("xn--sttus-hra.acme.test")
        );
    }

    #[test]
    fn normalize_refuses_what_is_not_a_domain() {
        for host in ["", "localhost", "status", ".", ":443", "[::1]:443"] {
            assert_eq!(normalize(host), None, "{host}");
        }
        assert_eq!(normalize(&format!("{}.test", "a".repeat(250))), None);
    }

    #[test]
    fn normalize_refuses_a_malformed_dns_name() {
        for host in [
            "status..customer.test",
            "-lead.customer.test",
            "trail-.customer.test",
            "status.customer.test-",
            ".customer.test",
            "status_page.customer.test",
            "STATUS_.customer.test",
        ] {
            assert_eq!(normalize(host), None, "{host}");
        }
        let long = format!("{}.customer.test", "a".repeat(64));
        assert_eq!(normalize(&long), None);
        let ok = format!("{}.customer.test", "a".repeat(63));
        assert!(normalize(&ok).is_some());
    }
}
