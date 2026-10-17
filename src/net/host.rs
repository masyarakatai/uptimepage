//! Host-name canonical forms shared by the check path and the ingest boundary.

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

/// Canonical host key: IDN-encoded + ASCII-lowercased + trailing dot stripped.
/// Infallible — falls back to ASCII-lowercase when IDN encoding fails, so the
/// worker hot path never panics on unexpected input.
///
/// Used by:
/// - per-(org, host, port) throttle key.
/// - per-TLD RDAP throttle (`rdap_tld`).
/// - cross-tenant RDAP singleflight cache key.
///
/// Use [`canonical_host_strict`] at the API ingest boundary to reject malformed
/// IDN with a 400 instead of silently falling back.
pub fn canonical_host(host: &str) -> String {
    let trimmed = host.trim_end_matches('.');
    idna::domain_to_ascii(trimmed).unwrap_or_else(|_| trimmed.to_ascii_lowercase())
}

/// Strict variant of [`canonical_host`] for use at the API ingest boundary.
/// Uses UTS46 with UseSTD3ASCIIRules, so leading/trailing hyphens, embedded
/// underscores, and other malformed IDN are rejected with a 400 instead of
/// silently stored.
pub fn canonical_host_strict(host: &str) -> Result<String, idna::Errors> {
    strict_to_ascii(host, AsciiDenyList::STD3)
}

/// [`canonical_host_strict`] with `_` allowed, for DNS query names: `_dmarc`,
/// `s1._domainkey` and `_sip._tcp` are ordinary owner names but not hostnames.
pub fn canonical_dns_name(name: &str) -> Result<String, idna::Errors> {
    const STD3_WITH_UNDERSCORE: AsciiDenyList =
        AsciiDenyList::new(true, "!\"#$%&'()*+,/:;<=>?@[\\]^`{|}~");
    strict_to_ascii(name, STD3_WITH_UNDERSCORE)
}

fn strict_to_ascii(name: &str, deny: AsciiDenyList) -> Result<String, idna::Errors> {
    Uts46::new()
        .to_ascii(
            name.trim_end_matches('.').as_bytes(),
            deny,
            Hyphens::Check,
            DnsLength::Verify,
        )
        .map(|cow| cow.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_normalization_collapses_trailing_dot_and_case() {
        assert_eq!(canonical_host("Example.COM."), "example.com");
        assert_eq!(canonical_host("example.com"), "example.com");
    }

    #[test]
    fn host_normalization_idn_round_trips_to_punycode() {
        let punycode = "xn--bhn-qla.de";
        assert_eq!(canonical_host("Bähn.de"), punycode);
        assert_eq!(canonical_host("BÄHN.de"), punycode);
        assert_eq!(canonical_host("bähn.de."), punycode);
        assert_eq!(canonical_host("xn--bhn-qla.de"), punycode);
    }

    #[test]
    fn canonical_host_strict_rejects_bad_idn() {
        assert!(canonical_host_strict("--invalid-leading.com").is_err());
    }

    #[test]
    fn dns_name_differs_from_strict_only_by_underscore() {
        assert!(canonical_host_strict("_dmarc.example.com").is_err());
        assert_eq!(
            canonical_dns_name("_dmarc.example.com").unwrap(),
            "_dmarc.example.com"
        );
        for b in (0u8..=0x7f).filter(|&b| b != b'_') {
            let name = format!("a{}b.example.com", b as char);
            assert_eq!(
                canonical_dns_name(&name).ok(),
                canonical_host_strict(&name).ok(),
                "byte {b:#04x}"
            );
        }
    }
}
