//! DNS record values as an exact record set compares them.

use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_resolver::proto::rr::{Name, RData, RecordType};

use super::DnsRecordType;

impl DnsRecordType {
    pub fn wire(self) -> RecordType {
        match self {
            DnsRecordType::A => RecordType::A,
            DnsRecordType::Aaaa => RecordType::AAAA,
            DnsRecordType::Cname => RecordType::CNAME,
            DnsRecordType::Mx => RecordType::MX,
            DnsRecordType::Ns => RecordType::NS,
            DnsRecordType::Txt => RecordType::TXT,
            DnsRecordType::Soa => RecordType::SOA,
            DnsRecordType::Ptr => RecordType::PTR,
            DnsRecordType::Caa => RecordType::CAA,
            DnsRecordType::Srv => RecordType::SRV,
        }
    }

    /// A value in the form answers display, for an error that asks for one.
    pub fn example_record(self) -> &'static str {
        match self {
            DnsRecordType::A => "192.0.2.1",
            DnsRecordType::Aaaa => "2001:db8::1",
            DnsRecordType::Cname | DnsRecordType::Ns | DnsRecordType::Ptr => "host.example.com.",
            DnsRecordType::Mx => "10 mail.example.com.",
            DnsRecordType::Txt => "v=spf1 -all",
            DnsRecordType::Soa => {
                "ns1.example.com. hostmaster.example.com. 2026101201 7200 3600 1209600 3600"
            }
            DnsRecordType::Caa => "0 issue \"letsencrypt.org\"",
            DnsRecordType::Srv => "10 5 5060 sip.example.com.",
        }
    }
}

/// Reads an expected value written as a result's answers show it, or in
/// zone-file form (`"v=spf1 -all"`, `010 xn--mller-kva.de.`). Every field is
/// required and nothing may follow the last. Names take underscores anywhere,
/// as answers carry them. Unquoted TXT is taken whole: answers show it
/// unquoted, its strings joined. `None` when the value is not in the type's
/// form.
pub fn parse_expected(record_type: DnsRecordType, value: &str) -> Option<RData> {
    let value = value.trim();
    let fields: Vec<&str> = value.split_whitespace().collect();
    let name = |s: &str| Name::from_str_relaxed(s).ok();
    let short = |s: &str| s.parse::<u16>().ok();
    let rdata = match (record_type, fields.as_slice()) {
        (DnsRecordType::A, [ip]) => RData::A(A(ip.parse().ok()?)),
        (DnsRecordType::Aaaa, [ip]) => RData::AAAA(AAAA(ip.parse().ok()?)),
        (DnsRecordType::Cname, [n]) => RData::CNAME(CNAME(name(n)?)),
        (DnsRecordType::Ns, [n]) => RData::NS(NS(name(n)?)),
        (DnsRecordType::Ptr, [n]) => RData::PTR(PTR(name(n)?)),
        (DnsRecordType::Mx, [preference, n]) => RData::MX(MX::new(short(preference)?, name(n)?)),
        (DnsRecordType::Srv, [priority, weight, port, n]) => RData::SRV(SRV::new(
            short(priority)?,
            short(weight)?,
            short(port)?,
            name(n)?,
        )),
        (DnsRecordType::Soa, [mname, rname, serial, refresh, retry, expire, minimum]) => {
            RData::SOA(SOA::new(
                name(mname)?,
                name(rname)?,
                serial.parse().ok()?,
                refresh.parse().ok()?,
                retry.parse().ok()?,
                expire.parse().ok()?,
                minimum.parse().ok()?,
            ))
        }
        (DnsRecordType::Caa, _) => RData::try_from_str(RecordType::CAA, value).ok()?,
        (DnsRecordType::Txt, _) if value.starts_with('"') => {
            RData::try_from_str(RecordType::TXT, value).ok()?
        }
        (DnsRecordType::Txt, _) => RData::TXT(TXT::new(vec![value.to_owned()])),
        _ => return None,
    };
    Some(rdata)
}

/// The spelling two equal records share. TXT and CAA keep their text and case:
/// a CAA value can carry a case-sensitive account URI. The rest is shown from
/// parsed values, so `010`, `2001:0db8::1` and an `xn--` label each fold to
/// one spelling, then names drop case and the trailing dot.
pub fn record_key(rdata: &RData) -> String {
    let shown = rdata.to_string();
    match rdata {
        RData::TXT(_) | RData::CAA(_) => shown.trim().to_owned(),
        _ => shown
            .split_whitespace()
            .map(fold_token)
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// One value of an exact set, as answers are matched against it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExpectedRecord {
    /// A whole record, by its [`record_key`].
    Whole(String),
    /// One MX record for this host, at any preference, by its folded name.
    MxHost(String),
}

/// What an expected value matches. `None` when it is in neither form.
pub fn parse_expected_record(record_type: DnsRecordType, value: &str) -> Option<ExpectedRecord> {
    if let Some(rdata) = parse_expected(record_type, value) {
        return Some(ExpectedRecord::Whole(record_key(&rdata)));
    }
    bare_mx_host(record_type, value)
        .map(|host| ExpectedRecord::MxHost(fold_token(&host.to_string())))
}

/// [`parse_expected_record`] of a stored value; one that does not parse keeps
/// its own trimmed text and so matches nothing.
pub fn expected_record(record_type: DnsRecordType, value: &str) -> ExpectedRecord {
    parse_expected_record(record_type, value)
        .unwrap_or_else(|| ExpectedRecord::Whole(value.trim().to_owned()))
}

/// An MX answer's folded host, which a bare MX value claims it by, and its
/// preference.
pub fn mx_host_key(rdata: &RData) -> Option<(String, u16)> {
    match rdata {
        RData::MX(mx) => Some((fold_token(&mx.exchange.to_string()), mx.preference)),
        _ => None,
    }
}

// A lone number or IPv4 address has no letter, and an IPv6 address fails the
// name parse on its colons: either would be a host that never answers.
fn bare_mx_host(record_type: DnsRecordType, value: &str) -> Option<Name> {
    let value = value.trim();
    if record_type != DnsRecordType::Mx
        || value.contains(char::is_whitespace)
        || !value.chars().any(char::is_alphabetic)
    {
        return None;
    }
    Name::from_str_relaxed(value).ok()
}

fn fold_token(token: &str) -> String {
    token.strip_suffix('.').unwrap_or(token).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_mx_host_folds_like_the_answer_it_names() {
        let answer = |value: &str| {
            mx_host_key(&parse_expected(DnsRecordType::Mx, value).unwrap())
                .unwrap()
                .0
        };
        for (bare, answered) in [
            ("Smtp.Google.com.", "1 smtp.google.com."),
            ("пошта.укр", "10 xn--80a1acn3a.xn--j1amh."),
        ] {
            assert_eq!(
                parse_expected_record(DnsRecordType::Mx, bare),
                Some(ExpectedRecord::MxHost(answer(answered))),
                "{bare:?}"
            );
        }
        for refused in [
            "10",
            "192.0.2.10",
            "2001:db8::1",
            "::1",
            "mail..example.com",
        ] {
            assert_eq!(
                parse_expected_record(DnsRecordType::Mx, refused),
                None,
                "{refused:?}"
            );
        }
        assert_eq!(parse_expected_record(DnsRecordType::Ns, "a b"), None);
    }

    fn key(record_type: DnsRecordType, value: &str) -> String {
        record_key(&parse_expected(record_type, value).unwrap())
    }

    #[test]
    fn spellings_of_one_record_share_a_key() {
        for (record_type, a, b) in [
            (
                DnsRecordType::Mx,
                "10 Mail.Example.com",
                "10 mail.example.com.",
            ),
            (
                DnsRecordType::Mx,
                "010 mail.example.com.",
                "10 mail.example.com.",
            ),
            (DnsRecordType::Mx, "10 xn--mller-kva.de.", "10 müller.de."),
            (DnsRecordType::Aaaa, "2001:0DB8:0:0::1", "2001:db8::1"),
            (
                DnsRecordType::Srv,
                "10 5 05060 sip.example.com",
                "10 5 5060 sip.example.com.",
            ),
            (DnsRecordType::Txt, "\"v=spf1 \" \"-all\"", "v=spf1 -all"),
            (DnsRecordType::Txt, "  v=spf1 -all\r", "v=spf1 -all"),
            (
                DnsRecordType::Mx,
                "10 MX_backup.example.com",
                "10 mx_backup.example.com.",
            ),
            (
                DnsRecordType::Caa,
                "0  issue   \"letsencrypt.org\"",
                "0 issue \"letsencrypt.org\"",
            ),
        ] {
            assert_eq!(key(record_type, a), key(record_type, b), "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn caa_keeps_the_case_of_its_value() {
        let k = |v| key(DnsRecordType::Caa, v);
        assert_ne!(
            k("0 issue \"letsencrypt.org; accounturi=https://acme.example/acct/AbC\""),
            k("0 issue \"letsencrypt.org; accounturi=https://acme.example/acct/abc\"")
        );
    }

    #[test]
    fn txt_keeps_its_case_and_inner_spacing() {
        let k = |v| key(DnsRecordType::Txt, v);
        assert_ne!(k("v=DMARC1; p=reject"), k("v=DMARC1; p=Reject"));
        assert_eq!(
            k("v=spf1 include:_spf.example.com ~all"),
            "v=spf1 include:_spf.example.com ~all"
        );
    }

    #[test]
    fn values_the_type_never_answers_with_do_not_parse() {
        for (record_type, value) in [
            (DnsRecordType::A, "2001:db8::1"),
            (DnsRecordType::A, "mail.example.com"),
            (DnsRecordType::Aaaa, "192.0.2.1"),
            (DnsRecordType::Mx, "mail.example.com."),
            (DnsRecordType::Mx, "70000 mail.example.com."),
            (DnsRecordType::Srv, "5060 sip.example.com."),
            (DnsRecordType::Caa, "issue letsencrypt.org"),
            (DnsRecordType::A, "192.0.2.1 192.0.2.2"),
            (DnsRecordType::A, "192.0.2.1 primary"),
            (
                DnsRecordType::Mx,
                "10 mail.example.com. 20 alt.example.com.",
            ),
            (DnsRecordType::Cname, "edge.example.net. extra"),
            (
                DnsRecordType::Soa,
                "ns1.example.com. hostmaster.example.com. 1",
            ),
        ] {
            assert!(
                parse_expected(record_type, value).is_none(),
                "{value:?} parsed as {record_type:?}"
            );
        }
    }

    #[test]
    fn every_example_parses_as_its_type() {
        for record_type in [
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Cname,
            DnsRecordType::Mx,
            DnsRecordType::Ns,
            DnsRecordType::Txt,
            DnsRecordType::Soa,
            DnsRecordType::Ptr,
            DnsRecordType::Caa,
            DnsRecordType::Srv,
        ] {
            assert!(parse_expected(record_type, record_type.example_record()).is_some());
        }
    }
}
