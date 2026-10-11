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
            .map(|token| token.strip_suffix('.').unwrap_or(token).to_lowercase())
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// [`record_key`] of an expected value; one that does not parse keeps its
/// own trimmed text and so matches nothing.
pub fn expected_key(record_type: DnsRecordType, value: &str) -> String {
    parse_expected(record_type, value)
        .map(|rdata| record_key(&rdata))
        .unwrap_or_else(|| value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

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
