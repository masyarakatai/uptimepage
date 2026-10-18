use std::collections::BTreeMap;
use std::time::Instant;

use chrono::Utc;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{Name, Record};
use tokio::time::timeout;
use uuid::Uuid;

use crate::domain::dns_record::{ExpectedRecord, expected_record, mx_host_key, record_key};
use crate::domain::{CheckDetails, CheckResult, CheckStatus, DnsCheck, DnsDetails, DnsRecordType};
use crate::http_client::{HttpClients, build_single_resolver};

pub async fn execute_dns_check(
    target_id: Uuid,
    org_id: Uuid,
    check: &DnsCheck,
    clients: &HttpClients,
) -> CheckResult {
    let started_at = Utc::now();
    let start = Instant::now();

    let outcome = timeout(check.timeout, run_check(check, clients)).await;
    let duration_ms = start.elapsed().as_millis() as u32;

    match outcome {
        Ok(Ok(verdict)) => CheckResult {
            dns_ms: Some(duration_ms.min(u16::MAX as u32) as u16),
            ..CheckResult::graded(
                target_id,
                org_id,
                started_at,
                duration_ms,
                verdict.status,
                verdict.details,
            )
        },
        Ok(Err(err)) => CheckResult {
            target_id,
            org_id,
            timestamp: started_at,
            status: CheckStatus::Down,
            duration_ms,
            dns_ms: None,
            connect_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            response_code: None,
            response_size: None,
            network: None,
            diagnostic: None,
            error: Some(err.to_string()),
            details: None,
        },
        Err(_) => {
            CheckResult::error_with_elapsed(target_id, org_id, started_at, duration_ms, "timeout")
        }
    }
}

#[derive(Debug)]
pub struct DnsVerdict {
    pub status: CheckStatus,
    pub details: CheckDetails,
}

async fn run_check(check: &DnsCheck, clients: &HttpClients) -> anyhow::Result<DnsVerdict> {
    // Custom-resolver path rebuilds a single-server resolver on every
    // tick *by design*: a check pointed at `1.1.1.1` must measure that
    // server's view, not the shared cache's. Don't "optimise" by
    // caching — it silently masks the failure modes the check exists to
    // detect.
    let owned_resolver;
    let resolver: &TokioResolver = match &check.resolver {
        Some(addr) => {
            owned_resolver = build_single_resolver(addr, check.timeout)?;
            &owned_resolver
        }
        None => clients.resolver().inner(),
    };

    let name = query_name(check)?;
    let lookup = match resolver.lookup(name, check.record_type.wire()).await {
        Ok(l) => l,
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => {
            return Ok(classify(check, &[]));
        }
        Err(e) => return Err(e.into()),
    };
    Ok(classify(check, lookup.answers()))
}

// A PTR check on an address queries its in-addr.arpa / ip6.arpa name. UTF-8
// parsing applies STD3 per label and refuses an underscore inside one
// (`foo_bar`); the relaxed parse falls back to plain ASCII for those.
fn query_name(check: &DnsCheck) -> anyhow::Result<Name> {
    if check.record_type == DnsRecordType::Ptr
        && let Some(ip) = check.address()
    {
        return Ok(Name::from(ip));
    }
    Ok(Name::from_str_relaxed(&check.domain)?)
}

// `records` is the whole answer section. Records of the queried type are the
// answers; the CNAME chain that led to them is shown apart as aliases, so the
// answers can be copied into an exact set as they are.
fn classify(check: &DnsCheck, records: &[Record]) -> DnsVerdict {
    let queried = check.record_type.wire();
    let (mut own, chain): (Vec<&Record>, Vec<&Record>) =
        records.iter().partition(|r| r.record_type() == queried);
    // A resolver rotates its answers. Sorted, every rotation stores one
    // reading, and regions that got the same set read alike. The chain keeps
    // its order: it is the path the name took.
    own.sort_by_cached_key(|r| r.data.to_string());
    let shown = |rs: &[&Record]| rs.iter().map(|r| r.data.to_string()).collect::<Vec<_>>();
    let (answers, aliases) = (shown(&own), shown(&chain));
    let diff = check
        .exact_records()
        .map(|expected| SetDiff::of(check.record_type, expected, &own, &answers));
    let matched: Option<bool> = match &diff {
        Some(d) => Some(d.missing.is_empty() && d.unexpected.is_empty()),
        None => check
            .contains_needle()
            .map(|needle| answers.iter().chain(&aliases).any(|a| a.contains(needle))),
    };

    // Empty answers = NXDOMAIN-equivalent. Mismatched answers = the resolver
    // returned the wrong record (BGP hijack, registrar takeover, regional
    // misroute) — user explicitly opted into strict matching, so a sustained
    // mismatch is a real outage signal.
    let status = if records.is_empty() || matches!(matched, Some(false)) {
        CheckStatus::Down
    } else {
        CheckStatus::Up
    };

    let (missing, unexpected) = diff.map(|d| (d.missing, d.unexpected)).unzip();
    DnsVerdict {
        status,
        details: CheckDetails::Dns(DnsDetails {
            domain: check.domain.clone(),
            record_type: check.record_type,
            missing,
            unexpected,
            answers,
            aliases,
            expected_contains: check.expected_contains.clone(),
            matched,
        }),
    }
}

/// Expected records no answer carries, and answers nothing expected, each in
/// the first spelling its own list gives it.
struct SetDiff {
    missing: Vec<String>,
    unexpected: Vec<String>,
}

impl SetDiff {
    // `answers` is `own` as displayed, one for one.
    fn of<'a>(
        record_type: DnsRecordType,
        expected: &'a [String],
        own: &[&Record],
        answers: &'a [String],
    ) -> Self {
        let want = first_spelling(
            expected
                .iter()
                .map(|v| (expected_record(record_type, v), v)),
        );
        // Each distinct answer once, with the host a bare MX value claims it by.
        let mut got = BTreeMap::new();
        for (r, shown) in own.iter().zip(answers) {
            got.entry(record_key(&r.data))
                .or_insert_with(|| (shown.as_str(), mx_host_key(&r.data)));
        }
        // Every value claims one answer. Whole values go first, so a bare
        // host cannot take the answer a pinned one needs. A bare host takes its
        // lowest preference, the record most likely to have been there.
        let (whole, bare): (Vec<_>, Vec<_>) = want
            .iter()
            .partition(|(value, _)| matches!(value, ExpectedRecord::Whole(_)));
        let mut missing = Vec::new();
        for (value, shown) in whole.into_iter().chain(bare) {
            let claim = match value {
                ExpectedRecord::Whole(key) => got.contains_key(key).then(|| key.clone()),
                ExpectedRecord::MxHost(host) => got
                    .iter()
                    .filter_map(|(key, (_, mx))| {
                        mx.as_ref()
                            .filter(|(h, _)| h == host)
                            .map(|(_, preference)| (preference, key))
                    })
                    .min()
                    .map(|(_, key)| key.clone()),
            };
            match claim {
                Some(key) => {
                    got.remove(&key);
                }
                None => missing.push((*shown).to_owned()),
            }
        }
        Self {
            missing,
            unexpected: got
                .into_values()
                .map(|(shown, _)| shown.to_owned())
                .collect(),
        }
    }
}

fn first_spelling<'a, K: Ord>(
    keyed: impl Iterator<Item = (K, &'a String)>,
) -> BTreeMap<K, &'a str> {
    let mut out = BTreeMap::new();
    for (key, value) in keyed {
        out.entry(key).or_insert(value.as_str());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn check(expected: Option<&str>) -> DnsCheck {
        DnsCheck {
            expected_contains: expected.map(str::to_string),
            ..lookup("example.com", DnsRecordType::A)
        }
    }

    fn lookup(domain: &str, record_type: DnsRecordType) -> DnsCheck {
        DnsCheck {
            domain: domain.into(),
            record_type,
            resolver: None,
            expected_contains: None,
            expected_records: None,
            timeout: Duration::from_secs(3),
        }
    }

    fn exact(record_type: DnsRecordType, expected: &[&str]) -> DnsCheck {
        DnsCheck {
            expected_records: Some(expected.iter().map(|s| s.to_string()).collect()),
            ..lookup("example.com", record_type)
        }
    }

    fn records(record_type: DnsRecordType, values: &[&str]) -> Vec<Record> {
        values
            .iter()
            .map(|v| {
                let rdata = crate::domain::dns_record::parse_expected(record_type, v).unwrap();
                Record::from_rdata(Name::root(), 300, rdata)
            })
            .collect()
    }

    fn judge(check: &DnsCheck, answers: &[&str]) -> DnsVerdict {
        classify(check, &records(check.record_type, answers))
    }

    fn details(v: &DnsVerdict) -> serde_json::Value {
        serde_json::from_str(&v.details.error_json()).unwrap()
    }

    #[test]
    fn underscore_names_parse_as_relative_query_names() {
        for domain in ["_dmarc.example.com", "foo_bar.example.com", "example.com"] {
            let name = query_name(&lookup(domain, DnsRecordType::Txt)).unwrap();
            assert_eq!(name.to_ascii(), domain);
            assert!(!name.is_fqdn(), "{domain} became absolute");
        }
        let idn = query_name(&lookup("bähn.de", DnsRecordType::A)).unwrap();
        assert_eq!(idn.to_ascii(), "xn--bhn-qla.de");
    }

    #[test]
    fn wildcard_name_queries_the_wildcard_owner() {
        let name = query_name(&lookup("*.example.com", DnsRecordType::A)).unwrap();
        assert!(name.is_wildcard());
        assert_eq!(name.to_ascii(), "*.example.com");
    }

    #[test]
    fn ptr_on_an_address_queries_its_reverse_name() {
        let name = |domain| {
            query_name(&lookup(domain, DnsRecordType::Ptr))
                .unwrap()
                .to_ascii()
        };
        assert_eq!(name("192.0.2.1"), "1.2.0.192.in-addr.arpa.");
        assert_eq!(
            name("2001:db8::1"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
        assert_eq!(name("::ffff:192.0.2.1"), "1.2.0.192.in-addr.arpa.");
        assert_eq!(name("1.2.0.192.in-addr.arpa"), "1.2.0.192.in-addr.arpa");
    }

    #[test]
    fn empty_answers_are_down() {
        let v = judge(&check(None), &[]);
        assert_eq!(v.status, CheckStatus::Down);
    }

    #[test]
    fn answers_without_expectation_are_up() {
        let v = judge(&check(None), &["192.0.2.1"]);
        assert_eq!(v.status, CheckStatus::Up);
    }

    #[test]
    fn matching_substring_is_up() {
        let v = judge(&check(Some("192.0.2.1")), &["192.0.2.1"]);
        assert_eq!(v.status, CheckStatus::Up);
    }

    #[test]
    fn mismatched_substring_is_down() {
        let v = judge(&check(Some("203.0.113.7")), &["192.0.2.1"]);
        assert_eq!(v.status, CheckStatus::Down);
    }

    #[test]
    fn empty_expected_string_is_ignored() {
        let v = judge(&check(Some("")), &["192.0.2.1"]);
        assert_eq!(v.status, CheckStatus::Up);
    }

    #[test]
    fn details_matched_is_null_when_no_expectation() {
        let v = judge(&check(None), &[]);
        assert!(
            v.details.error_json().contains("\"matched\":null"),
            "got: {}",
            v.details.error_json()
        );
    }

    #[test]
    fn details_matched_is_true_when_substring_present() {
        let v = judge(&check(Some("192.0.2.1")), &["192.0.2.1"]);
        assert!(
            v.details.error_json().contains("\"matched\":true"),
            "got: {}",
            v.details.error_json()
        );
    }

    #[test]
    fn details_matched_is_false_when_substring_absent() {
        let v = judge(&check(Some("203.0.113.7")), &["192.0.2.1"]);
        assert!(
            v.details.error_json().contains("\"matched\":false"),
            "got: {}",
            v.details.error_json()
        );
    }

    #[test]
    fn exact_set_ignores_order_duplicates_case_and_trailing_dot() {
        let check = exact(
            DnsRecordType::Mx,
            &[
                "20 ALT.example.com",
                "10 mail.example.com.",
                "10 mail.example.com",
            ],
        );
        let v = judge(&check, &["10 mail.example.com.", "20 alt.example.com."]);
        assert_eq!(v.status, CheckStatus::Up);
        let d = details(&v);
        assert_eq!(d["matched"], true);
        assert_eq!(d["missing"], serde_json::json!([]));
        assert_eq!(d["unexpected"], serde_json::json!([]));
    }

    #[test]
    fn exact_set_fails_on_an_added_record() {
        let v = judge(
            &exact(DnsRecordType::Ns, &["ns1.example.net."]),
            &["ns1.example.net.", "ns.attacker.example."],
        );
        assert_eq!(v.status, CheckStatus::Down);
        let d = details(&v);
        assert_eq!(d["matched"], false);
        assert_eq!(d["missing"], serde_json::json!([]));
        assert_eq!(d["unexpected"], serde_json::json!(["ns.attacker.example."]));
    }

    #[test]
    fn exact_set_fails_on_a_removed_record() {
        let v = judge(
            &exact(DnsRecordType::A, &["192.0.2.1", "192.0.2.2"]),
            &["192.0.2.1"],
        );
        assert_eq!(v.status, CheckStatus::Down);
        assert_eq!(details(&v)["missing"], serde_json::json!(["192.0.2.2"]));
    }

    #[test]
    fn exact_set_names_both_sides_of_a_changed_record() {
        let v = judge(
            &exact(
                DnsRecordType::Txt,
                &["v=spf1 include:_spf.example.com ~all"],
            ),
            &["v=spf1 include:_spf.example.com include:evil.example ~all"],
        );
        assert_eq!(v.status, CheckStatus::Down);
        let d = details(&v);
        assert_eq!(
            d["missing"],
            serde_json::json!(["v=spf1 include:_spf.example.com ~all"])
        );
        assert_eq!(
            d["unexpected"],
            serde_json::json!(["v=spf1 include:_spf.example.com include:evil.example ~all"])
        );
    }

    #[test]
    fn a_bare_mx_host_matches_it_at_any_preference() {
        let check = exact(
            DnsRecordType::Mx,
            &["smtp.google.com", "5 backup.example.com"],
        );
        for answers in [
            &["1 smtp.google.com.", "5 backup.example.com."][..],
            &["30 SMTP.google.com", "5 backup.example.com."][..],
        ] {
            assert_eq!(
                judge(&check, answers).status,
                CheckStatus::Up,
                "{answers:?}"
            );
        }

        let v = judge(
            &check,
            &[
                "1 smtp.google.com.",
                "7 backup.example.com.",
                "0 mx.attacker.example.",
            ],
        );
        assert_eq!(v.status, CheckStatus::Down);
        let d = details(&v);
        assert_eq!(d["missing"], serde_json::json!(["5 backup.example.com"]));
        assert_eq!(
            d["unexpected"],
            serde_json::json!(["0 mx.attacker.example.", "7 backup.example.com."])
        );

        let v = judge(&check, &["5 backup.example.com."]);
        assert_eq!(v.status, CheckStatus::Down);
        assert_eq!(
            details(&v)["missing"],
            serde_json::json!(["smtp.google.com"])
        );
    }

    #[test]
    fn a_bare_mx_host_stands_for_one_record() {
        let bare = exact(DnsRecordType::Mx, &["smtp.google.com"]);
        for (answers, extra) in [
            (
                ["1 smtp.google.com.", "50 smtp.google.com."],
                "50 smtp.google.com.",
            ),
            (
                ["10 smtp.google.com.", "5 smtp.google.com."],
                "10 smtp.google.com.",
            ),
        ] {
            let v = judge(&bare, &answers);
            assert_eq!(v.status, CheckStatus::Down);
            assert_eq!(details(&v)["unexpected"], serde_json::json!([extra]));
        }

        let both = exact(
            DnsRecordType::Mx,
            &["mail.example.com", "10 mail.example.com"],
        );
        assert_eq!(
            judge(&both, &["20 mail.example.com.", "10 mail.example.com."]).status,
            CheckStatus::Up
        );
        let v = judge(&both, &["10 mail.example.com."]);
        assert_eq!(v.status, CheckStatus::Down);
        assert_eq!(
            details(&v)["missing"],
            serde_json::json!(["mail.example.com"])
        );
    }

    #[test]
    fn exact_set_compares_addresses_by_value() {
        let v = judge(
            &exact(DnsRecordType::Aaaa, &["2001:0DB8:0:0::1"]),
            &["2001:db8::1"],
        );
        assert_eq!(v.status, CheckStatus::Up);
    }

    #[test]
    fn exact_set_keeps_txt_case() {
        let v = judge(
            &exact(DnsRecordType::Txt, &["v=DMARC1; p=reject"]),
            &["v=DMARC1; p=Reject"],
        );
        assert_eq!(v.status, CheckStatus::Down);
    }

    #[test]
    fn exact_set_against_no_answer_misses_everything() {
        let v = judge(&exact(DnsRecordType::A, &["192.0.2.1"]), &[]);
        assert_eq!(v.status, CheckStatus::Down);
        assert_eq!(details(&v)["missing"], serde_json::json!(["192.0.2.1"]));
    }

    #[test]
    fn empty_exact_set_is_no_expectation() {
        let v = judge(&exact(DnsRecordType::A, &[]), &["192.0.2.1"]);
        assert_eq!(v.status, CheckStatus::Up);
        let d = details(&v);
        assert_eq!(d["matched"], serde_json::Value::Null);
        assert!(d.get("missing").is_none());
    }

    #[test]
    fn substring_details_carry_no_set_diff() {
        let v = judge(&check(Some("192.0.2.1")), &["192.0.2.1"]);
        assert_eq!(
            v.details.error_json(),
            r#"{"domain":"example.com","record_type":"A","answers":["192.0.2.1"],"expected_contains":"192.0.2.1","matched":true}"#
        );
    }

    #[test]
    fn an_empty_answer_documents_no_records() {
        let v = judge(&check(None), &[]);
        assert_eq!(v.status, CheckStatus::Down);
        assert_eq!(
            v.details.error_json(),
            r#"{"domain":"example.com","record_type":"A","answers":[],"expected_contains":null,"matched":null}"#
        );
    }

    #[test]
    fn a_missed_substring_documents_the_answers() {
        let v = judge(&check(Some("203.0.113.7")), &["192.0.2.1"]);
        assert_eq!(v.status, CheckStatus::Down);
        assert_eq!(
            v.details.error_json(),
            r#"{"domain":"example.com","record_type":"A","answers":["192.0.2.1"],"expected_contains":"203.0.113.7","matched":false}"#
        );
    }

    #[test]
    fn the_set_diff_leads_the_details() {
        let v = judge(&exact(DnsRecordType::A, &["192.0.2.1"]), &["192.0.2.9"]);
        assert_eq!(
            v.details.error_json(),
            r#"{"domain":"example.com","record_type":"A","missing":["192.0.2.1"],"unexpected":["192.0.2.9"],"answers":["192.0.2.9"],"expected_contains":null,"matched":false}"#
        );
    }

    #[test]
    fn answers_are_sorted_whatever_order_they_arrive_in() {
        let check = exact(DnsRecordType::A, &["192.0.2.1"]);
        let first = judge(&check, &["192.0.2.9", "192.0.2.1", "192.0.2.5"]);
        let rotated = judge(&check, &["192.0.2.5", "192.0.2.9", "192.0.2.1"]);
        assert_eq!(first.details, rotated.details);
        let d = details(&first);
        assert_eq!(
            d["answers"],
            serde_json::json!(["192.0.2.1", "192.0.2.5", "192.0.2.9"])
        );
        assert_eq!(d["missing"], serde_json::json!([]));
        assert_eq!(
            d["unexpected"],
            serde_json::json!(["192.0.2.5", "192.0.2.9"])
        );
    }

    #[test]
    fn exact_set_leaves_the_cname_chain_out() {
        let mut chain = records(DnsRecordType::Cname, &["edge.cdn.example.net."]);
        chain.extend(records(DnsRecordType::A, &["192.0.2.1"]));
        let v = classify(&exact(DnsRecordType::A, &["192.0.2.1"]), &chain);
        assert_eq!(v.status, CheckStatus::Up);
        let d = details(&v);
        assert_eq!(d["answers"], serde_json::json!(["192.0.2.1"]));
        assert_eq!(d["aliases"], serde_json::json!(["edge.cdn.example.net."]));
    }

    #[test]
    fn a_substring_still_matches_the_cname_chain() {
        let mut chain = records(DnsRecordType::Cname, &["edge.cdn.example.net."]);
        chain.extend(records(DnsRecordType::A, &["192.0.2.1"]));
        let v = classify(&check(Some("edge.cdn")), &chain);
        assert_eq!(v.status, CheckStatus::Up);
    }

    #[test]
    fn exact_set_reads_zone_file_spellings() {
        let v = judge(
            &exact(DnsRecordType::Txt, &[r#""v=DKIM1; k=rsa; " "p=MIIBIjAN""#]),
            &["v=DKIM1; k=rsa; p=MIIBIjAN"],
        );
        assert_eq!(v.status, CheckStatus::Up);
        let v = judge(
            &exact(DnsRecordType::Mx, &["010 xn--mller-kva.de."]),
            &["10 müller.de."],
        );
        assert_eq!(v.status, CheckStatus::Up);
    }

    #[test]
    fn exact_set_ignores_whitespace_around_txt() {
        let v = judge(
            &exact(DnsRecordType::Txt, &["v=spf1 -all\r"]),
            &["v=spf1 -all"],
        );
        assert_eq!(v.status, CheckStatus::Up);
    }
}
