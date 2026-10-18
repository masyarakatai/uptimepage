use chrono::{DateTime, Duration, Utc};

use crate::app::AppState;
use crate::domain::{
    CheckDetails, CheckResult, CheckSpec, CheckStatus, Expiry, NO_COMMON_NAME, expiry,
};
use crate::domain::{OrgId, Target};
use crate::storage::{ClampedRange, TimeRange};

/// How far back the card looks past two intervals, so a paused monitor
/// still shows what it last read. Covers the week a domain check serves a
/// cached answer, whose last real lookup is the reading worth showing.
const LOOKBACK_DAYS: i64 = 7;

/// Past these, groups and the records in one group fold behind a toggle: a
/// CDN answering differently in every region, or a TXT name with a long
/// list, would otherwise push the rest of the page down.
const GROUPS_SHOWN: usize = 3;
pub(super) const CHIPS_SHOWN: usize = 6;
/// Names a group spells out before it counts the rest.
const NAMES_SHOWN: usize = 3;

/// What the newest run in each region read. Regions that read the same thing
/// fold into one group.
pub struct CheckFacts {
    pub kind: FactsKind,
    /// Worst verdict first, then the soonest to expire, then the group with
    /// the most regions.
    pub groups: Vec<FactsGroup>,
    /// The newest reading among the groups.
    pub checked_at: DateTime<Utc>,
    /// Each region's stored reading, as the results API returns it.
    pub raw: Vec<RawReading>,
}

pub struct RawReading {
    pub region: String,
    pub json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactsKind {
    Cert,
    Dns,
    Domain,
}

pub struct FactsGroup {
    pub regions: Vec<String>,
    pub checked_at: DateTime<Utc>,
    /// Worst verdict among the group's regions.
    pub status: CheckStatus,
    /// Whole days until the certificate or registration runs out, floored
    /// so a few hours past expiry reads as expired.
    pub days_left: Option<i64>,
    pub facts: Facts,
}

/// Compared to fold regions together, so it leaves out what differs only by
/// when the region looked: `days_remaining`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Facts {
    Cert(CertFacts),
    Dns(DnsFacts),
    Domain(DomainFacts),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFacts {
    pub not_after: DateTime<Utc>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsFacts {
    pub record_type: &'static str,
    pub domain: String,
    /// The answers, each one the expected set lacks flagged, then the
    /// expected values no answer carried.
    pub chips: Vec<RecordChip>,
    pub aliases: Vec<String>,
    /// The substring no answer carried.
    pub unmatched: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordChip {
    pub value: String,
    pub kind: ChipKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipKind {
    Answer,
    Unexpected,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainFacts {
    pub domain: String,
    pub expires_at: DateTime<Utc>,
    pub registrar: Option<String>,
}

impl Facts {
    pub fn cert(&self) -> Option<&CertFacts> {
        match self {
            Self::Cert(f) => Some(f),
            _ => None,
        }
    }

    pub fn dns(&self) -> Option<&DnsFacts> {
        match self {
            Self::Dns(f) => Some(f),
            _ => None,
        }
    }

    pub fn domain(&self) -> Option<&DomainFacts> {
        match self {
            Self::Domain(f) => Some(f),
            _ => None,
        }
    }

    pub fn expires_at(&self) -> Option<&DateTime<Utc>> {
        match self {
            Self::Cert(f) => Some(&f.not_after),
            Self::Domain(f) => Some(&f.expires_at),
            Self::Dns(_) => None,
        }
    }
}

impl From<CheckDetails> for Facts {
    fn from(details: CheckDetails) -> Self {
        let named = |cn: String| (cn != NO_COMMON_NAME).then_some(cn);
        match details {
            CheckDetails::TlsCert(d) => Self::Cert(CertFacts {
                not_after: d.not_after,
                subject: named(d.subject_common_name),
                issuer: named(d.issuer_common_name),
            }),
            CheckDetails::Dns(d) => {
                let unmatched = d
                    .expected_contains
                    .filter(|_| d.matched == Some(false) && d.missing.is_none());
                let unexpected = d.unexpected.unwrap_or_default();
                let answers = d.answers.into_iter().map(|value| {
                    let kind = if unexpected.contains(&value) {
                        ChipKind::Unexpected
                    } else {
                        ChipKind::Answer
                    };
                    RecordChip { value, kind }
                });
                let missing = d
                    .missing
                    .unwrap_or_default()
                    .into_iter()
                    .map(|value| RecordChip {
                        value,
                        kind: ChipKind::Missing,
                    });
                Self::Dns(DnsFacts {
                    record_type: d.record_type.as_str(),
                    domain: d.domain,
                    chips: answers.chain(missing).collect(),
                    aliases: d.aliases,
                    unmatched,
                })
            }
            CheckDetails::DomainExpiry(d) => Self::Domain(DomainFacts {
                domain: d.domain,
                expires_at: d.expiration_date,
                registrar: d.registrar,
            }),
        }
    }
}

impl CertFacts {
    pub fn subject_name(&self) -> &str {
        self.subject.as_deref().unwrap_or("no common name")
    }

    pub fn issuer_name(&self) -> &str {
        self.issuer
            .as_deref()
            .unwrap_or("an issuer with no common name")
    }
}

impl DomainFacts {
    pub fn registrar_name(&self) -> &str {
        self.registrar
            .as_deref()
            .unwrap_or("no registrar published")
    }
}

impl FactsKind {
    pub fn title(self) -> &'static str {
        match self {
            Self::Cert => "Certificate",
            Self::Dns => "Records",
            Self::Domain => "Registration",
        }
    }

    /// What regions that disagree saw several of.
    pub fn readings(self) -> &'static str {
        match self {
            Self::Cert => "certificates",
            Self::Dns => "answer sets",
            Self::Domain => "registrations",
        }
    }
}

/// The CNAME chain is left out, so regions that reach the same answers
/// through different edges read alike.
impl PartialEq for DnsFacts {
    fn eq(&self, other: &Self) -> bool {
        (self.record_type, &self.domain, &self.chips, &self.unmatched)
            == (
                other.record_type,
                &other.domain,
                &other.chips,
                &other.unmatched,
            )
    }
}

impl Eq for DnsFacts {}

/// The substring a DNS check looked for, and how many regions lacked it.
pub struct Lacking<'a> {
    pub want: &'a str,
    pub regions: usize,
    pub everywhere: bool,
}

impl DnsFacts {
    /// Records the name answered with, leaving out the ones it lacked.
    pub fn record_count(&self) -> usize {
        self.chips
            .iter()
            .filter(|c| c.kind != ChipKind::Missing)
            .count()
    }

    /// The answer is not the expected set.
    pub fn off_set(&self) -> bool {
        self.chips.iter().any(|c| c.kind != ChipKind::Answer)
    }

    pub fn shown_chips(&self) -> &[RecordChip] {
        &self.chips[..self.chips.len().min(CHIPS_SHOWN)]
    }

    pub fn more_chips(&self) -> &[RecordChip] {
        &self.chips[self.chips.len().min(CHIPS_SHOWN)..]
    }

    /// The expected values no answer carried, then the answers the expected
    /// set lacks.
    pub fn diff(&self) -> Vec<&RecordChip> {
        let of = |kind| self.chips.iter().filter(move |c| c.kind == kind);
        of(ChipKind::Missing)
            .chain(of(ChipKind::Unexpected))
            .collect()
    }
}

impl RecordChip {
    /// A diff sign, so the kind reads without its colour.
    pub fn marker(&self) -> &'static str {
        match self.kind {
            ChipKind::Answer => "",
            ChipKind::Unexpected => "+",
            ChipKind::Missing => "−",
        }
    }

    pub fn class(&self) -> &'static str {
        match self.kind {
            ChipKind::Answer => "",
            ChipKind::Unexpected => "record-chip--unexpected",
            ChipKind::Missing => "record-chip--missing",
        }
    }

    pub fn title(&self) -> &'static str {
        match self.kind {
            ChipKind::Answer => "",
            ChipKind::Unexpected => "answered, but not in the expected set",
            ChipKind::Missing => "expected, but not answered",
        }
    }
}

impl FactsGroup {
    /// The group's own region, or how many it holds.
    pub fn label(&self) -> String {
        match self.regions.as_slice() {
            [one] => one.clone(),
            many => format!("{} regions", many.len()),
        }
    }

    /// `eu-central, eu-north, us-east +4`.
    pub fn names(&self) -> String {
        let shown = self.regions[..self.regions.len().min(NAMES_SHOWN)].join(", ");
        match self.regions.len().saturating_sub(NAMES_SHOWN) {
            0 => shown,
            rest => format!("{shown} +{rest}"),
        }
    }

    /// Unique among the groups, for a toggle that must survive the live poll.
    pub fn chips_id(&self) -> String {
        format!("check-facts-chips-{}", self.regions[0])
    }

    pub fn countdown(&self) -> Option<Expiry> {
        self.days_left.map(expiry)
    }

    /// Colour for the number that decided the verdict.
    pub fn value_tone(&self) -> &'static str {
        match self.status {
            CheckStatus::Down => "dashboard-kpi-card__value--bad",
            CheckStatus::Degraded => "dashboard-kpi-card__value--warn",
            CheckStatus::Up | CheckStatus::Error => "",
        }
    }

    /// Colour for the group's name where the verdict is not up.
    pub fn label_tone(&self) -> &'static str {
        match self.status {
            CheckStatus::Down => "text-state-bad",
            CheckStatus::Degraded => "text-state-warn",
            CheckStatus::Up | CheckStatus::Error => "",
        }
    }
}

impl CheckFacts {
    pub fn region_count(&self) -> usize {
        self.groups.iter().map(|g| g.regions.len()).sum()
    }

    /// More than one region reported, so each group names its own.
    pub fn show_regions(&self) -> bool {
        self.region_count() > 1
    }

    /// What the second group read that the first did not, for the card the
    /// first fills: `elsewhere example.com by R3`.
    pub fn elsewhere(&self) -> Option<String> {
        let (top, next) = (self.groups.first()?, self.groups.get(1)?);
        match (&top.facts, &next.facts) {
            (Facts::Cert(a), Facts::Cert(b)) => {
                let subject = (a.subject != b.subject).then(|| match &b.subject {
                    Some(subject) => subject.clone(),
                    None => format!("a certificate with {}", b.subject_name()),
                });
                let issuer = (a.issuer != b.issuer).then(|| format!("by {}", b.issuer_name()));
                let parts: Vec<String> = subject.into_iter().chain(issuer).collect();
                (!parts.is_empty()).then(|| format!("elsewhere {}", parts.join(" ")))
            }
            (Facts::Domain(a), Facts::Domain(b)) if a.registrar != b.registrar => {
                Some(format!("elsewhere {}", b.registrar_name()))
            }
            _ => None,
        }
    }

    pub fn shown_groups(&self) -> &[FactsGroup] {
        &self.groups[..self.groups.len().min(GROUPS_SHOWN)]
    }

    pub fn more_groups(&self) -> &[FactsGroup] {
        &self.groups[self.groups.len().min(GROUPS_SHOWN)..]
    }

    pub fn more_group_regions(&self) -> usize {
        self.more_groups().iter().map(|g| g.regions.len()).sum()
    }

    pub fn lacking(&self) -> Option<Lacking<'_>> {
        let want = self
            .groups
            .iter()
            .find_map(|g| g.facts.dns()?.unmatched.as_deref())?;
        let regions = self
            .groups
            .iter()
            .filter(|g| g.facts.dns().is_some_and(|d| d.unmatched.is_some()))
            .map(|g| g.regions.len())
            .sum();
        Some(Lacking {
            want,
            regions,
            everywhere: regions == self.region_count(),
        })
    }

    /// Some region's answer is not the expected set.
    pub fn off_set(&self) -> bool {
        self.groups
            .iter()
            .any(|g| g.facts.dns().is_some_and(DnsFacts::off_set))
    }

    /// A region the monitor no longer runs in is left out; one that runs
    /// but keeps failing to read anything keeps its last reading. An empty
    /// `assigned` leaves every region in.
    pub fn fold(
        kind: FactsKind,
        rows: Vec<(String, CheckResult)>,
        now: DateTime<Utc>,
        assigned: &[String],
    ) -> Self {
        let current = rows
            .into_iter()
            .filter(|(region, _)| assigned.is_empty() || assigned.contains(region));
        let mut groups: Vec<FactsGroup> = Vec::new();
        let mut raw = Vec::new();
        for (region, result) in current {
            let Some(details) = result.details else {
                continue;
            };
            raw.push(RawReading {
                region: region.clone(),
                json: details.pretty_json(),
            });
            let facts = Facts::from(details);
            match groups.iter_mut().find(|g| g.facts == facts) {
                Some(group) => {
                    group.regions.push(region);
                    group.checked_at = group.checked_at.max(result.timestamp);
                    if result.status.severity_rank() > group.status.severity_rank() {
                        group.status = result.status;
                    }
                }
                None => groups.push(FactsGroup {
                    regions: vec![region],
                    checked_at: result.timestamp,
                    status: result.status,
                    days_left: facts
                        .expires_at()
                        .map(|at| (*at - now).num_seconds().div_euclid(86_400)),
                    facts,
                }),
            }
        }
        groups.sort_by(|a, b| {
            b.status
                .severity_rank()
                .cmp(&a.status.severity_rank())
                .then(a.days_left.cmp(&b.days_left))
                .then(b.regions.len().cmp(&a.regions.len()))
        });
        let checked_at = groups
            .iter()
            .map(|g| g.checked_at)
            .max()
            .unwrap_or_default();
        Self {
            kind,
            groups,
            checked_at,
            raw,
        }
    }
}

/// `None` for kinds that read nothing worth a card, and when the read fails:
/// the card is one panel on a page with more to show.
pub(super) async fn load(
    state: &AppState,
    org: OrgId,
    target: &Target,
    region: Option<&str>,
) -> Option<CheckFacts> {
    let kind = match target.check {
        CheckSpec::TlsCert(_) => FactsKind::Cert,
        CheckSpec::Dns(_) => FactsKind::Dns,
        CheckSpec::DomainExpiry(_) => FactsKind::Domain,
        _ => return None,
    };
    let now = Utc::now();
    let lookback =
        Duration::from_std(target.interval * 2).unwrap_or_default() + Duration::days(LOOKBACK_DAYS);
    // A probe clock a little ahead of ours must not hide its newest run.
    let range = ClampedRange::unclamped(TimeRange {
        from: now - lookback,
        to: now + Duration::minutes(5),
    });
    let (rows, assigned) = tokio::join!(
        state
            .results_store
            .latest_details_by_region(org, target.id, range, region),
        state.target_store.regions_for_target(org, target.id),
    );
    let rows = rows
        .map_err(|err| tracing::warn!(error = %err, "check facts card unavailable"))
        .ok()?;
    let assigned = assigned
        .map_err(|err| tracing::warn!(error = %err, "check facts regions unavailable"))
        .ok()?
        .unwrap_or_default();
    let rows = rows
        .into_iter()
        .filter(|(_, result)| {
            result
                .details
                .as_ref()
                .is_some_and(|details| reads_current(&target.check, details))
        })
        .collect();
    Some(CheckFacts::fold(kind, rows, now, &assigned))
}

/// A reading taken before the name, record type or expected substring was
/// edited answers another question. A region that keeps failing the new one
/// would show it forever, so it goes. A certificate reading names no host,
/// and a DNS reading keeps no expected set, so those cannot be told apart.
fn reads_current(check: &CheckSpec, details: &CheckDetails) -> bool {
    match (check, details) {
        (CheckSpec::Dns(c), CheckDetails::Dns(d)) => {
            d.domain == c.domain
                && d.record_type == c.record_type
                && d.expected_contains == c.expected_contains
        }
        (CheckSpec::DomainExpiry(c), CheckDetails::DomainExpiry(d)) => d.domain == c.domain,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use uuid::Uuid;

    use super::*;
    use crate::domain::{DnsDetails, DnsRecordType, TlsCertDetails};

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 19, hour, 0, 0).unwrap()
    }

    fn row(
        region: &str,
        hour: u32,
        status: CheckStatus,
        details: CheckDetails,
    ) -> (String, CheckResult) {
        let result = CheckResult::graded(Uuid::nil(), Uuid::nil(), at(hour), 5, status, details);
        (region.to_string(), result)
    }

    fn cert(days_remaining: i64, subject: &str) -> CheckDetails {
        CheckDetails::TlsCert(TlsCertDetails {
            days_remaining,
            not_after: Utc.with_ymd_and_hms(2027, 1, 12, 10, 0, 0).unwrap(),
            subject_common_name: subject.into(),
            issuer_common_name: "R11".into(),
        })
    }

    fn a_records(answers: &[&str]) -> CheckDetails {
        CheckDetails::Dns(DnsDetails {
            domain: "example.com".into(),
            record_type: DnsRecordType::A,
            missing: None,
            unexpected: None,
            answers: answers.iter().map(|a| a.to_string()).collect(),
            aliases: Vec::new(),
            expected_contains: None,
            matched: None,
        })
    }

    fn fold(kind: FactsKind, rows: Vec<(String, CheckResult)>) -> CheckFacts {
        CheckFacts::fold(kind, rows, at(12), &[])
    }

    #[test]
    fn regions_that_read_the_same_certificate_fold_into_one() {
        let rows = vec![
            row("eu-central", 9, CheckStatus::Up, cert(85, "example.com")),
            row(
                "us-east",
                11,
                CheckStatus::Degraded,
                cert(84, "example.com"),
            ),
        ];
        let card = fold(FactsKind::Cert, rows);
        assert_eq!(card.groups.len(), 1);
        let group = &card.groups[0];
        assert_eq!(group.regions, ["eu-central", "us-east"]);
        assert_eq!(group.checked_at, at(11));
        assert_eq!(group.status, CheckStatus::Degraded);
        assert_eq!(group.days_left, Some(84));
        let countdown = group.countdown().unwrap();
        assert_eq!(
            (countdown.lead, countdown.value.as_str(), countdown.unit),
            ("expires in", "84", "days")
        );
        assert_eq!(card.checked_at, at(11));
        assert!(card.show_regions());
    }

    #[test]
    fn equal_answers_fold_and_other_answers_split() {
        let rows = vec![
            row(
                "eu-central",
                9,
                CheckStatus::Up,
                a_records(&["192.0.2.1", "192.0.2.2"]),
            ),
            row(
                "eu-north",
                9,
                CheckStatus::Up,
                a_records(&["192.0.2.1", "192.0.2.2"]),
            ),
            row("us-east", 9, CheckStatus::Up, a_records(&["198.51.100.7"])),
        ];
        let card = fold(FactsKind::Dns, rows);
        assert_eq!(card.groups.len(), 2);
        assert_eq!(card.groups[0].regions, ["eu-central", "eu-north"]);
        let dns = card.groups[0].facts.dns().unwrap();
        let values: Vec<_> = dns.chips.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(values, ["192.0.2.1", "192.0.2.2"]);
        assert_eq!(card.groups[1].regions, ["us-east"]);
        assert_eq!(card.groups[0].days_left, None);
    }

    #[test]
    fn the_first_card_names_what_the_second_group_read_differently() {
        let CheckDetails::TlsCert(old) = cert(3, "example.com") else {
            unreachable!()
        };
        let old = CheckDetails::TlsCert(TlsCertDetails {
            issuer_common_name: "R3".into(),
            not_after: at(7),
            ..old
        });
        let rows = vec![
            row("eu-central", 9, CheckStatus::Up, cert(84, "example.com")),
            row("ap-south", 9, CheckStatus::Down, old),
        ];
        let card = fold(FactsKind::Cert, rows);
        assert_eq!(card.groups[0].label(), "ap-south");
        assert_eq!(card.elsewhere().as_deref(), Some("elsewhere by R11"));

        let same = vec![
            row("eu-central", 9, CheckStatus::Up, cert(84, "example.com")),
            row("us-east", 9, CheckStatus::Up, cert(84, "example.com")),
        ];
        assert_eq!(fold(FactsKind::Cert, same).elsewhere(), None);
    }

    #[test]
    fn the_soonest_expiry_leads_among_equal_verdicts() {
        let rows = vec![
            row("eu-central", 9, CheckStatus::Up, cert(80, "example.com")),
            row("eu-north", 9, CheckStatus::Up, cert(80, "example.com")),
            row("us-east", 9, CheckStatus::Up, {
                let CheckDetails::TlsCert(d) = cert(9, "example.com") else {
                    unreachable!()
                };
                CheckDetails::TlsCert(TlsCertDetails {
                    not_after: at(7) + Duration::days(9),
                    ..d
                })
            }),
        ];
        let card = fold(FactsKind::Cert, rows);
        assert_eq!(card.groups[0].label(), "us-east");
    }

    #[test]
    fn answers_reached_through_different_cnames_read_alike() {
        let via = |edge: &str| {
            let CheckDetails::Dns(d) = a_records(&["192.0.2.1"]) else {
                unreachable!()
            };
            CheckDetails::Dns(DnsDetails {
                aliases: vec![edge.into()],
                ..d
            })
        };
        let rows = vec![
            row(
                "eu-central",
                9,
                CheckStatus::Up,
                via("eu.edge.example.net."),
            ),
            row("us-east", 9, CheckStatus::Up, via("us.edge.example.net.")),
        ];
        assert_eq!(fold(FactsKind::Dns, rows).groups.len(), 1);
    }

    #[test]
    fn the_worst_group_leads_then_the_biggest() {
        let rows = vec![
            row("ap-south", 9, CheckStatus::Up, a_records(&["192.0.2.3"])),
            row("eu-central", 9, CheckStatus::Up, a_records(&["192.0.2.1"])),
            row("eu-north", 9, CheckStatus::Up, a_records(&["192.0.2.1"])),
            row("us-east", 9, CheckStatus::Down, a_records(&["192.0.2.9"])),
        ];
        let card = fold(FactsKind::Dns, rows);
        let order: Vec<_> = card.groups.iter().map(|g| g.label()).collect();
        assert_eq!(order, ["us-east", "2 regions", "ap-south"]);
    }

    #[test]
    fn a_big_group_names_a_few_regions_and_counts_the_rest() {
        let rows = ["a", "b", "c", "d", "e"]
            .map(|r| row(r, 9, CheckStatus::Up, a_records(&["192.0.2.1"])))
            .to_vec();
        let card = fold(FactsKind::Dns, rows);
        assert_eq!(card.groups[0].label(), "5 regions");
        assert_eq!(card.groups[0].names(), "a, b, c +2");
    }

    #[test]
    fn records_off_the_expected_set_are_flagged_and_long_lists_fold() {
        let CheckDetails::Dns(d) = a_records(&["192.0.2.1", "192.0.2.9"]) else {
            unreachable!()
        };
        let off = CheckDetails::Dns(DnsDetails {
            missing: Some(vec!["192.0.2.5".into()]),
            unexpected: Some(vec!["192.0.2.9".into()]),
            matched: Some(false),
            ..d
        });
        let card = fold(
            FactsKind::Dns,
            vec![row("default", 9, CheckStatus::Down, off)],
        );
        let dns = card.groups[0].facts.dns().unwrap();
        let kinds: Vec<_> = dns.chips.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [ChipKind::Answer, ChipKind::Unexpected, ChipKind::Missing]
        );
        assert_eq!(dns.record_count(), 2);
        assert!(card.off_set());

        let long: Vec<String> = (1..=8).map(|n| format!("192.0.2.{n}")).collect();
        let long: Vec<&str> = long.iter().map(String::as_str).collect();
        let card = fold(
            FactsKind::Dns,
            vec![row("default", 9, CheckStatus::Up, a_records(&long))],
        );
        let dns = card.groups[0].facts.dns().unwrap();
        assert_eq!((dns.shown_chips().len(), dns.more_chips().len()), (6, 2));
        assert!(!card.off_set());
    }

    #[test]
    fn a_region_the_monitor_left_drops_out_and_a_failing_one_stays() {
        let rows = vec![
            row("eu-central", 11, CheckStatus::Up, a_records(&["192.0.2.1"])),
            row("eu-north", 2, CheckStatus::Up, a_records(&["192.0.2.1"])),
            row("us-east", 7, CheckStatus::Down, a_records(&["192.0.2.9"])),
        ];
        let assigned = ["eu-central".to_string(), "eu-north".to_string()];
        let card = CheckFacts::fold(FactsKind::Dns, rows, at(12), &assigned);
        assert_eq!(card.groups.len(), 1);
        assert_eq!(card.groups[0].regions, ["eu-central", "eu-north"]);
        assert_eq!(card.groups[0].status, CheckStatus::Up);
    }

    #[test]
    fn hours_past_expiry_read_as_expired() {
        let lapsed = CheckDetails::TlsCert(TlsCertDetails {
            days_remaining: 0,
            not_after: at(7),
            subject_common_name: "example.com".into(),
            issuer_common_name: "R11".into(),
        });
        let card = fold(
            FactsKind::Cert,
            vec![row("default", 9, CheckStatus::Down, lapsed)],
        );
        let countdown = card.groups[0].countdown().unwrap();
        assert_eq!(
            (countdown.lead, countdown.value.as_str(), countdown.unit),
            ("expired", "1", "day ago")
        );
    }

    #[test]
    fn raw_keeps_every_region_that_a_group_folds() {
        let rows = vec![
            row("eu-central", 9, CheckStatus::Up, cert(85, "example.com")),
            row("us-east", 11, CheckStatus::Up, cert(84, "example.com")),
        ];
        let card = fold(FactsKind::Cert, rows);
        assert_eq!(card.groups.len(), 1);
        let regions: Vec<_> = card.raw.iter().map(|r| r.region.as_str()).collect();
        assert_eq!(regions, ["eu-central", "us-east"]);
        assert!(card.raw[1].json.contains("\"days_remaining\": 84"));
        assert!(card.raw[1].json.starts_with("{\n  \"type\": \"tls_cert\""));
    }

    #[test]
    fn a_reading_from_before_the_query_was_edited_is_dropped() {
        let spec = |json| serde_json::from_value::<CheckSpec>(json).unwrap();
        let mx = spec(serde_json::json!({
            "type": "dns", "domain": "example.com", "record_type": "MX", "timeout": 3000
        }));
        let CheckDetails::Dns(a) = a_records(&["192.0.2.1"]) else {
            unreachable!()
        };
        let mx_details = DnsDetails {
            record_type: DnsRecordType::Mx,
            answers: vec!["10 mail.example.com.".into()],
            ..a.clone()
        };
        let mx_answer = CheckDetails::Dns(mx_details.clone());
        assert!(!reads_current(&mx, &CheckDetails::Dns(a.clone())));
        assert!(reads_current(&mx, &mx_answer));
        let renamed = CheckDetails::Dns(DnsDetails {
            domain: "old.example.com".into(),
            ..a
        });
        assert!(!reads_current(&mx, &renamed));
        let old_needle = CheckDetails::Dns(DnsDetails {
            expected_contains: Some("mail.example.com".into()),
            matched: Some(true),
            ..mx_details
        });
        assert!(!reads_current(&mx, &old_needle));

        let domain = spec(serde_json::json!({
            "type": "domain_expiry", "domain": "example.com",
            "warn_days": 30, "critical_days": 7, "timeout": 10000
        }));
        let reading = |name: &str| {
            CheckDetails::DomainExpiry(crate::domain::DomainExpiryDetails {
                domain: name.into(),
                days_remaining: 90,
                expiration_date: at(9),
                registrar: None,
            })
        };
        assert!(reads_current(&domain, &reading("example.com")));
        assert!(!reads_current(&domain, &reading("example.org")));
    }

    #[test]
    fn one_region_names_no_regions() {
        let rows = vec![row("default", 9, CheckStatus::Up, cert(84, "example.com"))];
        assert!(!fold(FactsKind::Cert, rows).show_regions());
    }

    #[test]
    fn a_certificate_without_a_common_name_shows_no_subject() {
        let rows = vec![row("default", 9, CheckStatus::Up, cert(84, NO_COMMON_NAME))];
        let card = fold(FactsKind::Cert, rows);
        let facts = card.groups[0].facts.cert().unwrap();
        assert_eq!(facts.subject, None);
        assert_eq!(facts.issuer.as_deref(), Some("R11"));
    }

    #[test]
    fn only_a_missed_substring_reads_as_unmatched() {
        let substring = |matched| {
            let CheckDetails::Dns(d) = a_records(&["192.0.2.1"]) else {
                unreachable!()
            };
            CheckDetails::Dns(DnsDetails {
                expected_contains: Some("203.0.113.7".into()),
                matched: Some(matched),
                ..d
            })
        };
        let card = |details| {
            fold(
                FactsKind::Dns,
                vec![row("default", 9, CheckStatus::Down, details)],
            )
        };
        let missed = card(substring(false));
        let lacking = missed.lacking().unwrap();
        assert_eq!(
            (lacking.want, lacking.regions, lacking.everywhere),
            ("203.0.113.7", 1, true)
        );
        assert!(!missed.off_set());
        assert!(card(substring(true)).lacking().is_none());

        let mixed = fold(
            FactsKind::Dns,
            vec![
                row("eu-central", 9, CheckStatus::Up, substring(true)),
                row("us-east", 9, CheckStatus::Down, substring(false)),
            ],
        );
        let lacking = mixed.lacking().unwrap();
        assert_eq!((lacking.regions, lacking.everywhere), (1, false));
    }
}
