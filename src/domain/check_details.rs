use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;

use super::DnsRecordType;

/// What the certificate subject reads as when it carries no common name.
pub const NO_COMMON_NAME: &str = "<no CN>";

/// What a certificate, DNS or domain check read, on every graded run, so a
/// healthy result still says what it saw. A result that is not up also
/// carries the inner document, unchanged, as its `error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckDetails {
    TlsCert(TlsCertDetails),
    Dns(DnsDetails),
    DomainExpiry(DomainExpiryDetails),
}

impl CheckDetails {
    /// The tagged document a result row stores.
    pub fn stored_json(&self) -> String {
        to_json(self)
    }

    /// The stored document, indented for a person to read.
    pub fn pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("infallible serialize for fixed struct")
    }

    /// The document a result that is not up carries as its `error`.
    pub fn error_json(&self) -> String {
        match self {
            Self::TlsCert(d) => to_json(d),
            Self::Dns(d) => to_json(d),
            Self::DomainExpiry(d) => to_json(d),
        }
    }
}

fn to_json(details: &impl Serialize) -> String {
    serde_json::to_string(details).expect("infallible serialize for fixed struct")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TlsCertDetails {
    pub days_remaining: i64,
    #[serde(serialize_with = "rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub not_after: DateTime<Utc>,
    pub subject_common_name: String,
    pub issuer_common_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnsDetails {
    pub domain: String,
    pub record_type: DnsRecordType,
    /// Expected values no answer carries; set only with `expected_records`.
    /// The diff leads: an alert cuts the text short, and what changed is
    /// the part worth keeping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub missing: Option<Vec<String>>,
    /// Answers nothing expected; set only with `expected_records`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub unexpected: Option<Vec<String>>,
    /// Records of the queried type.
    pub answers: Vec<String>,
    /// The CNAME chain that led to the answers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub expected_contains: Option<String>,
    pub matched: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DomainExpiryDetails {
    pub domain: String,
    pub days_remaining: i64,
    #[serde(serialize_with = "rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expiration_date: DateTime<Utc>,
    pub registrar: Option<String>,
}

// `+00:00`, as the `error` document has always spelled it.
fn rfc3339<S: Serializer>(at: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&at.to_rfc3339())
}

/// A type from a newer agent would fail the whole ingest batch. Details only
/// describe a verdict, so drop them alone.
pub(super) fn lenient_details<'de, D>(deserializer: D) -> Result<Option<CheckDetails>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match serde_json::from_value(raw) {
        Ok(details) => Ok(Some(details)),
        // Quiet: a newer agent would say so on every result it sends.
        Err(error) => {
            tracing::debug!(%error, "unreadable check details dropped from result");
            Ok(None)
        }
    }
}

impl CheckDetails {
    /// `None` for a stored document this build cannot read. Quiet, since
    /// after a rollback every row a newer build wrote would say so.
    pub fn parse(raw: &str) -> Option<Self> {
        serde_json::from_str(raw)
            .map_err(|error| tracing::debug!(%error, "unreadable stored check details"))
            .ok()
    }
}

/// Days left in parts a card can set apart: `expires in` · `84` · `days`.
pub struct Expiry {
    pub lead: &'static str,
    pub value: String,
    pub unit: &'static str,
}

pub fn expiry(days: i64) -> Expiry {
    let plural = |n: i64| if n == 1 { "day" } else { "days" };
    match days {
        ..0 => Expiry {
            lead: "expired",
            value: (-days).to_string(),
            unit: if days == -1 { "day ago" } else { "days ago" },
        },
        0 => Expiry {
            lead: "expires",
            value: "today".to_string(),
            unit: "",
        },
        n => Expiry {
            lead: "expires in",
            value: n.to_string(),
            unit: plural(n),
        },
    }
}

/// `expires in 84 days`, `expires today`, `expired 3 days ago`.
pub fn expiry_words(days: i64) -> String {
    let Expiry { lead, value, unit } = expiry(days);
    [lead, value.as_str(), unit]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn cert() -> CheckDetails {
        CheckDetails::TlsCert(TlsCertDetails {
            days_remaining: 84,
            not_after: Utc.with_ymd_and_hms(2027, 1, 12, 10, 0, 0).unwrap(),
            subject_common_name: "example.com".into(),
            issuer_common_name: "R11".into(),
        })
    }

    #[test]
    fn the_error_document_keeps_its_old_spelling() {
        assert_eq!(
            cert().error_json(),
            r#"{"days_remaining":84,"not_after":"2027-01-12T10:00:00+00:00","subject_common_name":"example.com","issuer_common_name":"R11"}"#
        );
        let domain = CheckDetails::DomainExpiry(DomainExpiryDetails {
            domain: "example.com".into(),
            days_remaining: 5,
            expiration_date: Utc.with_ymd_and_hms(2026, 10, 24, 0, 0, 0).unwrap(),
            registrar: None,
        });
        assert_eq!(
            domain.error_json(),
            r#"{"domain":"example.com","days_remaining":5,"expiration_date":"2026-10-24T00:00:00+00:00","registrar":null}"#
        );
    }

    #[test]
    fn details_are_tagged_and_read_back() {
        let json = serde_json::to_string(&cert()).unwrap();
        assert!(json.starts_with(r#"{"type":"tls_cert","#), "{json}");
        assert_eq!(CheckDetails::parse(&json), Some(cert()));
    }

    #[test]
    fn expiry_reads_forward_and_back() {
        assert_eq!(expiry_words(84), "expires in 84 days");
        assert_eq!(expiry_words(1), "expires in 1 day");
        assert_eq!(expiry_words(0), "expires today");
        assert_eq!(expiry_words(-1), "expired 1 day ago");
        assert_eq!(expiry_words(-3), "expired 3 days ago");
    }

    #[test]
    fn an_unknown_type_reads_as_nothing() {
        assert_eq!(CheckDetails::parse(r#"{"type":"smtp","banner":"x"}"#), None);
        assert_eq!(CheckDetails::parse("not json"), None);
    }
}
