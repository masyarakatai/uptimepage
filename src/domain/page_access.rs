//! Who may open a private status page, and the record of who did.
//!
//! Visitors here are not app users: a viewer is an address that proved itself
//! on one page's host, and nothing about it reaches the app's own sign-in.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{UserId, email_norm, hostname};

/// Plan-independent: the list exists to name people, not to be metered.
pub const MAX_ACCESS_RULES: usize = 500;

/// The periods the editor offers. The column CHECKs hold the same lists.
pub const RECHECK_DAY_CHOICES: &[i32] = &[30, 90, 365];
pub const SESSION_DAY_CHOICES: &[i32] = &[7, 30, 90];

macro_rules! db_enum {
    ($(#[$meta:meta])* $name:ident, $check:literal { $($variant:ident => $db:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            #[doc = concat!("Declaration order; the enum-drift test pins this against `", $check, "`.")]
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_db_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $db),+
                }
            }

            pub fn from_db_str(s: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_db_str() == s)
            }
        }
    };
}

db_enum!(
    /// An exact address lets in one person; a domain lets in every address at it.
    AccessRuleKind, "status_page_access_rules_kind_check" {
        Address => "address",
        Domain => "domain",
    }
);

db_enum!(
    /// How a session was opened. A shared password joins later as a session
    /// with no viewer.
    PageSessionMethod, "status_page_sessions_method_check" {
        Email => "email",
    }
);

db_enum!(
    AccessEventKind, "status_page_access_events_kind_check" {
        CodeSent => "code_sent",
        CodeFailed => "code_failed",
        SignedIn => "signed_in",
        SignedOut => "signed_out",
        PasskeyAdded => "passkey_added",
        PasskeyRemoved => "passkey_removed",
        Blocked => "blocked",
        Unblocked => "unblocked",
    }
);

db_enum!(
    AccessEventMethod, "status_page_access_events_method_check" {
        Email => "email",
        Passkey => "passkey",
    }
);

/// One entry on a page's access list, already normalised: lower case, no
/// leading `@`, an internationalised domain in its ASCII form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessRule {
    pub kind: AccessRuleKind,
    /// `anna@dealer.example` or `dealer.example`.
    pub value: String,
}

impl AccessRule {
    /// `email` must be normalised the same way the rule was.
    pub fn admits(&self, email: &str) -> bool {
        match self.kind {
            AccessRuleKind::Address => self.value == email,
            AccessRuleKind::Domain => email
                .rsplit_once('@')
                .is_some_and(|(_, domain)| domain == self.value),
        }
    }
}

/// The one spelling a visitor's address and a list entry are compared in:
/// lower case, the domain in its ASCII form. `None` when it is not an address.
pub fn normalize_email(raw: &str) -> Option<String> {
    let email = email_norm::normalize(raw)?;
    let (local, domain) = email.split_once('@')?;
    // `hostname::normalize` would drop a port; an address has none.
    if domain.contains(['@', ':']) {
        return None;
    }
    let domain = hostname::normalize(domain)?;
    Some(format!("{}@{domain}", local.to_lowercase()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    #[error("enter a domain such as example.com or an address such as name@example.com")]
    Malformed,
}

impl AccessRule {
    /// What the owner typed: `dealer.example`, `@dealer.example` or `anna@dealer.example`.
    pub fn parse(raw: &str) -> Result<Self, RuleError> {
        let raw = raw.trim();
        let raw = raw.strip_prefix('@').unwrap_or(raw);
        if raw.contains('@') {
            let value = normalize_email(raw).ok_or(RuleError::Malformed)?;
            return Ok(Self {
                kind: AccessRuleKind::Address,
                value,
            });
        }
        // `hostname::normalize` drops a port, which a domain entry never has.
        if raw.contains(':') {
            return Err(RuleError::Malformed);
        }
        let value = hostname::normalize(raw).ok_or(RuleError::Malformed)?;
        Ok(Self {
            kind: AccessRuleKind::Domain,
            value: value.into_owned(),
        })
    }

    /// A rule as stored or sent, brought to the spelling [`Self::parse`]
    /// produces, so its kind and value cannot disagree.
    pub fn normalized(&self) -> Result<Self, RuleError> {
        let parsed = Self::parse(&self.value)?;
        if parsed.kind == self.kind {
            Ok(parsed)
        } else {
            Err(RuleError::Malformed)
        }
    }
}

/// The owner's settings for one page. `protected` is what makes it private;
/// the rest is kept while it is public so a round trip loses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageAccessSettings {
    pub protected: bool,
    pub email_enabled: bool,
    pub passkeys_enabled: bool,
    /// Days a passkey viewer may go without proving their address again.
    /// `None` never asks.
    pub recheck_days: Option<i32>,
    /// `None` keeps a session until sign-out, block, or the list stops
    /// matching.
    pub session_days: Option<i32>,
}

impl Default for PageAccessSettings {
    fn default() -> Self {
        Self {
            protected: false,
            email_enabled: true,
            passkeys_enabled: true,
            recheck_days: None,
            session_days: None,
        }
    }
}

/// What the gate reads for one page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageAccess {
    pub settings: PageAccessSettings,
    pub rules: Vec<AccessRule>,
}

impl PageAccess {
    pub fn is_private(&self) -> bool {
        self.settings.protected
    }

    /// `email` must be normalised the same way the rules were.
    pub fn admits(&self, email: &str) -> bool {
        self.settings.email_enabled && self.rules.iter().any(|r| r.admits(email))
    }
}

/// Who may open a page, as the API, MCP and Terraform send and read it.
/// Replaces the stored settings and list whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessSpec {
    /// Private when true: only the addresses and domains on `rules` can open
    /// the page. False keeps the list for the next time it is made private.
    pub protected: bool,
    #[serde(default)]
    pub email: EmailAccessSpec,
    /// Up to 500 entries.
    #[serde(default)]
    pub rules: Vec<AccessRule>,
}

/// The emailed-code way in, and the passkeys that shortcut it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailAccessSpec {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Viewers may save a passkey after an email sign-in and use it next time.
    #[serde(default = "yes")]
    pub passkeys_enabled: bool,
    /// Ask passkey viewers for an email code again after this many days: 30,
    /// 90 or 365. `null` never asks.
    #[serde(default)]
    pub recheck_days: Option<i32>,
    /// Keep a sign-in for this many days: 7, 30 or 90. `null` keeps it until
    /// sign-out, a block, or the list stops covering the viewer.
    #[serde(default)]
    pub session_days: Option<i32>,
}

fn yes() -> bool {
    true
}

impl Default for EmailAccessSpec {
    fn default() -> Self {
        let s = PageAccessSettings::default();
        Self {
            enabled: s.email_enabled,
            passkeys_enabled: s.passkeys_enabled,
            recheck_days: s.recheck_days,
            session_days: s.session_days,
        }
    }
}

impl From<&PageAccess> for AccessSpec {
    fn from(a: &PageAccess) -> Self {
        let s = a.settings;
        Self {
            protected: s.protected,
            email: EmailAccessSpec {
                enabled: s.email_enabled,
                passkeys_enabled: s.passkeys_enabled,
                recheck_days: s.recheck_days,
                session_days: s.session_days,
            },
            rules: a.rules.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    #[error("access.rules[{index}]: {source}")]
    Rule { index: usize, source: RuleError },
    #[error("a page lists at most {MAX_ACCESS_RULES} addresses and domains")]
    TooManyRules,
    #[error("{field} must be one of {choices:?} or null")]
    Period {
        field: &'static str,
        choices: &'static [i32],
    },
    #[error("a private page needs a way in: turn the email code on")]
    NoWayIn,
    #[error("add who can open it: a private page needs at least one address or domain")]
    EmptyList,
    #[error("private status pages are part of the Team plan")]
    NotOnPlan,
}

impl AccessError {
    pub fn field(&self) -> String {
        match self {
            Self::Rule { index, .. } => format!("access.rules[{index}]"),
            Self::TooManyRules | Self::EmptyList => "access.rules".into(),
            Self::Period { field, .. } => (*field).into(),
            Self::NoWayIn => "access.email.enabled".into(),
            Self::NotOnPlan => "access.protected".into(),
        }
    }
}

impl AccessSpec {
    /// The write this spec asks for, normalised, or why it cannot be made.
    /// `may_be_private` is whether the plan includes private pages or the page
    /// already is one: a page held since its plan lost them stays editable.
    pub fn validate(self, may_be_private: bool) -> Result<PageAccess, AccessError> {
        // Before any parsing, so an oversized list costs nothing to refuse.
        if self.rules.len() > MAX_ACCESS_RULES {
            return Err(AccessError::TooManyRules);
        }
        let mut seen = std::collections::HashSet::with_capacity(self.rules.len());
        let mut rules: Vec<AccessRule> = Vec::with_capacity(self.rules.len());
        for (index, rule) in self.rules.iter().enumerate() {
            let rule = rule
                .normalized()
                .map_err(|source| AccessError::Rule { index, source })?;
            if seen.insert(rule.clone()) {
                rules.push(rule);
            }
        }
        for (value, field, choices) in [
            (
                self.email.recheck_days,
                "access.email.recheck_days",
                RECHECK_DAY_CHOICES,
            ),
            (
                self.email.session_days,
                "access.email.session_days",
                SESSION_DAY_CHOICES,
            ),
        ] {
            if value.is_some_and(|v| !choices.contains(&v)) {
                return Err(AccessError::Period { field, choices });
            }
        }
        if self.protected {
            if !may_be_private {
                return Err(AccessError::NotOnPlan);
            }
            if !self.email.enabled {
                return Err(AccessError::NoWayIn);
            }
            if rules.is_empty() {
                return Err(AccessError::EmptyList);
            }
        }
        Ok(PageAccess {
            settings: PageAccessSettings {
                protected: self.protected,
                email_enabled: self.email.enabled,
                passkeys_enabled: self.email.passkeys_enabled,
                recheck_days: self.email.recheck_days,
                session_days: self.email.session_days,
            },
            rules,
        })
    }
}

/// A validated access write, carried with the page edit it arrives in so both
/// commit together.
#[derive(Debug, Clone)]
pub struct AccessWrite {
    pub access: PageAccess,
    pub actor: Option<UserId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: AccessRuleKind, value: &str) -> AccessRule {
        AccessRule {
            kind,
            value: value.into(),
        }
    }

    #[test]
    fn a_domain_admits_every_address_at_it_and_nothing_below_it() {
        let r = rule(AccessRuleKind::Domain, "dealer.example");
        assert!(r.admits("anna@dealer.example"));
        assert!(!r.admits("anna@mail.dealer.example"));
        assert!(!r.admits("anna@notdealer.example"));
        assert!(!r.admits("dealer.example"));
    }

    #[test]
    fn an_address_admits_only_itself() {
        let r = rule(AccessRuleKind::Address, "anna@dealer.example");
        assert!(r.admits("anna@dealer.example"));
        assert!(!r.admits("bob@dealer.example"));
    }

    #[test]
    fn a_page_with_email_off_admits_nobody_by_email() {
        let mut access = PageAccess {
            settings: PageAccessSettings {
                protected: true,
                ..Default::default()
            },
            rules: vec![rule(AccessRuleKind::Domain, "dealer.example")],
        };
        assert!(access.admits("anna@dealer.example"));
        access.settings.email_enabled = false;
        assert!(!access.admits("anna@dealer.example"));
    }

    #[test]
    fn an_entry_is_read_as_typed_and_stored_in_one_spelling() {
        assert_eq!(
            AccessRule::parse(" @Dealer.EXAMPLE ").unwrap(),
            rule(AccessRuleKind::Domain, "dealer.example")
        );
        assert_eq!(
            AccessRule::parse("Anna@Bücher.de").unwrap(),
            rule(AccessRuleKind::Address, "anna@xn--bcher-kva.de")
        );
        for bad in [
            "",
            "@",
            "dealer",
            "dealer.example:443",
            "a@b",
            "anna@",
            "two words.de",
            "a@@dealer.example",
            "anna@dealer.example:443",
        ] {
            assert!(AccessRule::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_rule_whose_kind_and_value_disagree_is_refused() {
        assert!(
            rule(AccessRuleKind::Domain, "anna@dealer.example")
                .normalized()
                .is_err()
        );
        assert!(
            rule(AccessRuleKind::Address, "dealer.example")
                .normalized()
                .is_err()
        );
        assert_eq!(
            rule(AccessRuleKind::Domain, "DEALER.example")
                .normalized()
                .unwrap(),
            rule(AccessRuleKind::Domain, "dealer.example")
        );
    }

    #[test]
    fn a_visitor_address_matches_a_rule_typed_in_another_case_or_script() {
        let email = normalize_email("ANNA@bücher.de").unwrap();
        assert!(AccessRule::parse("Bücher.de").unwrap().admits(&email));
        assert!(AccessRule::parse("anna@BÜCHER.de").unwrap().admits(&email));
    }

    fn spec(protected: bool, rules: &[(&str, AccessRuleKind)]) -> AccessSpec {
        AccessSpec {
            protected,
            email: EmailAccessSpec::default(),
            rules: rules.iter().map(|(v, k)| rule(*k, v)).collect(),
        }
    }

    #[test]
    fn a_private_page_needs_the_plan_a_way_in_and_someone_on_the_list() {
        let ok = spec(true, &[("dealer.example", AccessRuleKind::Domain)]);
        assert!(ok.clone().validate(true).is_ok());
        assert_eq!(ok.clone().validate(false), Err(AccessError::NotOnPlan));
        assert_eq!(spec(true, &[]).validate(true), Err(AccessError::EmptyList));
        let mut off = ok;
        off.email.enabled = false;
        assert_eq!(off.validate(true), Err(AccessError::NoWayIn));
        // Public keeps its list, empty or not, whatever the plan.
        assert!(spec(false, &[]).validate(false).is_ok());
    }

    #[test]
    fn the_list_is_normalised_deduplicated_and_capped() {
        let access = spec(
            true,
            &[
                ("DEALER.example", AccessRuleKind::Domain),
                ("dealer.example", AccessRuleKind::Domain),
            ],
        )
        .validate(true)
        .unwrap();
        assert_eq!(
            access.rules,
            vec![rule(AccessRuleKind::Domain, "dealer.example")]
        );
        let bad = spec(true, &[("dealer.example", AccessRuleKind::Address)]);
        assert!(matches!(
            bad.validate(true),
            Err(AccessError::Rule { index: 0, .. })
        ));
        let many: Vec<String> = (0..=MAX_ACCESS_RULES).map(|i| format!("d{i}.de")).collect();
        let many: Vec<(&str, AccessRuleKind)> = many
            .iter()
            .map(|d| (d.as_str(), AccessRuleKind::Domain))
            .collect();
        assert_eq!(
            spec(true, &many).validate(true),
            Err(AccessError::TooManyRules)
        );
    }

    #[test]
    fn only_the_offered_periods_are_accepted() {
        let mut s = spec(true, &[("dealer.example", AccessRuleKind::Domain)]);
        s.email.recheck_days = Some(14);
        assert!(matches!(
            s.clone().validate(true),
            Err(AccessError::Period { .. })
        ));
        s.email.recheck_days = Some(90);
        s.email.session_days = Some(30);
        assert!(s.validate(true).is_ok());
    }

    #[test]
    fn db_strings_round_trip() {
        for k in AccessEventKind::ALL {
            assert_eq!(AccessEventKind::from_db_str(k.as_db_str()), Some(*k));
        }
        assert_eq!(AccessRuleKind::from_db_str("nope"), None);
    }
}
