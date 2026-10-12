//! Pointing an existing check at another address while every other setting
//! stays as it is: what a duplicated monitor changes and nothing more.

use std::fmt;

use url::Url;

use super::CheckSpec;

#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    Passive,
    Empty,
    Url,
    Port,
    Malformed,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passive => "heartbeat and manual monitors have no address to change",
            Self::Empty => "address is empty",
            Self::Url => "address must be an absolute http or https URL",
            Self::Port => "port must be between 1 and 65535",
            Self::Malformed => "address is not a host, or a host:port",
        })
    }
}

impl CheckSpec {
    /// What [`Self::retarget`] accepts for this check, written so that handing
    /// it back changes nothing. `None` for the passive kinds.
    pub fn address(&self) -> Option<String> {
        match self {
            CheckSpec::Http(c) => Some(c.url.to_string()),
            CheckSpec::Flow(c) => Some(c.start_url.to_string()),
            CheckSpec::Tcp(c) => Some(host_port(&c.host, c.port)),
            CheckSpec::TlsCert(c) => Some(host_port(&c.host, c.port)),
            CheckSpec::Ping(c) => Some(c.host.clone()),
            CheckSpec::Dns(c) => Some(c.domain.clone()),
            CheckSpec::DomainExpiry(c) => Some(c.domain.clone()),
            CheckSpec::Heartbeat(_) | CheckSpec::Manual(_) => None,
        }
    }

    /// The request field [`Self::address`] is read from, for an error that
    /// refuses it.
    pub fn address_field(&self) -> Option<&'static str> {
        match self {
            CheckSpec::Http(_) => Some("check.url"),
            CheckSpec::Flow(_) => Some("check.start_url"),
            CheckSpec::Tcp(_) | CheckSpec::TlsCert(_) | CheckSpec::Ping(_) => Some("check.host"),
            CheckSpec::Dns(_) | CheckSpec::DomainExpiry(_) => Some("check.domain"),
            CheckSpec::Heartbeat(_) | CheckSpec::Manual(_) => None,
        }
    }

    /// A URL for http and flow, a host or `host:port` for tcp and tls, a host
    /// for ping, a domain for dns and domain expiry. Only the shape is parsed
    /// here; the result goes through the same validation as any new check.
    pub fn retarget(&mut self, address: &str) -> Result<(), AddressError> {
        let address = address.trim();
        match self {
            CheckSpec::Heartbeat(_) | CheckSpec::Manual(_) => return Err(AddressError::Passive),
            _ if address.is_empty() => return Err(AddressError::Empty),
            CheckSpec::Http(c) => c.url = parse_url(address)?,
            CheckSpec::Flow(c) => c.start_url = parse_url(address)?,
            CheckSpec::Tcp(c) => (c.host, c.port) = host_and_port(address, c.port)?,
            CheckSpec::TlsCert(c) => (c.host, c.port) = host_and_port(address, c.port)?,
            CheckSpec::Ping(c) => c.host = address.to_owned(),
            CheckSpec::Dns(c) => c.domain = address.to_owned(),
            CheckSpec::DomainExpiry(c) => c.domain = address.to_owned(),
        }
        Ok(())
    }
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn parse_url(address: &str) -> Result<Url, AddressError> {
    Url::parse(address).map_err(|_| AddressError::Url)
}

/// A bare IPv6 literal has colons but no port, so only a bracketed one or a
/// single colon carries a port.
fn host_and_port(address: &str, port: u16) -> Result<(String, u16), AddressError> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(AddressError::Malformed)?;
        let port = match tail {
            "" => port,
            _ => parse_port(tail.strip_prefix(':').ok_or(AddressError::Malformed)?)?,
        };
        return Ok((host.to_owned(), port));
    }
    match address.split_once(':') {
        Some((host, p)) if !p.contains(':') => Ok((host.to_owned(), parse_port(p)?)),
        _ => Ok((address.to_owned(), port)),
    }
}

fn parse_port(raw: &str) -> Result<u16, AddressError> {
    match raw.parse::<u16>() {
        Ok(0) | Err(_) => Err(AddressError::Port),
        Ok(p) => Ok(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(json: &str) -> CheckSpec {
        serde_json::from_str(json).unwrap()
    }

    fn tcp() -> CheckSpec {
        spec(r#"{"type":"tcp","host":"db-a.example.com","port":5432,"timeout":3000}"#)
    }

    #[test]
    fn http_swaps_the_url_and_keeps_the_rest() {
        let mut c = spec(
            r#"{"type":"http","url":"https://a.example.com/health","method":"POST","timeout":4000,
                "follow_redirects":true,"max_redirects":3,"expected_status":{"kind":"exact","value":204},
                "headers":{"x-api-key":"k"},"body":"{}","verify_tls":false,"bearer_token":"t"}"#,
        );
        c.retarget(" https://b.example.com/ready ").unwrap();
        let CheckSpec::Http(h) = c else { panic!() };
        assert_eq!(h.url.as_str(), "https://b.example.com/ready");
        assert_eq!(h.headers.get("x-api-key").map(String::as_str), Some("k"));
        assert_eq!(h.bearer_token.as_deref(), Some("t"));
        assert_eq!(h.body.as_deref(), Some("{}"));
        assert!(!h.verify_tls);
    }

    #[test]
    fn a_url_kind_refuses_a_bare_host() {
        let mut c = spec(
            r#"{"type":"flow","start_url":"https://a.example.com/login","steps":[],
                "timeout":30000,"step_timeout":5000,"verify_tls":true}"#,
        );
        assert_eq!(c.retarget("b.example.com"), Err(AddressError::Url));
    }

    #[test]
    fn tcp_takes_a_host_and_keeps_the_port() {
        let mut c = tcp();
        c.retarget("db-b.example.com").unwrap();
        let CheckSpec::Tcp(t) = c else { panic!() };
        assert_eq!((t.host.as_str(), t.port), ("db-b.example.com", 5432));
    }

    #[test]
    fn tcp_takes_a_host_and_port() {
        let mut c = tcp();
        c.retarget("db-b.example.com:5433").unwrap();
        let CheckSpec::Tcp(t) = c else { panic!() };
        assert_eq!((t.host.as_str(), t.port), ("db-b.example.com", 5433));
    }

    #[test]
    fn ipv6_takes_a_port_only_in_brackets() {
        let mut c = tcp();
        c.retarget("[2001:db8::1]:6379").unwrap();
        let CheckSpec::Tcp(t) = &c else { panic!() };
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::1", 6379));
        c.retarget("2001:db8::2").unwrap();
        let CheckSpec::Tcp(t) = c else { panic!() };
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::2", 6379));
    }

    #[test]
    fn a_bad_port_or_bracket_is_refused() {
        for (raw, err) in [
            ("db.example.com:0", AddressError::Port),
            ("db.example.com:70000", AddressError::Port),
            ("db.example.com:", AddressError::Port),
            ("[2001:db8::1", AddressError::Malformed),
            ("[2001:db8::1]6379", AddressError::Malformed),
        ] {
            assert_eq!(tcp().retarget(raw), Err(err), "{raw}");
        }
    }

    #[test]
    fn name_kinds_take_the_address_as_is() {
        let mut dns =
            spec(r#"{"type":"dns","domain":"a.example.com","record_type":"MX","timeout":3000}"#);
        dns.retarget("b.example.com").unwrap();
        let CheckSpec::Dns(d) = dns else { panic!() };
        assert_eq!(d.domain, "b.example.com");
        assert_eq!(d.record_type.as_str(), "MX");
    }

    #[test]
    fn the_address_retargets_to_itself() {
        for json in [
            r#"{"type":"tcp","host":"db.example.com","port":5432,"timeout":3000}"#,
            r#"{"type":"tcp","host":"2001:db8::1","port":6379,"timeout":3000}"#,
            r#"{"type":"ping","host":"gw.example.com","timeout":3000}"#,
            r#"{"type":"tls_cert","host":"example.com","port":8443,"warn_days":30,"critical_days":7,"timeout":5000}"#,
            r#"{"type":"dns","domain":"a.example.com","record_type":"A","timeout":3000}"#,
        ] {
            let before = spec(json);
            let mut after = before.clone();
            after.retarget(&before.address().unwrap()).unwrap();
            assert_eq!(
                serde_json::to_value(&after).unwrap(),
                serde_json::to_value(&before).unwrap(),
                "{json}"
            );
        }
    }

    #[test]
    fn passive_kinds_and_blank_addresses_are_refused() {
        let mut hb = spec(r#"{"type":"heartbeat","period":300000,"grace":60000}"#);
        assert_eq!(hb.address(), None);
        assert_eq!(hb.retarget("x.example.com"), Err(AddressError::Passive));
        assert_eq!(tcp().retarget("  "), Err(AddressError::Empty));
    }
}
