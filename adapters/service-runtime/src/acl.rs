//! Official service IPv4/IPv6 accept/reject policies from `service.c`.
//!
//! Lists use semicolon-terminated C network notation. Port suffixes are checked
//! by the parser but do not participate in service.c's address-only decision.
//! Malformed configured lists are explicit errors; the C setup drops its parser
//! error and can consequently remove a restriction. Rust does not grant access
//! after a policy parse failure.
use gnunet_config::Configuration;
use gnunet_types::Error;
use std::net::{IpAddr, Ipv6Addr};

#[derive(Clone, Debug)]
struct Rule {
    network: u128,
    mask: u128,
}

/// Official per-family service admission lists. Unix sockets use filesystem ACLs.
#[derive(Clone, Debug, Default)]
pub struct AccessPolicy {
    allow4: Option<Vec<Rule>>,
    deny4: Option<Vec<Rule>>,
    allow6: Option<Vec<Rule>>,
    deny6: Option<Vec<Rule>>,
}
impl AccessPolicy {
    /// Parse all four service options. An absent list means no restriction of
    /// that kind; malformed or empty configured lists are never ignored.
    pub fn from_config(config: &Configuration, section: &[u8]) -> Result<Self, Error> {
        let get = |key: &[u8], v6| config.get(section, key).map(|v| parse(v, v6)).transpose();
        Ok(Self {
            allow4: get(b"ACCEPT_FROM", false)?,
            deny4: get(b"REJECT_FROM", false)?,
            allow6: get(b"ACCEPT_FROM6", true)?,
            deny6: get(b"REJECT_FROM6", true)?,
        })
    }
    /// Accept exactly when the applicable allow list matches (or is absent)
    /// and the applicable deny list does not match. Denial wins.
    #[must_use]
    pub fn allows(&self, ip: IpAddr) -> bool {
        let (allow, deny, ip) = match ip {
            IpAddr::V4(ip) => (&self.allow4, &self.deny4, u128::from(u32::from(ip))),
            IpAddr::V6(ip) => (&self.allow6, &self.deny6, u128::from(ip)),
        };
        let listed = |rules: &[Rule]| {
            rules
                .iter()
                .take_while(|r| r.network != 0)
                .any(|r| ip & r.mask == r.network & r.mask)
        };
        allow.as_ref().is_none_or(|r| listed(r)) && !deny.as_ref().is_some_and(|r| listed(r))
    }
}
fn number(input: &str) -> Result<u32, Error> {
    let text = input.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let text = text.strip_prefix('+').unwrap_or(text);
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidInput);
    }
    text.parse().map_err(|_| Error::InvalidInput)
}
fn ipv4(input: &str) -> Result<u32, Error> {
    let mut parts = input.split('.');
    let mut out = 0;
    for _ in 0..4 {
        let n = number(parts.next().ok_or(Error::InvalidInput)?)?;
        if n > 255 {
            return Err(Error::InvalidInput);
        }
        out = (out << 8) | n;
    }
    if parts.next().is_some() {
        return Err(Error::InvalidInput);
    }
    Ok(out)
}
fn port(input: &str) -> Result<(), Error> {
    let value = input
        .strip_prefix('!')
        .unwrap_or(input)
        .trim_end_matches(|c: char| c.is_ascii_whitespace());
    let (start, end) = if let Some((a, b)) = value.split_once('-') {
        (number(a)?, number(b)?)
    } else {
        let n = number(value)?;
        (n, n)
    };
    if start == 0 || end > 65535 || end < start {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn parse(input: &[u8], v6: bool) -> Result<Vec<Rule>, Error> {
    let text = std::str::from_utf8(input).map_err(|_| Error::InvalidInput)?;
    if text.is_empty() || !text.ends_with(';') {
        return Err(Error::InvalidInput);
    }
    let mut out = Vec::new();
    for mut item in text[..text.len() - 1].split(';') {
        if item.is_empty() {
            return Err(Error::InvalidInput);
        }
        let rule = if v6 {
            let (network, mask) = if let Some((address, mut mask)) = item.rsplit_once('/') {
                // Match the actual C scan: a colon after '/' denotes a port
                // suffix even when a caller meant a colon-form IPv6 mask.
                if let Some((prefix, suffix)) = mask.rsplit_once(':') {
                    port(suffix)?;
                    mask = prefix;
                }
                let mask = if let Ok(ip) = mask.parse::<Ipv6Addr>() {
                    u128::from(ip)
                } else {
                    let bits = number(mask)?;
                    if bits > 128 {
                        return Err(Error::InvalidInput);
                    }
                    if bits == 0 {
                        0
                    } else {
                        u128::MAX << (128 - bits)
                    }
                };
                (address, mask)
            } else {
                (item, u128::MAX)
            };
            Rule {
                network: u128::from(
                    network
                        .parse::<Ipv6Addr>()
                        .map_err(|_| Error::InvalidInput)?,
                ),
                mask,
            }
        } else {
            if let Some((address, ports)) = item.split_once(':') {
                port(ports)?;
                item = address;
            }
            let (network, mask) = if let Some((network, mask)) = item.split_once('/') {
                let mask = if mask.contains('.') {
                    ipv4(mask)?
                } else {
                    let bits = number(mask)?;
                    if bits > 32 {
                        return Err(Error::InvalidInput);
                    }
                    if bits == 0 {
                        0
                    } else {
                        u32::MAX << (32 - bits)
                    }
                };
                (ipv4(network)?, mask)
            } else {
                (ipv4(item)?, u32::MAX)
            };
            Rule {
                network: u128::from(network),
                mask: u128::from(mask),
            }
        };
        out.try_reserve(1).map_err(|_| Error::Capacity)?;
        out.push(rule);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Actual address admission and C grammar boundary assertions"
    )]
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn official_masks_ports_denial_and_zero_terminator() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = Configuration::new(Default::default());
        config.set_value(
            b"s",
            b"ACCEPT_FROM",
            Some(b"127.0.0.0/8:!80-90;10.0.0.0/255.0.255.0;"),
        )?;
        config.set_value(b"s", b"REJECT_FROM", Some(b"127.0.0.2;"))?;
        config.set_value(b"s", b"ACCEPT_FROM6", Some(b"2001:db8::/32:443;::1;"))?;
        let p = AccessPolicy::from_config(&config, b"s")?;
        assert!(p.allows(Ipv4Addr::LOCALHOST.into()));
        assert!(!p.allows(Ipv4Addr::new(127, 0, 0, 2).into()));
        assert!(p.allows(Ipv4Addr::new(10, 99, 0, 42).into()));
        assert!(!p.allows(Ipv4Addr::new(10, 99, 1, 42).into()));
        assert!(p.allows(Ipv6Addr::LOCALHOST.into()));
        assert!(!p.allows(Ipv6Addr::UNSPECIFIED.into()));
        config.set_value(b"s", b"ACCEPT_FROM", Some(b"0.0.0.0/0;127.0.0.1;"))?;
        assert!(!AccessPolicy::from_config(&config, b"s")?.allows(Ipv4Addr::LOCALHOST.into()));
        for bad in [
            b"".as_slice(),
            b"127.0.0.1",
            b"127.0.0.1:0;",
            b"127.0.0.1/33;",
            b"127.0.0.1;;",
        ] {
            config.set_value(b"s", b"ACCEPT_FROM", Some(bad))?;
            assert!(AccessPolicy::from_config(&config, b"s").is_err());
        }
        Ok(())
    }
}
