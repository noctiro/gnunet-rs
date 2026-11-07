//! Actual official `[pt]` switches, with explicit finite Rust resource policy.
use crate::{Failure, Limits};
use gnunet_config::Configuration;
use gnunet_pt::{core, packet::Families};
use std::time::Duration;
/// Effective actual daemon policy. Reading performs no native/provider work.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Official TUNNEL_IPV4/TUNNEL_IPV6.
    pub families: Families,
    /// Official TUNNEL_DNS, requiring real DHT/CADET discovery.
    pub tunnel_dns: bool,
    /// Pure bounded original request/advertisement ownership.
    pub core: core::Limits,
    /// Native port bounds.
    pub native: Limits,
    /// Shared process Resolver driver bounds.
    pub resolver: gnunet_resolver_broker::Limits,
}
fn flag(c: &Configuration, key: &[u8]) -> Result<bool, Failure> {
    Ok(if c.have_value(b"pt", key) {
        c.get_yesno(b"pt", key)?
    } else {
        false
    })
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(if c.have_value(b"pt-rust", key) {
        usize::try_from(c.get_number(b"pt-rust", key)?)?
    } else {
        default
    })
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let d = if c.have_value(b"pt-rust", key) {
        Duration::from_micros(c.get_time(b"pt-rust", key)?)
    } else {
        default
    };
    if d.is_zero()
        || d.as_micros() >= u128::from(u64::MAX)
        || tokio::time::Instant::now().checked_add(d).is_none()
    {
        return Err("PT requires finite nonzero timeout".into());
    }
    Ok(d)
}
impl Settings {
    /// Read the active official flags and finite metadata budgets. It
    /// neither enables an unsupported tunnel nor silently substitutes a resolver.
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let mut pure = core::Limits::default();
        let mut native = Limits::default();
        pure.requests = number(c, b"MAX_REQUESTS", pure.requests)?;
        pure.packet_bytes = number(c, b"MAX_DNS_BYTES", pure.packet_bytes)?;
        pure.payload_bytes = number(c, b"PAYLOAD_BYTES", pure.payload_bytes)?;
        pure.records = number(c, b"MAX_RECORDS", pure.records)?;
        pure.questions = number(c, b"MAX_QUESTIONS", pure.questions)?;
        pure.exits = number(c, b"MAX_EXITS", pure.exits)?;
        pure.tunnels = number(c, b"MAX_TUNNELS", pure.tunnels)?;
        pure.attempts =
            u32::try_from(number(c, b"MAX_ATTEMPTS", usize::try_from(pure.attempts)?)?)?;
        pure.parse_work = number(c, b"PARSE_WORK", pure.parse_work)?;
        native.dns.request_timeout =
            duration(c, b"REQUEST_TIMEOUT", Duration::from_micros(pure.timeout))?;
        pure.timeout = u64::try_from(native.dns.request_timeout.as_micros())?;
        native.control_timeout = duration(c, b"CONTROL_TIMEOUT", native.control_timeout)?;
        native.discovery_timeout = duration(c, b"DISCOVERY_TIMEOUT", native.discovery_timeout)?;
        native.retry = duration(c, b"CAPACITY_RETRY", native.retry)?;
        native.advertisement_lifetime = duration(
            c,
            b"MAX_ADVERTISEMENT_LIFETIME",
            native.advertisement_lifetime,
        )?;
        native.dns.requests = pure.requests;
        native.vpn.operations = pure.requests;
        native.dns.input_timeout = native.control_timeout;
        native.dns.source_bytes = number(c, b"DNS_OUTPUT_BYTES", native.dns.source_bytes)?;
        let out = Self {
            families: Families {
                ipv4: flag(c, b"TUNNEL_IPV4")?,
                ipv6: flag(c, b"TUNNEL_IPV6")?,
            },
            tunnel_dns: flag(c, b"TUNNEL_DNS")?,
            core: pure,
            native,
            resolver: Default::default(),
        };
        Ok(out)
    }
}
