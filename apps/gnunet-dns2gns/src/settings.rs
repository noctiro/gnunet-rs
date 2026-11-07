//! Ordinary DNS2GNS bind configuration, distinct from installed defaults.
use crate::Cause;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
pub(super) struct Settings {
    pub ipv4: SocketAddrV4,
    pub ipv6: SocketAddrV6,
    pub upstream: SocketAddr,
}
impl Settings {
    pub(super) fn read(
        configuration: &gnunet_config::Configuration,
        upstream: IpAddr,
    ) -> Result<Self, Cause> {
        let ipv4 = configuration
            .get(b"dns2gns", b"BIND_TO")
            .ok_or("missing [DNS2GNS] BIND_TO")?;
        let ipv4 = std::str::from_utf8(ipv4)?.parse::<Ipv4Addr>()?;
        let ipv6 = configuration
            .get(b"dns2gns", b"BIND_TO6")
            .ok_or("missing [DNS2GNS] BIND_TO6")?;
        let ipv6 = std::str::from_utf8(ipv6)?.parse::<Ipv6Addr>()?;
        // Native code has a 53 fallback. The normal installed gns.conf instead
        // supplies its own PORT (15353); do not hardcode that installed value.
        let port = match configuration.get(b"dns2gns", b"PORT") {
            None => 53,
            Some(value) => std::str::from_utf8(value)?.parse::<u16>()?,
        };
        Ok(Self {
            ipv4: SocketAddrV4::new(ipv4, port),
            ipv6: SocketAddrV6::new(ipv6, port, 0, 0),
            upstream: SocketAddr::new(upstream, 53),
        })
    }
}
