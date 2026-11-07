//! Numeric listener and existing certificate paths; reading keys is a host effect.
use crate::{Cause, options::Chosen};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::PathBuf,
};

pub(super) struct Settings {
    pub bind: Vec<SocketAddr>,
    pub authority: PathBuf,
    pub roots: Option<PathBuf>,
    pub disable_ipv6: bool,
}
impl Settings {
    pub(super) fn read(
        configuration: &gnunet_config::Configuration,
        chosen: Chosen,
    ) -> Result<Self, Cause> {
        let ipv4 = configuration
            .get(b"gns-proxy", b"BIND_TO")
            .ok_or("missing [gns-proxy] BIND_TO")?;
        let ipv4 = std::str::from_utf8(ipv4)?.parse::<Ipv4Addr>()?;
        let mut bind = vec![SocketAddr::V4(SocketAddrV4::new(ipv4, chosen.port))];
        if !chosen.disable_ipv6 {
            let ipv6 = configuration
                .get(b"gns-proxy", b"BIND_TO6")
                .ok_or("missing [gns-proxy] BIND_TO6")?;
            let ipv6 = std::str::from_utf8(ipv6)?.parse::<Ipv6Addr>()?;
            bind.push(SocketAddr::V6(SocketAddrV6::new(ipv6, chosen.port, 0, 0)));
        }
        let authority = match chosen.authority {
            Some(path) => path,
            None => configuration.get_filename(
                b"gns-proxy",
                b"PROXY_CACERT",
                &gnunet_config::ProcessEnvironment,
            )?,
        };
        let roots = if configuration
            .get(b"gns-proxy-rust", b"PKIX_ROOTS")
            .is_some()
        {
            Some(configuration.get_filename(
                b"gns-proxy-rust",
                b"PKIX_ROOTS",
                &gnunet_config::ProcessEnvironment,
            )?)
        } else {
            None
        };
        Ok(Self {
            bind,
            authority,
            roots,
            disable_ipv6: chosen.disable_ipv6,
        })
    }
}
