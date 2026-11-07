use super::*;
use std::net::{SocketAddrV4, SocketAddrV6};

pub(super) fn endpoint(bytes: &[u8], default: u16) -> Result<SocketAddr, Error> {
    if bytes.len() > 128 {
        return Err(Fault::TooLarge.into());
    }
    let url = std::str::from_utf8(bytes).map_err(|_| Fault::InvalidInput)?;
    let address = url.strip_prefix("ip+udp://").ok_or(Fault::Unsupported)?;
    let address = address.strip_suffix('/').unwrap_or(address);
    let result = if let Some(v6) = address.strip_prefix('[') {
        let (host, suffix) = v6.split_once(']').ok_or(Fault::InvalidInput)?;
        let (host, scope) = match host.split_once('%') {
            Some((host, scope)) => (host, scope.parse::<u32>().map_err(|_| Fault::InvalidInput)?),
            None => (host, 0),
        };
        let ip = host.parse::<Ipv6Addr>().map_err(|_| Fault::InvalidInput)?;
        let port = if suffix.is_empty() {
            default
        } else {
            suffix
                .strip_prefix(':')
                .ok_or(Fault::InvalidInput)?
                .parse::<u16>()
                .map_err(|_| Fault::InvalidInput)?
        };
        SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope))
    } else {
        let (host, port) = match address.split_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().map_err(|_| Fault::InvalidInput)?),
            None => (address, default),
        };
        SocketAddr::V4(SocketAddrV4::new(
            host.parse().map_err(|_| Fault::InvalidInput)?,
            port,
        ))
    };
    if result.port() == 0 || result.ip().is_unspecified() || result.ip().is_multicast() {
        return Err(Fault::InvalidInput.into());
    }
    Ok(normalize(result))
}
pub(super) fn normalize(endpoint: SocketAddr) -> SocketAddr {
    match endpoint {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), 0, v6.scope_id())),
        },
        v4 => v4,
    }
}
pub(super) fn snapshot(config: Config, bound: &[SocketAddr]) -> io::Result<Vec<Address>> {
    let rows = gnunet_native::interfaces::snapshot(config.interfaces)?;
    let mut endpoints = Vec::new();
    endpoints
        .try_reserve_exact(
            rows.len()
                .checked_add(bound.len())
                .ok_or_else(|| io::Error::other("IP address count overflow"))?,
        )
        .map_err(|_| io::Error::other("IP address allocation refused"))?;
    for local in bound {
        for row in &rows {
            if !row.is_up()
                || row.address.is_ipv4() != local.is_ipv4()
                || row.address.ip().is_unspecified()
                || row.address.ip().is_multicast()
            {
                continue;
            }
            if !local.ip().is_unspecified() && local.ip() != row.address.ip() {
                continue;
            }
            if let (SocketAddr::V6(local), SocketAddr::V6(actual)) = (local, row.address)
                && local.scope_id() != 0
                && local.scope_id() != actual.scope_id()
                && local.scope_id() != row.index
            {
                continue;
            }
            let mut endpoint = row.address;
            endpoint.set_port(local.port());
            if let SocketAddr::V6(ref mut v6) = endpoint
                && v6.ip().is_unicast_link_local()
                && v6.scope_id() == 0
            {
                v6.set_scope_id(row.index);
            }
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
    }
    endpoints.sort_unstable();
    let mut addresses = Vec::new();
    addresses
        .try_reserve_exact(endpoints.len())
        .map_err(|_| io::Error::other("IP address allocation refused"))?;
    for endpoint in endpoints {
        addresses.push(Address {
            endpoint,
            url: format!("ip+udp://{endpoint}"),
        });
    }
    Ok(addresses)
}
