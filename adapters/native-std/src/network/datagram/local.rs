//! Original local UDP reply authority, independent of platform I/O.
#[cfg(test)]
mod tests;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod unix;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub use unix::LocalDatagram;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::LocalDatagramIo;

use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU32,
    sync::Arc,
};

/// Return address and scope observed on one original UDP listener.
#[derive(Debug)]
pub struct LocalReplyPath {
    owner: Arc<()>,
    peer: SocketAddr,
    local: SocketAddr,
    ingress: NonZeroU32,
}

impl LocalReplyPath {
    /// Peer endpoint to which a reply will be addressed.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }
}

fn return_endpoints(
    bound: SocketAddr,
    peer: SocketAddr,
    destination: IpAddr,
    ingress: NonZeroU32,
) -> io::Result<(SocketAddr, SocketAddr)> {
    if peer.port() == 0
        || peer.is_ipv4() != bound.is_ipv4()
        || destination.is_ipv4() != bound.is_ipv4()
        || (!bound.ip().is_unspecified() && bound.ip() != destination)
    {
        return Err(invalid("inconsistent UDP listener endpoint metadata"));
    }
    let local = match destination {
        IpAddr::V4(ip) => SocketAddrV4::new(ip, bound.port()).into(),
        IpAddr::V6(ip) => SocketAddrV6::new(ip, bound.port(), 0, ipv6_scope(ip, ingress)).into(),
    };
    for endpoint in [peer, local] {
        match endpoint {
            SocketAddr::V4(address) if address.ip().is_broadcast() => {
                return Err(invalid("UDP broadcast address"));
            }
            SocketAddr::V6(address)
                if address.ip().to_ipv4_mapped().is_some()
                    || (address.ip().segments()[0] & 0xffc0 == 0xfec0)
                    || address.scope_id() != ipv6_scope(*address.ip(), ingress) =>
            {
                return Err(invalid("UDP endpoint has an invalid IPv6 zone"));
            }
            endpoint if endpoint.ip().is_multicast() || endpoint.ip().is_unspecified() => {
                return Err(invalid("UDP endpoint requires a unicast address"));
            }
            _ => {}
        }
    }
    if let SocketAddr::V6(bound) = bound
        && bound.scope_id() != 0
        && bound.scope_id() != ingress.get()
    {
        return Err(invalid("UDP listener scope differs from ingress"));
    }
    Ok((peer, local))
}

fn ipv6_scope(ip: std::net::Ipv6Addr, ingress: NonZeroU32) -> u32 {
    if ip.is_unicast_link_local() {
        ingress.get()
    } else {
        0
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
