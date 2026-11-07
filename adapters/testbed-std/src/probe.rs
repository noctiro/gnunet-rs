//! Real bounded dual transport/family probe; no future exclusive-port promise.
use crate::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
fn unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
    )
}
/// Actual simultaneous local bind observation, before closing all four probes.
/// The source token records only logical per-system exclusion after this call.
pub(crate) fn available(port: u16, families: Families) -> Result<bool, Failure> {
    let mut sockets = Vec::new();
    sockets.try_reserve_exact(4).map_err(|_| Fault::Capacity)?;
    let mut any = false;
    for v6 in [false, true] {
        if (!v6 && !families.ipv4) || (v6 && !families.ipv6) {
            continue;
        }
        let mut supported = true;
        for udp in [false, true] {
            let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
            let typ = if udp { Type::DGRAM } else { Type::STREAM };
            let protocol = if udp { Protocol::UDP } else { Protocol::TCP };
            let socket = match Socket::new(domain, typ, Some(protocol)) {
                Ok(s) => s,
                Err(e) if unsupported(&e) => {
                    supported = false;
                    break;
                }
                Err(e) => {
                    return Err(Failure::io(
                        "probe socket",
                        Path::new("<wildcard socket>"),
                        e,
                    ));
                }
            };
            if v6 {
                socket
                    .set_only_v6(true)
                    .map_err(|e| Failure::io("probe v6-only", Path::new("<wildcard socket>"), e))?
            }
            let address = if v6 {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
            } else {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
            };
            match socket.bind(&address.into()) {
                Ok(()) => sockets.push(socket),
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => return Ok(false),
                Err(e) if unsupported(&e) => {
                    supported = false;
                    break;
                }
                Err(e) => return Err(Failure::io("probe bind", Path::new("<wildcard socket>"), e)),
            }
        }
        if supported {
            any = true;
        }
    }
    if !any {
        return Err(Fault::Unsupported.into());
    }
    Ok(true)
}
