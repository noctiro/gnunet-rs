//! `GNUNET_CLIENT_test` from the pinned official `util/client.c`.
//!
//! This synchronous test is deliberately weak. ARM-managed Unix endpoints are
//! checked by path existence without waking the service. Other Unix endpoints
//! are connected and immediately closed. Loopback TCP is tested by attempting
//! bind; other hostnames are assumed up without DNS or a network connection.
//! None of these observations establishes a TEST reply or application authority.
use crate::ConnectError;
use gnunet_config::Configuration;
#[cfg(unix)]
use gnunet_config::ProcessEnvironment;
#[cfg(unix)]
use nix::unistd::{AccessFlags, access};
#[cfg(unix)]
use socket2::SockAddr;
use socket2::{Domain, Socket, Type};
#[cfg(unix)]
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Source-defined observation, without an authenticated application handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicePresence {
    /// The configured local endpoint is not in use in this finite observation.
    Down,
    /// Official weak evidence or a remote-host assumption says likely up.
    LikelyUp,
}

#[cfg(unix)]
fn arm_bound(config: &Configuration, service: &[u8]) -> bool {
    if config
        .get_yesno(service, b"IMMEDIATE_START")
        .is_ok_and(|value| value)
    {
        !config
            .get_yesno(service, b"NOARMBIND")
            .is_ok_and(|value| value)
    } else {
        config
            .get_yesno(service, b"START_ON_DEMAND")
            .is_ok_and(|value| value)
    }
}

#[cfg(unix)]
fn unix(path: &std::path::Path) -> Result<ServicePresence, ConnectError> {
    // Unlike ordinary CLIENT connection selection, this source operation never
    // shortens a long path. Validate the native sockaddr before socket creation.
    let address = SockAddr::unix(path)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    match socket.connect(&address) {
        Ok(()) => Ok(ServicePresence::LikelyUp),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Ok(ServicePresence::Down)
        }
        // The actual source treats EAGAIN/EACCES/ENOTSOCK/etc. as evidence of
        // presence. This is intentionally no stronger than its C counterpart.
        Err(_) => Ok(ServicePresence::LikelyUp),
    }
}

/// Test likely service presence with the official synchronous native semantics.
/// `Err` corresponds to source SYSERR, distinct from definitive Down. A Unix
/// connect may block just as in C; this operation supplies no fabricated timeout.
/// Every created socket is local to this call and closed before return.
pub fn test(config: &Configuration, service: &[u8]) -> Result<ServicePresence, ConnectError> {
    #[cfg(unix)]
    match config.get_filename(service, b"UNIXPATH", &ProcessEnvironment) {
        Ok(path) => {
            if path.as_os_str().is_empty() {
                return Err(gnunet_config::Error::InvalidValue.into());
            }
            if access(&path, AccessFlags::F_OK).is_ok() {
                if arm_bound(config, service) {
                    return Ok(ServicePresence::LikelyUp);
                }
                let result = unix(&path)?;
                if result != ServicePresence::Down {
                    return Ok(result);
                }
            }
            if !config.have_value(service, b"PORT") {
                return Ok(ServicePresence::Down);
            }
        }
        Err(error) if config.have_value(service, b"UNIXPATH") => return Err(error.into()),
        Err(_) => {}
    }
    let port = u16::try_from(config.get_number(service, b"PORT")?)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(gnunet_config::Error::InvalidValue)?;
    if config.get(service, b"HOSTNAME").is_some_and(|hostname| {
        !hostname.eq_ignore_ascii_case(b"localhost")
            && !hostname.eq_ignore_ascii_case(b"ip6-localnet")
    }) {
        // Numeric loopback spelling and empty hostname are also in this branch
        // in the actual source. Do not replace it with a DNS/address heuristic.
        return Ok(ServicePresence::LikelyUp);
    }
    let mut result = Ok(ServicePresence::Down);
    for (domain, address) in [
        (Domain::IPV4, SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        (Domain::IPV6, SocketAddr::from((Ipv6Addr::LOCALHOST, port))),
    ] {
        match Socket::new(domain, Type::STREAM, None) {
            Ok(socket) => {
                if socket.bind(&address.into()).is_err() {
                    result = Ok(ServicePresence::LikelyUp);
                }
            }
            Err(error) if domain == Domain::IPV4 => result = Err(ConnectError::Io(error)),
            // An unavailable IPv6 stack does not invalidate an IPv4 result.
            Err(_) => {}
        }
    }
    result
}
