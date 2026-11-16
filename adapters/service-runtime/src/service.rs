//! Shared listener references and service policy; no client or protocol engine.
use crate::acl::AccessPolicy;
#[cfg(any(unix, windows))]
use crate::local::Listener as UnixListener;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// One caller-owned listening socket; no network protocol is added by this host.
#[derive(Clone, Copy, Debug)]
pub enum Listener<'a> {
    /// Local Unix-domain stream listener.
    #[cfg(any(unix, windows))]
    Unix(&'a UnixListener),
    /// Official plain TCP service IPC listener.
    Tcp(&'a TcpListener),
}
impl Listener<'_> {
    /// Nonconsuming current accept-backlog/exceptional events. No connection is
    /// accepted and no service demand or listener ownership is manufactured.
    #[cfg(any(unix, windows))]
    pub fn level_readiness(self) -> std::io::Result<Option<crate::readiness::SocketEvents>> {
        #[cfg(unix)]
        let original = match self {
            Self::Unix(listener) => std::os::fd::AsFd::as_fd(listener),
            Self::Tcp(listener) => std::os::fd::AsFd::as_fd(listener),
        };
        #[cfg(windows)]
        let original = match self {
            Self::Unix(listener) => std::os::windows::io::AsSocket::as_socket(listener),
            Self::Tcp(listener) => std::os::windows::io::AsSocket::as_socket(listener),
        };
        gnunet_native::network::socket_readiness(
            original,
            crate::readiness::SocketInterest::Readable,
        )
    }
}
/// Actual remote address supplied by accept, before core admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAddress {
    /// Filesystem-controlled local Unix peer.
    Unix,
    /// IPv4 or IPv6 TCP peer, including its OS source port.
    Tcp(SocketAddr),
}
/// Official service shutdown lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum ShutdownMode {
    /// Stop all existing clients immediately when shutdown is requested.
    #[default]
    Immediate,
    /// Stop accepting and drain non-monitor clients before closing WATCH peers.
    Soft,
}
/// Service-level policies independent of explicit memory/connection capacities.
#[derive(Clone, Debug, Default)]
pub struct ServiceOptions {
    /// IPv4/IPv6 address policies; Unix remains filesystem-controlled.
    pub access: AccessPolicy,
    /// Ignore unknown message types when true. Malformed known requests still fail.
    pub tolerant: bool,
    /// Reference service lifetime after a shutdown request.
    pub shutdown: ShutdownMode,
}
