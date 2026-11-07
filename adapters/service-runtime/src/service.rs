//! Shared listener references and service policy; no client or protocol engine.
use crate::acl::AccessPolicy;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UnixListener};

/// One caller-owned listening socket; no network protocol is added by this host.
#[derive(Clone, Copy, Debug)]
pub enum Listener<'a> {
    /// Local Unix-domain stream listener.
    Unix(&'a UnixListener),
    /// Official plain TCP service IPC listener.
    Tcp(&'a TcpListener),
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
