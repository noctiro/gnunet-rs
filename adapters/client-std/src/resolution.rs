//! Explicit process-shared official Resolver callbacks for generic CLIENT.
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
/// A real logical-source timer. Drop cancels only this timer, not a DNS request.
pub type ResolutionTimer = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
/// Callback stream for one original shared forward request, without private MQ.
pub trait AddressLookup: Send {
    /// Poll one address upcall or actual final NULL. For an address, retain
    /// callback authority until address_effect_done acknowledges its real socket
    /// effect. NULL is consumed synchronously and is never manufactured.
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<IpAddr>>>;
    /// Poll the same original address upcall with native IPv6 scope and flow
    /// information intact. CLIENT replaces only its port with the configured
    /// service port before starting the socket attempt. The default lifts one
    /// IP-only callback to an unscoped socket address; it neither polls twice nor
    /// acknowledges the callback. The same address_effect_done/connected lease
    /// contract applies to both observation methods.
    fn poll_socket_addr(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<SocketAddr>>> {
        self.poll_next(cx)
            .map(|result| result.map(|address| address.map(|ip| SocketAddr::new(ip, 0))))
    }
    /// Return the current address callback only after creating/starting its
    /// native socket attempt. The next poll may continue the same original
    /// numeric/loopback callback stack; it must not dispatch unrelated tasks.
    fn address_effect_done(&mut self) -> io::Result<()>;
    /// Ignore later address callbacks while retaining the original subscription
    /// until actual END/timeout or service connection destruction, like client.c.
    fn connected(
        self: Box<Self>,
    ) -> io::Result<Box<dyn gnunet_service_runtime::connection::ConnectionLease>>;
}
/// Independent process Resolver selection, shared across all CLIENT MQs.
/// Implementations must use official Resolver semantics, never host DNS as a
/// substitute for ordinary lookups. CLIENT service configuration is independent.
pub trait ResolutionContext: Send + Sync {
    /// The same canonical process clock source used by this resolver domain.
    /// Cloning shares source identity only; every host reserves its own waiter.
    fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock>;
    /// Start one AF_UNSPEC lookup. None means native ip_get returned no handle;
    /// it is not a final NULL callback and must not fabricate connect failure.
    fn lookup(
        &self,
        hostname: &[u8],
        timeout: Duration,
    ) -> io::Result<Option<Box<dyn AddressLookup>>>;
    /// Start one actual AF_INET-only forward lookup for protocols such as SOCKS4.
    /// This explicit capability never consumes an unused IPv6 callback as if it
    /// produced a socket effect. Older caller ports refuse it without an effect.
    fn lookup_ipv4(
        &self,
        _hostname: &[u8],
        _timeout: Duration,
    ) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv4-only shared Resolver port unavailable",
        ))
    }
    /// Schedule one original logical-source timeout, including clock revisions.
    fn timer(&self, duration: Duration) -> io::Result<ResolutionTimer>;
}
/// Caller-declared address-probe resources; no GNUnet configuration key/wire field.
#[derive(Clone, Copy, Debug)]
pub struct ResolutionLimits {
    /// Total probes admitted by one physical attempt. This is not a DNS limit.
    pub max_address_probes: usize,
}
impl Default for ResolutionLimits {
    fn default() -> Self {
        Self {
            max_address_probes: 32,
        }
    }
}
/// Shared selected Resolver context; cloning never opens a connection.
pub type SharedResolution = Arc<dyn ResolutionContext>;

/// Exact origin marker for a refused caller-owned resolution/time resource.
///
/// The original I/O error remains available through [`Self::cause`] and the
/// standard error source chain. Its kind alone never identifies this boundary:
/// a native socket can report the same kind. Cloning retains the same cause,
/// without issuing a new lookup, timer, socket attempt or callback.
#[derive(Clone, Debug)]
pub struct PortError(Arc<io::Error>);
impl PortError {
    /// Borrow an exact marker carried by this error, without classifying by kind.
    #[must_use]
    pub fn from_io(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
    /// Retain the original cause and mark the call boundary exactly once.
    #[must_use]
    pub fn mark(error: io::Error) -> io::Error {
        if Self::from_io(&error).is_some() {
            error
        } else {
            Self(Arc::new(error)).to_io()
        }
    }
    /// The original error supplied by the resolution or logical timer port.
    #[must_use]
    pub fn cause(&self) -> &io::Error {
        &self.0
    }
    /// Another report of this same terminal refusal; this performs no I/O.
    #[must_use]
    pub fn to_io(&self) -> io::Error {
        io::Error::new(self.0.kind(), self.clone())
    }
}
impl std::fmt::Display for PortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "CLIENT resolution/time port: {}", self.0)
    }
}
impl std::error::Error for PortError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}
