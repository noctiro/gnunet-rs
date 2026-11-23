//! One DNSSTUB interface over standard sockets or original provider connections.
use crate::{UPSTREAM_SOCKETS, core};
use gnunet_dnsstub_host::{
    Admission, HostError, RequestId, ServerId, SocketId, Stopped, UnverifiedDatagram,
};
pub use gnunet_dnsstub_host::{Discard, Flow, Progress};
use gnunet_types::Error;
use std::{
    io,
    net::SocketAddr,
    task::{Context, Poll},
};
use tokio::time::Instant;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod provider;
/// Original standard DNSSTUB owner, used for actual bound socket reservations.
pub type Standard = gnunet_dnsstub_host::DnsStub<UPSTREAM_SOCKETS, { core::MAX_DNS_BYTES }, 4>;

/// Fixed original native readiness and submitted-send bounds.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[derive(Clone, Copy, Debug)]
pub struct ProviderUpstreamLimits {
    /// Initial readiness and each observed Ready-to-Waiting interval.
    pub readiness_timeout: std::time::Duration,
    /// Actual SDK send admission through completion/disposal observation.
    pub send_timeout: std::time::Duration,
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
impl Default for ProviderUpstreamLimits {
    fn default() -> Self {
        Self {
            readiness_timeout: std::time::Duration::from_secs(5),
            send_timeout: std::time::Duration::from_secs(30),
        }
    }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
impl ProviderUpstreamLimits {
    fn validate(self) -> Result<Self, Error> {
        let now = Instant::now();
        for duration in [self.readiness_timeout, self.send_timeout] {
            if duration.is_zero() || now.checked_add(duration).is_none() {
                return Err(Error::InvalidInput);
            }
        }
        Ok(self)
    }
}
/// Original send exceeded its fixed deadline; callback retirement is separate.
/// A present completion retains a late actual SDK result, not a timely success.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[derive(Debug)]
pub struct SendExpired {
    /// None means native acceptance was still unknown at expiry.
    pub completion: Option<io::Result<()>>,
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
impl std::fmt::Display for SendExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original native DNS send expired; completion={:?}",
            self.completion
        )
    }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
impl std::error::Error for SendExpired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.completion
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as &dyn std::error::Error)
    }
}

/// Actual native or standard I/O observations; no local bind address is invented.
#[derive(Debug)]
pub enum Event<'a> {
    /// Original standard socket or provider family/peer cache became ready.
    SocketOpened {
        /// Original pure DNSSTUB family-cache generation.
        socket: SocketId,
        /// Actual local preparation/connection readiness result.
        result: io::Result<()>,
    },
    /// Original send result, admission refusal or fixed-deadline expiry.
    /// Expiry retains any pending native callback loan independently.
    Sent {
        /// Original request owning the send, even if subsequently canceled.
        request: RequestId,
        /// Original family-cache generation.
        socket: SocketId,
        /// Actual configured destination.
        destination: SocketAddr,
        /// Original local acceptance result; no response acknowledgement.
        result: io::Result<usize>,
    },
    /// Raw original peer data matched by the shared DNSSTUB core.
    Datagram(UnverifiedDatagram<'a>),
    /// One datagram failed the unchanged core or response bound.
    Discarded {
        /// Original family-cache generation.
        socket: SocketId,
        /// Actual standard sender or fixed original native connection peer.
        source: SocketAddr,
        /// Original rejection.
        reason: Discard,
    },
    /// An isolated native receive rejection leaves the cache retained.
    ReceiveRejected {
        /// Original cache generation.
        socket: SocketId,
        /// Actual native error.
        error: io::Error,
    },
    /// One fixed native peer failed; other peers and callbacks remain live.
    PeerUnavailable {
        /// Original family-cache generation.
        socket: SocketId,
        /// Actual failed configured endpoint.
        destination: SocketAddr,
        /// Original native state or read error.
        error: io::Error,
    },
    /// A failed cache is invalidated; outstanding native loans still retire.
    ReceiveFailed {
        /// Invalidated original family-cache generation.
        socket: SocketId,
        /// Actual native error.
        error: io::Error,
    },
}
impl<'a> From<gnunet_dnsstub_host::Event<'a>> for Event<'a> {
    fn from(event: gnunet_dnsstub_host::Event<'a>) -> Self {
        use gnunet_dnsstub_host::Event as StandardEvent;
        match event {
            StandardEvent::SocketOpened { socket, result } => Self::SocketOpened {
                socket,
                result: result.map(|_| ()),
            },
            StandardEvent::Sent {
                request,
                socket,
                destination,
                result,
            } => Self::Sent {
                request,
                socket,
                destination,
                result,
            },
            StandardEvent::Datagram(data) => Self::Datagram(data),
            StandardEvent::Discarded {
                socket,
                source,
                reason,
            } => Self::Discarded {
                socket,
                source,
                reason,
            },
            StandardEvent::ReceiveRejected { socket, error } => {
                Self::ReceiveRejected { socket, error }
            }
            StandardEvent::ReceiveFailed { socket, error } => Self::ReceiveFailed { socket, error },
        }
    }
}
/// Original upstream shutdown observations, independently from interception source.
#[derive(Debug, Default)]
pub struct UpstreamRetirement {
    /// Native connections whose final cancellation and callback loans retired.
    pub native_connections: u64,
    /// Failed native retirement receipts.
    pub failures: u64,
    /// First independent native retirement failure, when present.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub first: Option<gnunet_native::dns_proxy::ConnectionRetirement>,
}
impl UpstreamRetirement {
    /// Whether original connection retirement observed any failure.
    pub const fn has_failure(&self) -> bool {
        self.failures != 0
    }
}
enum Backend {
    Standard(Box<Standard>),
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    Provider(Box<provider::Provider>),
}
/// Bounded DNSSTUB owner with one shared query/retry/callback state machine.
/// Provider mode uses Network.framework and requires original session authority.
pub struct Upstream {
    backend: Backend,
    retirement_taken: bool,
}
impl Upstream {
    /// Construct the standard owner without opening sockets or sending packets.
    /// # Errors
    /// Preserves standard DNSSTUB slot and response-bound validation.
    pub fn start(slots: usize, maximum: usize) -> Result<Self, Error> {
        Ok(Self {
            backend: Backend::Standard(Box::new(Standard::start(slots, maximum)?)),
            retirement_taken: false,
        })
    }
    /// Construct provider DNSSTUB state; connections open lazily during drive.
    /// # Errors
    /// Refuses invalid bounds or bounded allocation failure; session authority is checked before each lazy connection.
    /// # Panics
    /// Requires an entered Tokio runtime with time enabled.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn start_provider(
        session: gnunet_native::dns_proxy::provider::Session,
        slots: usize,
        maximum: usize,
        limits: ProviderUpstreamLimits,
    ) -> Result<Self, HostError> {
        Ok(Self {
            backend: Backend::Provider(Box::new(provider::Provider::start(
                session, slots, maximum, limits,
            )?)),
            retirement_taken: false,
        })
    }
    /// Whether this owner uses the native provider connection path.
    pub fn is_provider(&self) -> bool {
        match self.backend {
            Backend::Standard(_) => false,
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(_) => true,
        }
    }
    /// Borrow the actual standard owner for bound-socket lease checks.
    pub fn standard_owner(&self) -> Option<&Standard> {
        match &self.backend {
            Backend::Standard(owner) => Some(owner),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(_) => None,
        }
    }
    /// Borrow the actual standard owner for pre-capture socket reservation.
    pub fn standard_owner_mut(&mut self) -> Option<&mut Standard> {
        match &mut self.backend {
            Backend::Standard(owner) => Some(owner),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(_) => None,
        }
    }
    /// Add an explicit endpoint at the unchanged DNSSTUB list head.
    /// # Errors
    /// Preserves configured server capacity and stopped-owner validation.
    pub fn add_dns_sa(&mut self, address: SocketAddr) -> Result<ServerId, Error> {
        match &mut self.backend {
            Backend::Standard(owner) => owner.add_dns_sa(address),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.add_dns_sa(address),
        }
    }
    /// Change future retry intervals without resetting an already due attempt.
    /// # Errors
    /// Preserves the shared DNSSTUB duration and stopped-owner checks.
    pub fn set_retry(&mut self, retry: gnunet_types::Duration) -> Result<(), Error> {
        match &mut self.backend {
            Backend::Standard(owner) => owner.set_retry(retry),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.set_retry(retry),
        }
    }
    /// Number of current resolver callback owners, independent of duplicate data.
    pub fn pending_requests(&self) -> usize {
        match &self.backend {
            Backend::Standard(owner) => owner.pending_requests(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.pending_requests(),
        }
    }
    /// Configured request/cache slot count.
    pub fn slot_count(&self) -> usize {
        match &self.backend {
            Backend::Standard(owner) => owner.slot_count(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.slot_count(),
        }
    }
    /// Whether logical requests and future admissions have stopped.
    pub fn is_stopped(&self) -> bool {
        match &self.backend {
            Backend::Standard(owner) => owner.is_stopped(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.is_stopped(),
        }
    }
    /// Admit a query without network I/O using unbiased operating-system entropy.
    /// # Errors
    /// Preserves query, clock, capacity and entropy failures before admission.
    #[must_use = "Inspect evicted to retire the original replaced resolver callback."]
    pub fn resolve(&mut self, bytes: &[u8]) -> Result<Admission, HostError> {
        match &mut self.backend {
            Backend::Standard(owner) => owner.resolve(bytes),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.resolve(bytes),
        }
    }
    /// Cancel only the exact original callback; cached native owners remain live.
    /// # Errors
    /// Refuses stale or foreign request identities.
    pub fn resolve_cancel(&mut self, request: RequestId) -> Result<(), Error> {
        match &mut self.backend {
            Backend::Standard(owner) => owner.resolve_cancel(request),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.resolve_cancel(request),
        }
    }
    /// Invalidate logical callback authority and request original native cancellation.
    pub fn stop(&mut self) -> Stopped {
        match &mut self.backend {
            Backend::Standard(owner) => owner.stop(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.stop(),
        }
    }
    /// Synchronously obtain standard socket retirement after logical stop.
    pub fn take_immediate_retirement(&mut self) -> Option<UpstreamRetirement> {
        if self.retirement_taken || !self.is_stopped() || self.is_provider() {
            return None;
        }
        self.retirement_taken = true;
        Some(UpstreamRetirement::default())
    }
    /// Observe actual original cancellation and final callback disposal.
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<UpstreamRetirement> {
        if self.retirement_taken || !self.is_stopped() {
            return Poll::Pending;
        }
        let result = match &mut self.backend {
            Backend::Standard(_) => Poll::Ready(UpstreamRetirement::default()),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.poll_retirement(cx),
        };
        if result.is_ready() {
            self.retirement_taken = true;
        }
        let _ = cx;
        result
    }
    /// Observe existing native sends/readiness, fixed deadlines and retirement
    /// before canonical-clock work. It never starts I/O or consumes active reads.
    /// # Errors
    /// Returns original core/correlation errors without fabricating a response.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        mut callback: impl FnMut(Event<'_>) -> Flow,
    ) -> Poll<Result<Progress, HostError>> {
        match &mut self.backend {
            Backend::Standard(_) => {
                let _ = (cx, &mut callback);
                Poll::Pending
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => owner.poll_native_guard(cx, &mut callback),
        }
    }
    /// Drive original sends/retries/datagrams; canceled waits retain all owners.
    /// # Errors
    /// Returns core scheduling, clock or bounded host failures; no answer is fabricated.
    pub async fn drive(
        &mut self,
        deadline: Option<Instant>,
        mut callback: impl FnMut(Event<'_>) -> Flow,
    ) -> Result<Progress, HostError> {
        match &mut self.backend {
            Backend::Standard(owner) => {
                owner
                    .drive(deadline, |event, _| callback(event.into()))
                    .await
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Provider(owner) => {
                std::future::poll_fn(|cx| owner.poll(cx, deadline, &mut callback)).await
            }
        }
    }
}
impl Drop for Upstream {
    fn drop(&mut self) {
        let _stopped = self.stop();
    }
}

#[cfg(test)]
mod tests;
