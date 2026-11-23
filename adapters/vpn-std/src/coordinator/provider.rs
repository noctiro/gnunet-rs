//! Caller-owned raw IP and routing sources for application VPN providers.
use gnunet_vpn::{Prefix, RouteAction};
use std::{
    io,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use tokio::time::Instant;

/// Original provider-scope and operation revision. A replacement provider cannot
/// acknowledge an earlier request, even when it receives a late platform callback.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId {
    epoch: NonZeroU64,
    revision: NonZeroU64,
}
impl RequestId {
    /// Numeric identity of the original device owner.
    #[must_use]
    pub const fn epoch(self) -> NonZeroU64 {
        self.epoch
    }

    /// Monotonically increasing operation identity in that original owner.
    #[must_use]
    pub const fn revision(self) -> NonZeroU64 {
        self.revision
    }
}

/// Original complete platform route/settings request.
#[derive(Clone, Copy, Debug)]
pub struct RouteRequest {
    /// Echo this exact token on completion.
    pub id: RequestId,
    /// Install this complete plan or remove its original effects.
    pub action: RouteAction,
    /// Requested address and routing prefix for IPv4.
    pub ipv4: Option<Prefix>,
    /// Requested address and routing prefix for IPv6.
    pub ipv6: Option<Prefix>,
    /// Original requested maximum interface packet size.
    pub mtu: u32,
    /// Finite deadline; a replacement request cannot extend it.
    pub deadline: Instant,
}

/// Result reported by the actual route/settings provider.
#[derive(Debug)]
pub enum RouteOutcome {
    /// The original complete settings were installed and are available.
    Installed,
    /// The exact original settings have been revoked and cannot apply late.
    Removed,
    /// A refusal or interruption at the native settings boundary.
    Failed {
        /// Original platform error.
        error: io::Error,
        /// Original scope is proved absent with no possibility of late install.
        routes_absent: bool,
    },
}

/// Exact original native routing completion, or a revocation carrying the ID
/// of the last installed settings.
#[derive(Debug)]
pub struct RouteCompletion {
    /// ID provided at admission.
    pub id: RequestId,
    /// Outcome observed at the platform settings boundary.
    pub outcome: RouteOutcome,
}

/// Exact original immutable raw packet request.
#[derive(Clone, Copy, Debug)]
pub struct PacketRequest {
    /// Echo this exact token on completion.
    pub id: RequestId,
    /// Original finite latest output time.
    pub deadline: Instant,
}

/// What happened to the original packet at the local platform boundary.
#[derive(Debug)]
pub enum PacketOutcome {
    /// The whole original raw packet was accepted locally.
    Written {
        /// Exact count of original raw IP bytes accepted.
        bytes: usize,
    },
    /// No data from the request was accepted.
    Unsent {
        /// Original cancellation, deadline or native refusal.
        error: io::Error,
    },
    /// The request may have been exposed and cannot be replayed.
    Unknown {
        /// Original native error.
        error: io::Error,
        /// Positive exposure evidence, including an opaque submission whose
        /// failure cannot exclude local acceptance.
        exposed: bool,
    },
}

/// Actual completion of the original packet request.
#[derive(Debug)]
pub struct PacketCompletion {
    /// ID provided at admission.
    pub id: RequestId,
    /// Original native packet outcome.
    pub outcome: PacketOutcome,
}

/// Independent facts after retiring the original platform source.
#[derive(Debug)]
pub struct CloseOutcome {
    /// The complete original settings are proved absent with no late effects.
    pub routes_absent: bool,
    /// Original independent packet/settings close error, if any.
    pub error: Option<io::Error>,
}

/// Original caller-owned platform packet and settings operations. Pending polls
/// register the caller's waker. Queue acceptance is distinct from native completion.
/// Implementations retain no more than one settings request and one packet write;
/// every completion reports its original request, including failures and retries.
/// `Removed` and `routes_absent` require the real original settings to be absent
/// with late callbacks unable to install them again. `close` retires packet I/O;
/// route uncertainty remains explicit. No callback may borrow input after return.
pub trait Provider {
    /// Admit the original settings command. Err proves it was not admitted.
    fn begin_route(&mut self, request: RouteRequest) -> io::Result<()>;
    /// Poll an actual native completion, or revocation of the installed request.
    fn poll_route(&mut self, cx: &mut Context<'_>) -> Poll<RouteCompletion>;
    /// Fence this exact request from further coordinator callbacks. A removal
    /// subsequently admitted by the provider must sequence behind its effects.
    fn cancel_route(&mut self, id: RequestId) -> RouteOutcome;
    /// Admit the immutable raw packet. Err proves it was not admitted.
    fn begin_write(&mut self, request: PacketRequest, packet: &[u8]) -> io::Result<()>;
    /// Poll the actual whole-write outcome for the original ID.
    fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<PacketCompletion>;
    /// Retire the same write without replay. Report uncertainty if cancellation
    /// cannot exclude exposure. Do not return `Unsent` merely for a timeout.
    fn cancel_write(&mut self, id: RequestId) -> PacketOutcome;
    /// Poll one complete raw IP packet, with None reporting actual source EOF.
    /// The size limit applies before copying or exposing a frame to the caller.
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        max_bytes: usize,
    ) -> Poll<io::Result<Option<Vec<u8>>>>;
    /// Physically retire the original packet source and report any route evidence.
    fn close(&mut self) -> CloseOutcome;
}

/// Owned provider scope. Each instance admits unique packet and route IDs.
pub struct Application {
    pub(super) driver: Box<dyn Provider>,
    epoch: NonZeroU64,
    next: u64,
    closed: bool,
}
impl Application {
    pub(super) fn new(provider: impl Provider + 'static) -> io::Result<Self> {
        Self::from_boxed(Box::new(provider)).map_err(|(error, mut provider)| {
            let _outcome = provider.close();
            error
        })
    }

    pub(super) fn from_boxed(
        driver: Box<dyn Provider>,
    ) -> Result<Self, (io::Error, Box<dyn Provider>)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let Some(epoch) = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()
            .and_then(NonZeroU64::new)
        else {
            return Err((io::Error::other("VPN provider epoch exhausted"), driver));
        };
        Ok(Self {
            driver,
            epoch,
            next: 1,
            closed: false,
        })
    }

    pub(super) fn issue(&mut self) -> io::Result<RequestId> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let revision = NonZeroU64::new(self.next)
            .ok_or_else(|| io::Error::other("VPN provider revision exhausted"))?;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("VPN provider revision exhausted"))?;
        Ok(RequestId {
            epoch: self.epoch,
            revision,
        })
    }

    /// Original provider scope's numeric identity.
    #[must_use]
    pub const fn epoch(&self) -> NonZeroU64 {
        self.epoch
    }

    pub(super) const fn current(&self) -> bool {
        !self.closed
    }

    /// Physically close this original provider once and transfer its actual outcome.
    pub fn close(&mut self) -> Option<CloseOutcome> {
        if std::mem::replace(&mut self.closed, true) {
            return None;
        }
        Some(self.driver.close())
    }
}
impl Drop for Application {
    fn drop(&mut self) {
        let _outcome = self.close();
    }
}
