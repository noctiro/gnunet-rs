//! Original packet owner. Helper pipe acceptance is not a kernel TUN receipt.
use super::*;
/// Exactly one actual native descriptor or official helper process/pipe source.
#[expect(
    clippy::large_enum_variant,
    reason = "One linear original physical owner remains inline; refusal and cleanup need no additional fallible allocation"
)]
pub enum PacketSource {
    /// Kernel-qualified original native TUN/utun owner.
    Native(tun::AsyncTun),
    /// Original helper child, pipes, immutable frame and actual wait authority.
    Helper(tun::helper::Link),
}
impl PacketSource {
    /// Register the actual verified descriptor on the caller's runtime.
    pub fn native(owner: tun::OwnedTun) -> io::Result<Self> {
        tun::AsyncTun::new(owner).map(Self::Native)
    }
    /// Adopt an actual already-spawned helper owner, never fabricate a process.
    #[must_use]
    pub fn helper(owner: tun::helper::Link) -> Self {
        Self::Helper(owner)
    }
    /// Original lifetime, not administrative authority or process-ready proof.
    #[must_use]
    pub fn epoch(&self) -> tun::Epoch {
        match self {
            Self::Native(io) => io.epoch(),
            Self::Helper(io) => io.epoch(),
        }
    }
    /// Actual native metadata; helper index is initially zero until observation.
    #[must_use]
    pub fn info(&self) -> &tun::Info {
        match self {
            Self::Native(io) => io.info(),
            Self::Helper(io) => io.info(),
        }
    }
    /// Whether packet writes target an actual helper stdin pipe.
    #[must_use]
    pub fn is_helper(&self) -> bool {
        matches!(self, Self::Helper(_))
    }
    pub(super) fn poll_prepare(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tun::AdminFailure>> {
        match self {
            Self::Native(_) => Poll::Ready(Ok(())),
            Self::Helper(io) => io.poll_prepare(cx),
        }
    }
    pub(super) fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<tun::ReadEvent> {
        match self {
            Self::Native(_) => None,
            Self::Helper(io) => io.poll_native_guard(cx),
        }
    }
    pub(super) fn queue(&mut self, bytes: &[u8], until: Instant) -> io::Result<tun::WriteId> {
        match self {
            Self::Native(io) => io.queue(bytes, until),
            Self::Helper(io) => io.queue(bytes, until),
        }
    }
    pub(super) fn cancel(&mut self, id: &tun::WriteId) -> io::Result<tun::WriteEvent> {
        match self {
            Self::Native(io) => io.cancel(id),
            Self::Helper(io) => io.cancel(id),
        }
    }
    pub(super) fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<tun::ReadEvent> {
        match self {
            Self::Native(io) => io.poll_read(cx),
            Self::Helper(io) => io.poll_read(cx),
        }
    }
    pub(super) fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<tun::WriteEvent> {
        match self {
            Self::Native(io) => io.poll_write(cx),
            Self::Helper(io) => io.poll_write(cx),
        }
    }
    pub(super) fn plan(&mut self, action: tun::Action, until: Instant) -> io::Result<tun::Effect> {
        match self {
            Self::Native(io) => io.plan(action, until),
            Self::Helper(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper-owned configuration is read-only in EXIT",
            )),
        }
    }
    pub(super) fn apply(
        &mut self,
        effect: tun::Effect,
    ) -> Result<tun::NativeApplied, tun::ApplyFailure> {
        match self {
            Self::Native(io) => io.apply(effect),
            Self::Helper(_) => Err(tun::ApplyFailure {
                effect,
                error: io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "helper-owned configuration is read-only in EXIT",
                ),
                attempted: false,
            }),
        }
    }
    pub(super) fn route(
        &mut self,
        effect: tun::Effect,
    ) -> Result<tun::NativeRoute, tun::ApplyFailure> {
        match self {
            Self::Native(io) => io.route(effect),
            Self::Helper(_) => Err(tun::ApplyFailure {
                effect,
                error: io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "helper-owned configuration is read-only in EXIT",
                ),
                attempted: false,
            }),
        }
    }
    pub(super) fn watch_ipv6(
        &self,
        address: Ipv6Addr,
        prefix: u8,
        until: Instant,
        options: tun::Ipv6WatchOptions,
    ) -> io::Result<tun::Ipv6Watch> {
        match self {
            Self::Native(io) => io.watch_ipv6(address, prefix, until, options),
            Self::Helper(io) => io.watch_ipv6(address, prefix, until, options),
        }
    }
    pub(super) fn snapshot(
        &self,
        until: Instant,
    ) -> Result<tun::NativeSnapshot, tun::AdminFailure> {
        match self {
            Self::Native(io) => io.snapshot(until),
            Self::Helper(io) => io.snapshot(until),
        }
    }
    pub(super) fn query(
        &self,
        destination: std::net::IpAddr,
        prefix: u8,
        gateway: Option<std::net::IpAddr>,
        until: Instant,
    ) -> Result<tun::RouteQuery, tun::AdminFailure> {
        match self {
            Self::Native(io) => io.query_route(destination, prefix, gateway, until),
            Self::Helper(io) => io.query_route(destination, prefix, gateway, until),
        }
    }
    /// Close original packet transport. Helper close only requests process stop.
    pub fn close(&mut self) -> tun::Loss {
        match self {
            Self::Native(io) => io.close(),
            Self::Helper(io) => io.close(),
        }
    }
    /// Actual original helper wait result. Never call pipe close or Drop reap.
    pub async fn reap_helper(&mut self) -> Option<tun::helper::Report> {
        match self {
            Self::Native(_) => None,
            Self::Helper(io) => io.reap().await,
        }
    }
}
