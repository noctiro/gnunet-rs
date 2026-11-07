//! Actual owned device provenance; metadata claims never manufacture a new FD.
use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Provenance {
    Created,
    Borrowed,
    Helper,
}
/// One actual native TUN or helper packet owner and its restricted policy.
/// Native constructors allocate a new nonpersistent kernel interface; a helper
/// constructor owns a process/pipe source with separately observed native state.
/// Externally supplied/helper-owned configuration is never silently rewritten.
pub struct Device {
    pub(super) io: PacketIo,
    pub(super) provenance: Provenance,
}
impl Device {
    /// Adopt an already verified actual device for unchanged-plan verification.
    /// It must match the real desired snapshot/routes/DAD; no native write is
    /// performed to overwrite another owner's configuration or route on mismatch.
    #[must_use]
    pub fn borrow_existing(tun: tun::AsyncTun) -> Self {
        Self {
            io: PacketIo::Native(tun),
            provenance: Provenance::Borrowed,
        }
    }
    /// Linux: allocate a new kernel-selected nonpersistent TUN. Exclusivity is
    /// enforced in the same native TUNSETIFF; capability/errno refusal is retained.
    #[cfg(target_os = "linux")]
    pub fn open_linux(packet_information: bool, limits: tun::Limits) -> io::Result<Self> {
        Self::open_linux_named_exclusive(None, packet_information, limits)
    }
    /// Linux: exclusively create the requested new interface, or select a fresh
    /// kernel name for None. A preexisting named device is never adopted as
    /// Created, reconfigured, or cleaned by this constructor. No fallback opens it.
    #[cfg(target_os = "linux")]
    pub fn open_linux_named_exclusive(
        name: Option<&str>,
        packet_information: bool,
        limits: tun::Limits,
    ) -> io::Result<Self> {
        let tun = tun::OwnedTun::open_linux_exclusive(name, packet_information, limits)?;
        Ok(Self {
            io: PacketIo::Native(tun::AsyncTun::new(tun)?),
            provenance: Provenance::Created,
        })
    }
    /// macOS: allocate a new kernel-selected utun. No address/route is configured.
    #[cfg(target_os = "macos")]
    pub fn open_utun(limits: tun::Limits) -> io::Result<Self> {
        Self::open_utun_unit(None, limits)
    }
    /// macOS: create the actual requested utunN unit, or request a fresh unit for
    /// None. An occupied unit must fail its native controller connect. No arbitrary
    /// interface name is accepted or silently renamed into Created provenance.
    #[cfg(target_os = "macos")]
    pub fn open_utun_unit(unit: Option<u32>, limits: tun::Limits) -> io::Result<Self> {
        let tun = tun::OwnedTun::open_utun(unit, limits)?;
        if let Some(unit) = unit
            && tun.info().name != format!("utun{unit}")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "actual utun interface differs from the requested unit",
            ));
        }
        Ok(Self {
            io: PacketIo::Native(tun::AsyncTun::new(tun)?),
            provenance: Provenance::Created,
        })
    }
    /// Original actual device identity; cloning this metadata does not clone FD.
    #[must_use]
    pub fn epoch(&self) -> tun::Epoch {
        self.io.epoch()
    }
    /// Actual kernel-verified immutable interface name/index/mode.
    #[must_use]
    pub fn info(&self) -> &tun::Info {
        self.io.info()
    }
    /// Recover the same unique packet owner, never rebinding its old epoch. A
    /// spawned helper may already be configuring the OS and must be closed and
    /// actually reaped after a failed coordinator build.
    pub fn into_io(self) -> PacketIo {
        self.io
    }
}

/// The original actual packet owner. Helper pipe acceptance is distinguished
/// from a native TUN syscall and never treated as helper kernel completion.
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded original packet source lives inline for the coordinator lifetime; avoid a heap allocation solely to equalize native/helper variant sizes"
)]
pub enum PacketIo {
    /// Actual kernel-verified TUN/utun descriptor.
    Native(tun::AsyncTun),
    /// Actual official helper child and its original typed packet pipes.
    Helper(tun::helper::Link),
}
impl Device {
    /// Start the actual helper. No process-ready/configuration ACK is invented;
    /// the coordinator still queries native snapshot/routes and IPv6 DAD.
    pub fn start_helper(options: tun::helper::Options, limits: tun::Limits) -> io::Result<Self> {
        Ok(Self {
            io: PacketIo::Helper(tun::helper::Link::spawn(options, limits)?),
            provenance: Provenance::Helper,
        })
    }
}
impl PacketIo {
    /// Original packet source lifetime.
    #[must_use]
    pub fn epoch(&self) -> tun::Epoch {
        match self {
            Self::Native(io) => io.epoch(),
            Self::Helper(io) => io.epoch(),
        }
    }
    /// Actual native metadata; helper index is zero until initial observation.
    #[must_use]
    pub fn info(&self) -> &tun::Info {
        match self {
            Self::Native(io) => io.info(),
            Self::Helper(io) => io.info(),
        }
    }
    pub(super) fn is_helper(&self) -> bool {
        matches!(self, Self::Helper(_))
    }
    pub(super) fn accepts_mtu(&self, observed: u32, configured: u32) -> bool {
        match self {
            Self::Native(_) => observed == configured,
            Self::Helper(io) => io.accepts_mtu(observed),
        }
    }
    pub(super) fn initial_deadline(&self) -> Option<Instant> {
        match self {
            Self::Native(_) => None,
            Self::Helper(io) => Some(io.initial_deadline()),
        }
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
    pub(super) fn snapshot(
        &self,
        until: Instant,
    ) -> Result<tun::NativeSnapshot, tun::AdminFailure> {
        match self {
            Self::Native(io) => io.snapshot(until),
            Self::Helper(io) => io.snapshot(until),
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
    pub(super) fn query_route(
        &self,
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        until: Instant,
    ) -> Result<tun::RouteQuery, tun::AdminFailure> {
        match self {
            Self::Native(io) => io.query_route(destination, prefix, gateway, until),
            Self::Helper(io) => io.query_route(destination, prefix, gateway, until),
        }
    }
    pub(super) fn plan(&mut self, action: tun::Action, until: Instant) -> io::Result<tun::Effect> {
        match self {
            Self::Native(io) => io.plan(action, until),
            Self::Helper(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper-owned device is read-only in service",
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
                    "helper-owned device is read-only in service",
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
                    "helper-owned device is read-only in service",
                ),
                attempted: false,
            }),
        }
    }
    pub(super) fn queue(&mut self, raw: &[u8], until: Instant) -> io::Result<tun::WriteId> {
        match self {
            Self::Native(io) => io.queue(raw, until),
            Self::Helper(io) => io.queue(raw, until),
        }
    }
    pub(super) fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<tun::WriteEvent> {
        match self {
            Self::Native(io) => io.poll_write(cx),
            Self::Helper(io) => io.poll_write(cx),
        }
    }
    pub(super) fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<tun::ReadEvent> {
        match self {
            Self::Native(io) => io.poll_read(cx),
            Self::Helper(io) => io.poll_read(cx),
        }
    }
    /// Close original descriptor/pipes. For Helper this only requests stop;
    /// caller must separately reap the same child, even on a failed build.
    pub fn close(&mut self) -> tun::Loss {
        match self {
            Self::Native(io) => io.close(),
            Self::Helper(io) => io.close(),
        }
    }
    /// Wait the same original helper process after close, never a replacement PID.
    pub async fn reap_helper(&mut self) -> Option<tun::helper::Report> {
        match self {
            Self::Native(_) => None,
            Self::Helper(io) => io.reap().await,
        }
    }
}
