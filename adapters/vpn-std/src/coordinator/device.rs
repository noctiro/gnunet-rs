//! Actual owned device provenance; metadata claims never manufacture a new FD.
use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Provenance {
    Created,
    Borrowed,
    #[cfg(unix)]
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
    /// Adopt an actual Wintun session. Its provider-recorded creation origin
    /// selects administrative responsibility: the first session of a created adapter
    /// may be configured; restarted and explicitly opened sessions are verified unchanged.
    #[cfg(windows)]
    pub fn from_wintun(session: tun::wintun::Session, limits: tun::Limits) -> io::Result<Self> {
        let provenance = match session.adapter().origin() {
            tun::wintun::Origin::Created if session.kind() == tun::wintun::SessionKind::First => {
                Provenance::Created
            }
            tun::wintun::Origin::Created => Provenance::Borrowed,
            tun::wintun::Origin::Opened => Provenance::Borrowed,
        };
        let owner = tun::OwnedTun::from_wintun(session, limits)?;
        Ok(Self {
            io: PacketIo::Native(tun::AsyncTun::new(owner)?),
            provenance,
        })
    }
    /// Restart the retained original Windows adapter with a fresh packet epoch.
    /// Existing configuration is verified, never replayed as fresh provisioning.
    #[cfg(windows)]
    pub fn recover_wintun(recovery: tun::WintunRecovery) -> Result<Self, tun::WintunRestartError> {
        Ok(Self {
            io: PacketIo::Native(recovery.restart()?),
            provenance: Provenance::Borrowed,
        })
    }
    /// Refresh a same-scope packet handle while retaining original native
    /// creation lifetime. Configuration remains an unchanged-plan observation.
    #[cfg(windows)]
    pub fn refresh_wintun(recovery: tun::WintunRecovery) -> Result<Self, tun::WintunRestartError> {
        Ok(Self {
            io: PacketIo::Native(recovery.refresh_scope()?),
            provenance: Provenance::Borrowed,
        })
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
    /// FreeBSD: exclusively create a fresh TUN, optionally with the exact name.
    /// Native rename and interface cleanup stay attached to the original owner.
    /// An occupied name is never adopted or reconfigured as Created provenance.
    #[cfg(target_os = "freebsd")]
    pub fn open_freebsd_exclusive(name: Option<&str>, limits: tun::Limits) -> io::Result<Self> {
        let tun = tun::OwnedTun::open_freebsd_exclusive(name, limits)?;
        Ok(Self {
            io: PacketIo::Native(tun::AsyncTun::new(tun)?),
            provenance: Provenance::Created,
        })
    }
    /// FreeBSD: checkpoint admission and actual native identity before packet
    /// use, retiring the previous saved owner before allocating another TUN.
    /// The checkpoint parent must already exist privately; unresolved intents
    /// fence recreation. Native and checkpoint errors retain their owners.
    #[cfg(target_os = "freebsd")]
    pub fn open_freebsd_recoverable(
        name: Option<&str>,
        checkpoint: &std::path::Path,
        limits: tun::Limits,
    ) -> io::Result<Self> {
        let tun = tun::OwnedTun::open_freebsd_recoverable(name, checkpoint, limits)
            .map_err(io::Error::other)?;
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
#[cfg_attr(
    unix,
    expect(
        clippy::large_enum_variant,
        reason = "One bounded original packet source lives inline for the coordinator lifetime; avoid a heap allocation solely to equalize native/helper variant sizes"
    )
)]
pub enum PacketIo {
    /// Actual kernel-verified TUN/utun descriptor.
    Native(tun::AsyncTun),
    /// Actual official helper child and its original typed packet pipes.
    #[cfg(unix)]
    Helper(tun::helper::Link),
}
impl Device {
    /// Start the actual helper. No process-ready/configuration ACK is invented;
    /// the coordinator still queries native snapshot/routes and IPv6 DAD.
    #[cfg(unix)]
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
            #[cfg(unix)]
            Self::Helper(io) => io.epoch(),
        }
    }
    /// Actual native metadata; helper index is zero until initial observation.
    #[must_use]
    pub fn info(&self) -> &tun::Info {
        match self {
            Self::Native(io) => io.info(),
            #[cfg(unix)]
            Self::Helper(io) => io.info(),
        }
    }
    pub(super) fn is_helper(&self) -> bool {
        match self {
            Self::Native(_) => false,
            #[cfg(unix)]
            Self::Helper(_) => true,
        }
    }
    pub(super) fn accepts_mtu(&self, observed: &tun::NativeSnapshot, configured: u32) -> bool {
        match self {
            Self::Native(_) => {
                let wanted = observed.options();
                (!wanted.ipv4 || observed.ip_mtu(tun::Version::V4) == Some(configured))
                    && (!wanted.ipv6 || observed.ip_mtu(tun::Version::V6) == Some(configured))
            }
            #[cfg(unix)]
            Self::Helper(io) => io.accepts_mtu(observed.link_mtu()),
        }
    }
    pub(super) fn initial_deadline(&self) -> Option<Instant> {
        match self {
            Self::Native(_) => None,
            #[cfg(unix)]
            Self::Helper(io) => Some(io.initial_deadline()),
        }
    }
    pub(super) fn poll_prepare(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tun::AdminFailure>> {
        #[cfg(not(unix))]
        let _ = cx;
        match self {
            Self::Native(_) => Poll::Ready(Ok(())),
            #[cfg(unix)]
            Self::Helper(io) => io.poll_prepare(cx),
        }
    }
    pub(super) fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<tun::ReadEvent> {
        #[cfg(not(unix))]
        let _ = cx;
        match self {
            Self::Native(_) => None,
            #[cfg(unix)]
            Self::Helper(io) => io.poll_native_guard(cx),
        }
    }
    pub(super) fn snapshot(
        &self,
        until: Instant,
        options: tun::SnapshotOptions,
    ) -> Result<tun::NativeSnapshot, tun::AdminFailure> {
        match self {
            Self::Native(io) => io.snapshot(until, options),
            #[cfg(unix)]
            Self::Helper(io) => io.snapshot(until, options),
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
            #[cfg(unix)]
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
            #[cfg(unix)]
            Self::Helper(io) => io.query_route(destination, prefix, gateway, until),
        }
    }
    pub(super) fn plan(&mut self, action: tun::Action, until: Instant) -> io::Result<tun::Effect> {
        match self {
            Self::Native(io) => io.plan(action, until),
            #[cfg(unix)]
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
            #[cfg(unix)]
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
            #[cfg(unix)]
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
            #[cfg(unix)]
            Self::Helper(io) => io.queue(raw, until),
        }
    }
    pub(super) fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<tun::WriteEvent> {
        match self {
            Self::Native(io) => io.poll_write(cx),
            #[cfg(unix)]
            Self::Helper(io) => io.poll_write(cx),
        }
    }
    pub(super) fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<tun::ReadEvent> {
        match self {
            Self::Native(io) => io.poll_read(cx),
            #[cfg(unix)]
            Self::Helper(io) => io.poll_read(cx),
        }
    }
    /// Close original descriptor/pipes. For Helper this only requests stop;
    /// caller must separately reap the same child, even on a failed build.
    pub fn close(&mut self) -> tun::Loss {
        match self {
            Self::Native(io) => io.close(),
            #[cfg(unix)]
            Self::Helper(io) => io.close(),
        }
    }
    /// Wait the same original helper process after close, never a replacement PID.
    #[cfg(unix)]
    pub async fn reap_helper(&mut self) -> Option<tun::helper::Report> {
        match self {
            Self::Native(_) => None,
            #[cfg(unix)]
            Self::Helper(io) => io.reap().await,
        }
    }
}
