//! Owned verified native TUN/utun descriptors and caller-driven whole-packet I/O.
#![deny(unsafe_code)]
#![cfg(unix)]
mod admin;
mod control;
pub mod helper;
mod packet;
mod platform;
mod reactor;
mod readiness;
mod routes;
pub use admin::{AdminFailure, Ipv4Observation, NativeSnapshot};
pub use control::{Action, ApplyFailure, Effect, EffectId, NativeApplied, Reported, Timing};
pub use packet::{Mode, PacketError, Version, decode, prefix, version};
pub use reactor::{AsyncTun, Loss, LossCause, ReadEvent, Received, Unsent, WriteEvent, WriteId};
pub use readiness::{
    Ipv6Completion, Ipv6End, Ipv6Observation, Ipv6Progress, Ipv6State, Ipv6Target, Ipv6Watch,
    Ipv6WatchOptions,
};
pub use routes::{
    NativeRoute, RouteCompletion, RouteOutcome, RouteProgress, RouteQuery, RouteQueryCompletion,
    RouteQueryEvidence, RouteQueryOutcome, RouteQueryProblem, RouteQueryProgress,
    RouteQuerySubmission, RouteQueryTarget, RouteRecord, RouteSubmission,
};
use std::{
    cell::Cell,
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
    rc::Rc,
};
#[cfg(target_os = "freebsd")]
const MAX_PACKET_BYTES: usize = 65535; // FreeBSD if_tun.h TUNMRU.
#[cfg(not(target_os = "freebsd"))]
const MAX_PACKET_BYTES: usize = 65575;
/// Explicit maximum complete raw packet; no queues or unbounded worker are hidden.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum raw IP bytes, from 40 through 65575 (65535 on FreeBSD).
    /// IPv6 jumbograms are not supported.
    pub packet_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            packet_bytes: MAX_PACKET_BYTES,
        }
    }
}
impl Limits {
    fn validate(self) -> io::Result<()> {
        if !(40..=MAX_PACKET_BYTES).contains(&self.packet_bytes) {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN packet bound",
            ))
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
struct Stamp {
    alive: Cell<bool>,
}
/// Original actual packet-source lifetime. Native descriptors and helper pipes
/// have distinct epochs; cloning retains identity, never a descriptor or child.
#[derive(Clone, Debug)]
pub struct Epoch(Rc<Stamp>);
impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Epoch {}
impl Epoch {
    /// Whether the original native descriptor or helper pipe source is live.
    /// This is not process readiness, interface ownership or packet delivery.
    #[must_use]
    pub fn current(&self) -> bool {
        self.0.alive.get()
    }
}
/// Kernel-verified actual interface metadata, not administrative routing state.
#[derive(Clone, Debug)]
pub struct Info {
    /// Actual kernel interface name.
    pub name: String,
    /// Actual if_nametoindex result at verification.
    pub index: u32,
    /// Verified native packet mode.
    pub mode: Mode,
}
/// One exclusively owned verified TUN FD. Drop closes it and retires its epoch.
/// Existing duplicated descriptors remain the caller's responsibility.
pub struct OwnedTun {
    fd: Option<OwnedFd>,
    info: Info,
    limits: Limits,
    epoch: Epoch,
    next_effect: u64,
}
impl OwnedTun {
    fn verified(fd: OwnedFd, info: Info, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        platform::nonblocking(&fd)?;
        Ok(Self {
            fd: Some(fd),
            info,
            limits,
            epoch: Epoch(Rc::new(Stamp {
                alive: Cell::new(true),
            })),
            next_effect: 0,
        })
    }
    /// Consume and validate an existing real native TUN descriptor. On refusal it
    /// is closed, with the original ioctl/socket errno retained. No mock adoption.
    pub fn from_fd(fd: OwnedFd, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        let info = platform::verify(&fd)?;
        Self::verified(fd, info, limits)
    }
    /// Linux: open /dev/net/tun and issue the actual TUNSETIFF, without configuring
    /// addresses/routes. Name None requests kernel allocation; errors retain errno.
    #[cfg(target_os = "linux")]
    pub fn open_linux(
        name: Option<&str>,
        packet_information: bool,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open(name, packet_information)?;
        Self::from_fd(fd, limits)
    }
    /// Linux: create a nonpersistent TUN using TUNSETIFF with IFF_TUN_EXCL.
    /// A requested existing name is refused by the kernel; no name lookup or
    /// nonexclusive fallback can adopt another owner's interface. None requests
    /// a fresh kernel-selected name. Actual ioctl/open errno is preserved.
    #[cfg(target_os = "linux")]
    pub fn open_linux_exclusive(
        name: Option<&str>,
        packet_information: bool,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open_exclusive(name, packet_information)?;
        Self::from_fd(fd, limits)
    }
    /// macOS: connect the real utun kernel control; None requests a free unit,
    /// Some(n) requests utunN. It does not install an address or route.
    #[cfg(target_os = "macos")]
    pub fn open_utun(unit: Option<u32>, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open(unit)?;
        Self::from_fd(fd, limits)
    }
    /// FreeBSD: open an existing named TUN and enable its native family header.
    /// The interface must already exist. The caller must serialize interface
    /// creation/destruction across this open; observed replacement is refused.
    /// Close retires packet ownership and lets the kernel clear link/address
    /// state, but does not destroy the persistent FreeBSD interface. Interface
    /// creation/destruction remains with the caller's administrative owner.
    #[cfg(target_os = "freebsd")]
    pub fn open_freebsd_existing(name: &str, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open_existing(name)?;
        Self::from_fd(fd, limits)
    }
    /// Immutable actual device metadata.
    #[must_use]
    pub const fn info(&self) -> &Info {
        &self.info
    }
    /// Original physical lifetime token.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }
    /// Close the original descriptor once, reporting actual close errno. No retry
    /// can accidentally close a reused descriptor; no route deletion is claimed.
    pub fn close(mut self) -> io::Result<()> {
        self.epoch.0.alive.set(false);
        let fd = self
            .fd
            .take()
            .ok_or_else(|| io::Error::other("TUN already closed"))?;
        nix::unistd::close(fd).map_err(io::Error::from)
    }
    /// Borrow the actual descriptor without duplicating ownership.
    pub fn descriptor(&self) -> io::Result<BorrowedFd<'_>> {
        self.fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TUN closed"))
    }
    /// Transfer the original FD out, invalidating all old epoch/effect authority.
    pub fn into_fd(mut self) -> io::Result<OwnedFd> {
        self.epoch.0.alive.set(false);
        self.fd
            .take()
            .ok_or_else(|| io::Error::other("TUN already closed"))
    }
}
impl AsRawFd for OwnedTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}
impl Drop for OwnedTun {
    fn drop(&mut self) {
        self.epoch.0.alive.set(false);
    }
}

#[cfg(test)]
mod model;
