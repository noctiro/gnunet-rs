//! Shared verified interface metadata, packet bounds and source lifetimes.
use crate::Mode;
use std::{cell::Cell, io, rc::Rc};
#[cfg(any(target_os = "freebsd", windows))]
const MAX_PACKET_BYTES: usize = 65535; // FreeBSD if_tun.h TUNMRU.
#[cfg(not(any(target_os = "freebsd", windows)))]
const MAX_PACKET_BYTES: usize = 65575;
/// Explicit maximum complete raw packet; no queues or unbounded worker are hidden.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum raw IP bytes, from 40 through 65575 (65535 on FreeBSD/Windows).
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
    /// Largest raw packet accepted by the native device backend. FreeBSD TUN
    /// uses TUNMRU=65535, Windows uses the Wintun limit; Linux/macOS also accommodate the IPv6 header bytes.
    pub const MAX_PACKET_BYTES: usize = MAX_PACKET_BYTES;
    pub(crate) fn validate(self) -> io::Result<()> {
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
pub(crate) struct Stamp {
    pub(crate) alive: Cell<bool>,
    pub(crate) route_table: Option<u32>,
}
/// Original actual packet-source lifetime. Native descriptors and helper pipes
/// have distinct epochs; cloning retains identity, never a descriptor or child.
#[derive(Clone, Debug)]
pub struct Epoch(pub(crate) Rc<Stamp>);
impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Epoch {}
impl Epoch {
    /// Linux main table or FreeBSD interface FIB captured at source qualification.
    /// macOS uses scoped routes and Windows uses its original qualified native port;
    /// both return None. This snapshot
    /// selects route operations; it does not change packet-socket FIB policy.
    #[must_use]
    pub fn route_table(&self) -> Option<u32> {
        self.0.route_table
    }
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
