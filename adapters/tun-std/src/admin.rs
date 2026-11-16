//! Actual read-only per-interface observations, never restore/route ownership.
use crate::{Epoch, Info, OwnedTun, Version};
use std::{io, net::Ipv4Addr};
use tokio::time::Instant;
/// Requested IP observations. Default queries link state only; an unrequested
/// family is never queried or represented as absent. Native errors for requested
/// families retain their original classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SnapshotOptions {
    /// Query the applicable IPv4 MTU and selected IPv4 address/netmask.
    pub ipv4: bool,
    /// Query the applicable IPv6 MTU. Address/DAD uses its separate observer.
    pub ipv6: bool,
}
/// Address-specific native IPv4 observation; zero is never invented for absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4Observation {
    /// This snapshot did not request IPv4 address observations.
    NotRequested,
    /// Actual address/netmask octets returned by the kernel, including real zero.
    Present(Ipv4Addr),
    /// A completed native selection found no assigned address.
    Unassigned,
    /// Windows found several addresses without an original primary selection.
    Ambiguous {
        /// Actual number of native matching addresses.
        count: usize,
    },
    /// Actual EADDRNOTAVAIL from this exact interface getter.
    Absent {
        /// Native absence errno, retained without normalization.
        errno: i32,
    },
}
/// Original source-bound query failure, never a replacement-interface snapshot.
#[derive(Debug)]
pub enum AdminFailure {
    /// Original descriptor epoch retired or name/index changed/disappeared.
    SourceRetired,
    /// Original absolute query deadline elapsed, including a late native call.
    Deadline,
    /// Actual native errno or explicit malformed/unsupported ABI result.
    Kernel(io::Error),
    /// Original failure plus independent actual query-socket close errno.
    WithClose {
        /// Original classification/errno, never replaced by cleanup failure.
        failure: Box<AdminFailure>,
        /// Actual close error; descriptor close is never retried.
        close_error: io::Error,
    },
}
impl std::fmt::Display for AdminFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceRetired => f.write_str("original TUN source retired"),
            Self::Deadline => f.write_str("original admin deadline"),
            Self::Kernel(e) => e.fmt(f),
            Self::WithClose {
                failure,
                close_error,
            } => write!(f, "{failure}; query socket close: {close_error}"),
        }
    }
}
impl std::error::Error for AdminFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kernel(e) => Some(e),
            Self::WithClose { failure, .. } => Some(failure.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for AdminFailure {
    fn from(e: io::Error) -> Self {
        Self::Kernel(e)
    }
}
/// Actual finite group of read-only kernel interface getters. Fields are private
/// so a caller cannot manufacture a native receipt from configuration values.
/// This is a time-local observation, not a persistent or atomic restore image.
#[derive(Debug)]
pub struct NativeSnapshot {
    epoch: Epoch,
    interface: Info,
    deadline: Instant,
    started_at: Instant,
    observed_at: Instant,
    options: SnapshotOptions,
    link_mtu: u32,
    #[cfg(windows)]
    ipv4_mtu: Option<u32>,
    #[cfg(windows)]
    ipv6_mtu: Option<u32>,
    flags: Option<u32>,
    up: bool,
    windows_status: Option<(i32, i32)>,
    address: Ipv4Observation,
    netmask: Ipv4Observation,
    close_error: Option<io::Error>,
}
impl NativeSnapshot {
    /// Original actual descriptor lifetime, never retained alive by this receipt.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Original verified interface name/index, not rebound on reuse.
    #[must_use]
    pub const fn interface(&self) -> &Info {
        &self.interface
    }
    /// Original finite caller deadline.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
    /// First query time; the getters are a bounded group, not one atomic read.
    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.started_at
    }
    /// Native group completed before the original deadline.
    #[must_use]
    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }
    /// Exact scope requested for these original read-only observations.
    #[must_use]
    pub const fn options(&self) -> SnapshotOptions {
        self.options
    }
    /// Actual link-layer MTU from the Unix interface getter or Windows IF_ROW2.
    /// This is distinct from Windows family-specific IP MTUs.
    #[must_use]
    pub const fn link_mtu(&self) -> u32 {
        self.link_mtu
    }
    /// Applicable MTU for a requested IP family. Unix reports its shared link
    /// limit; Windows reports that family's actual IP-interface MTU. None means
    /// not requested, never missing-family evidence. Availability and address/DAD
    /// have their own native observations.
    #[must_use]
    pub const fn ip_mtu(&self, version: Version) -> Option<u32> {
        let requested = match version {
            Version::V4 => self.options.ipv4,
            Version::V6 => self.options.ipv6,
        };
        if !requested {
            return None;
        }
        #[cfg(unix)]
        {
            Some(self.link_mtu)
        }
        #[cfg(windows)]
        {
            match version {
                Version::V4 => self.ipv4_mtu,
                Version::V6 => self.ipv6_mtu,
            }
        }
    }
    /// Actual native administrative state; no operational-readiness claim.
    #[must_use]
    pub const fn up(&self) -> bool {
        self.up
    }
    /// Actual Unix interface flags (both 16-bit words on FreeBSD).
    /// Windows has native administrative/operational states instead and returns None.
    #[must_use]
    pub const fn flags(&self) -> Option<u32> {
        self.flags
    }
    /// Actual Windows administrative and operational status values, in that order.
    /// Unix returns None instead of inventing equivalent Windows states.
    #[must_use]
    pub const fn windows_status(&self) -> Option<(i32, i32)> {
        self.windows_status
    }
    /// Actual selected IPv4 address, native absence, ambiguity or NotRequested.
    #[must_use]
    pub const fn ipv4_address(&self) -> Ipv4Observation {
        self.address
    }
    /// Actual selected IPv4 netmask, native absence, ambiguity or NotRequested.
    #[must_use]
    pub const fn ipv4_netmask(&self) -> Ipv4Observation {
        self.netmask
    }
    /// Independent actual control socket close errno; never retried.
    #[must_use]
    pub const fn close_error(&self) -> Option<&io::Error> {
        self.close_error.as_ref()
    }
    #[cfg(unix)]
    pub(crate) fn take_close_error(&mut self) -> Option<io::Error> {
        self.close_error.take()
    }
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::snapshot;
#[cfg(windows)]
mod windows;
