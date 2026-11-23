//! Original-session reply routes with stable native interface observations.
use super::{Device, abi};
use crate::interfaces::{self, Identity};
use std::{
    fmt, io,
    sync::{Arc, Weak},
};
/// Native reply route could not be qualified or no longer matches its observation.
/// This is a packet refusal before injection, not filter loss or an unsent claim
/// about an earlier admitted operation.
#[derive(Clone, Debug)]
pub struct RouteUnavailable {
    interface: u32,
    cause: Arc<io::Error>,
}
impl fmt::Display for RouteUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "captured interface {} unavailable: {}",
            self.interface, self.cause
        )
    }
}
impl std::error::Error for RouteUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
/// Captured NETWORK metadata, bound to one original session allocation.
#[derive(Clone)]
pub struct CapturedAddress {
    pub(super) raw: abi::Address,
    pub(super) owner: Weak<Device>,
    observed: Result<Option<Identity>, RouteUnavailable>,
}
impl fmt::Debug for CapturedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedPacketAddress")
            .field("interface", &self.interface())
            .field("loopback", &self.loopback())
            .finish()
    }
}
impl CapturedAddress {
    pub(super) fn received(raw: abi::Address, owner: &Arc<Device>) -> Self {
        let observed = (|| -> io::Result<_> {
            if interfaces::compartment() != owner.compartment {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "original capture compartment changed",
                ));
            }
            if raw.flags & abi::LOOPBACK != 0 || raw.flags & abi::OUTBOUND == 0 {
                return Ok(None);
            }
            let observations = owner.route_observations();
            let now = counter()?;
            observations
                .get(raw.timestamp, now, raw.data[0] as u32)
                .cloned()
                .map(Some)
        })()
        .map_err(|cause| RouteUnavailable {
            interface: raw.data[0] as u32,
            cause: Arc::new(cause),
        });
        Self {
            raw,
            owner: Arc::downgrade(owner),
            observed,
        }
    }
    /// Captured interface/subinterface indices; not immutable physical identity.
    pub fn interface(&self) -> (u32, u32) {
        (self.raw.data[0] as u32, (self.raw.data[0] >> 32) as u32)
    }
    /// Whether Windows classified the original packet as host-local traffic.
    pub fn loopback(&self) -> bool {
        self.raw.flags & abi::LOOPBACK != 0
    }
    /// Whether the original packet used the IPv6 layout.
    pub fn ipv6(&self) -> bool {
        self.raw.flags & abi::IPV6 != 0
    }
    /// Original native checksum-validation observations.
    pub fn checksums(&self) -> (bool, bool) {
        (
            self.raw.flags & abi::IP_CHECKSUM != 0,
            self.raw.flags & abi::UDP_CHECKSUM != 0,
        )
    }
    /// Qualify a return route in the original session's network compartment.
    /// Inbound injection retains the LUID/GUID/index selected at receive
    /// completion from the packet's capture-time observation, then rechecks it.
    /// Loopback stays outbound; WinDivert ignores interface indices on that path.
    pub fn reply(&self) -> Result<ReplyAddress, RouteUnavailable> {
        let interface = self.observed.clone()?;
        let qualify = || -> io::Result<_> {
            let owner = self.owner.upgrade().ok_or(io::ErrorKind::NotConnected)?;
            if interfaces::compartment() != owner.compartment {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "original capture compartment changed",
                ));
            }
            let mut raw = self.raw;
            if !self.loopback() {
                raw.flags ^= abi::OUTBOUND;
            }
            raw.flags |= abi::IP_CHECKSUM | abi::UDP_CHECKSUM;
            if let Some(interface) = &interface {
                interface.check()?;
            }
            Ok(ReplyAddress {
                raw,
                owner: self.owner.clone(),
                compartment: owner.compartment,
                interface,
            })
        };
        qualify().map_err(|cause| RouteUnavailable {
            interface: self.interface().0,
            cause: Arc::new(cause),
        })
    }
}
/// Reply metadata bound to its original session and observed inbound interface.
#[derive(Clone)]
pub struct ReplyAddress {
    pub(super) raw: abi::Address,
    pub(super) owner: Weak<Device>,
    compartment: u32,
    interface: Option<Identity>,
}
impl fmt::Debug for ReplyAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplyPacketAddress")
            .field("interface", &self.interface)
            .field("compartment", &self.compartment)
            .finish_non_exhaustive()
    }
}
impl ReplyAddress {
    /// Whether this reply retains a checked non-loopback interface observation.
    /// WinDivert ignores interface indices for loopback injection. This does
    /// not pin the interface or certify a later injection; `check` still applies.
    pub fn has_interface_scope(&self) -> bool {
        self.interface.is_some() && self.raw.flags & abi::LOOPBACK == 0
    }
    /// Recheck the original route without adopting a replacement interface.
    /// This observation does not lock the kernel route through later injection.
    pub fn check(&self) -> Result<(), RouteUnavailable> {
        let result = if interfaces::compartment() != self.compartment {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original capture compartment changed",
            ))
        } else if let Some(interface) = &self.interface {
            interface.check()
        } else {
            Ok(())
        };
        result.map_err(|cause| RouteUnavailable {
            interface: self.raw.data[0] as u32,
            cause: Arc::new(cause),
        })
    }
}

#[expect(
    unsafe_code,
    reason = "QueryPerformanceCounter writes one initialized scalar and shares WinDivert's documented packet timestamp clock"
)]
fn counter() -> io::Result<i64> {
    let mut value = 0;
    // SAFETY: initialized scalar output remains live for the synchronous SDK call.
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut value) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if value < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "negative capture observation clock",
        ));
    }
    Ok(value)
}

pub(super) fn interface_snapshot() -> io::Result<(i64, Vec<Identity>)> {
    let identities = Identity::snapshot(super::observations::MAX_INTERFACES)?;
    Ok((counter()?, identities))
}

/// Allow missed refreshes without letting a failed observer authorize new
/// captures indefinitely. The DNS host normally refreshes once per second.
#[expect(
    unsafe_code,
    reason = "QueryPerformanceFrequency writes one initialized native clock scalar without retaining memory"
)]
pub(super) fn observation_age() -> io::Result<i64> {
    const MAXIMUM_SECONDS: i64 = 5;
    let mut frequency = 0i64;
    // SAFETY: one initialized exclusive scalar remains live for this call.
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    frequency
        .checked_mul(MAXIMUM_SECONDS)
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid capture clock frequency",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_capture_indices_and_loopback_do_not_supply_interface_scope() -> io::Result<()> {
        let mut reply = ReplyAddress {
            raw: abi::Address {
                flags: abi::OUTBOUND,
                data: [7 | (3 << 32), 0, 0, 0, 0, 0, 0, 0],
                ..Default::default()
            },
            owner: Weak::new(),
            compartment: 1,
            interface: None,
        };
        if reply.has_interface_scope() {
            return Err(io::Error::other(
                "numeric capture indices supplied an unobserved interface scope",
            ));
        }
        reply.interface = Some(Identity::fixture(7, 1));
        if !reply.has_interface_scope() {
            return Err(io::Error::other(
                "original retained interface observation lost its scope",
            ));
        }
        reply.raw.flags |= abi::LOOPBACK;
        if reply.has_interface_scope() {
            return Err(io::Error::other(
                "loopback admitted interface indices ignored by native injection",
            ));
        }
        Ok(())
    }
}
