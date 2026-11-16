//! Original caller-owned configuration intents; external reports never become
//! native route/address ACKs. Every action is explicit and tied to one device.
use crate::{Epoch, Info, OwnedTun};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::time::Instant;
/// One explicit administrative action. Address/netmask are separate atomic calls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Set the shared native Unix link MTU.
    #[cfg(unix)]
    Mtu(u32),
    /// Set exactly one native Windows IP family's MTU. Every family has its own
    /// original effect and completion; a later failure cannot hide an earlier call.
    #[cfg(windows)]
    IpMtu {
        /// Exact IP family whose native row is modified.
        version: crate::Version,
        /// Requested MTU in bytes.
        bytes: u32,
    },
    /// Set native administrative up/down, without operational-readiness credit.
    LinkUp(bool),
    /// Set the native IPv4 address. Windows creates an explicit /32 row and
    /// records it as this owner's primary address for the later netmask action;
    /// it does not remove preexisting addresses or replace an existing row.
    Ipv4Address(Ipv4Addr),
    /// Set the native IPv4 netmask. Windows updates the last address actually
    /// created by this owner; a snapshot cannot choose a different address.
    Ipv4Netmask(Ipv4Addr),
    /// Assign an IPv6 address/prefix using the actual native interface API.
    Ipv6Address {
        /// Exact address.
        address: Ipv6Addr,
        /// Prefix length through128.
        prefix: u8,
    },
    /// Native interface-route add/delete, or an explicit external gateway effect.
    Route {
        /// True adds, false removes.
        add: bool,
        /// Exact destination network/address.
        destination: IpAddr,
        /// Prefix length in its address family.
        prefix: u8,
        /// Optional same-family next hop; None means interface route.
        gateway: Option<IpAddr>,
    },
}
impl Action {
    pub(crate) fn validate(&self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Mtu(n) if *n == 0 || *n > 65535 => Err(invalid("invalid MTU")),
            #[cfg(windows)]
            Self::IpMtu { bytes, .. } if *bytes == 0 || *bytes > 65535 => {
                Err(invalid("invalid IP MTU"))
            }
            Self::Ipv6Address { prefix, .. } if *prefix > 128 => {
                Err(invalid("invalid IPv6 prefix"))
            }
            Self::Ipv4Netmask(mask)
                if u32::from(*mask).leading_ones() != u32::from(*mask).count_ones() =>
            {
                Err(invalid("noncontiguous IPv4 netmask"))
            }
            Self::Route {
                destination,
                prefix,
                gateway,
                ..
            } if usize::from(*prefix) > if destination.is_ipv4() { 32 } else { 128 }
                || gateway.is_some_and(|g| g.is_ipv4() != destination.is_ipv4()) =>
            {
                Err(invalid("invalid route prefix/family"))
            }
            Self::Route {
                destination,
                prefix,
                ..
            } => {
                let canonical = match destination {
                    IpAddr::V4(ip) => *prefix == 32 || u32::from(*ip) & (u32::MAX >> *prefix) == 0,
                    IpAddr::V6(ip) => {
                        *prefix == 128 || u128::from(*ip) & (u128::MAX >> *prefix) == 0
                    }
                };
                if canonical {
                    Ok(())
                } else {
                    Err(invalid("noncanonical route destination"))
                }
            }
            _ => Ok(()),
        }
    }
}
/// Original exact configuration intent; not an OS route sequence number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectId {
    epoch: Epoch,
    serial: u64,
}
impl EffectId {
    /// Original physical owner.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Diagnostic sequence; it cannot reconstruct authority.
    #[must_use]
    pub const fn diagnostic(&self) -> u64 {
        self.serial
    }
}
/// Non-Clone original effect, retaining its exact interface/action/deadline.
#[must_use]
pub struct Effect {
    id: EffectId,
    info: Info,
    action: Action,
    until: Instant,
}
impl Effect {
    /// Original effect identity.
    #[must_use]
    pub const fn id(&self) -> &EffectId {
        &self.id
    }
    /// Exact verified interface metadata at issue time.
    #[must_use]
    pub const fn interface(&self) -> &Info {
        &self.info
    }
    /// Exact requested action.
    #[must_use]
    pub const fn action(&self) -> &Action {
        &self.action
    }
    /// Original finite administrative deadline.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.until
    }
    /// Original source is current and this intent has not expired.
    #[must_use]
    pub fn current(&self) -> bool {
        self.id.epoch.current() && Instant::now() < self.until
    }
    /// Consume an externally executed effect and retain the caller's actual
    /// outcome. This is labelled CallerReported and never constructs NativeApplied.
    pub fn report(self, outcome: io::Result<()>) -> Reported {
        let timing = if !self.id.epoch.current() {
            Timing::SourceRetired
        } else if Instant::now() >= self.until {
            Timing::Late
        } else {
            Timing::Timely
        };
        Reported {
            id: self.id,
            action: self.action,
            timing,
            outcome,
        }
    }
}
/// Timing/source classification independent of an external actor's actual outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Timing {
    /// Original current source/deadline.
    Timely,
    /// Report arrived after original deadline; original effect is not retried.
    Late,
    /// Original descriptor retired before this report.
    SourceRetired,
}
/// An explicit caller report, without kernel ACK or success fabrication.
#[derive(Debug)]
pub struct Reported {
    /// Original effect.
    pub id: EffectId,
    /// Original action.
    pub action: Action,
    /// Actual report timing/source.
    pub timing: Timing,
    /// Caller-supplied outcome; retained even if late/source-lost.
    pub outcome: io::Result<()>,
}
/// Actual successful native administrative completion; not remote delivery.
#[derive(Debug)]
pub struct NativeApplied {
    id: EffectId,
    action: Action,
    timing: Timing,
}
impl NativeApplied {
    /// Original effect settled by the actual native call.
    #[must_use]
    pub const fn id(&self) -> &EffectId {
        &self.id
    }
    /// Original action whose native call returned success.
    #[must_use]
    pub const fn action(&self) -> &Action {
        &self.action
    }
    /// Native call completion compared with the original effect deadline.
    #[must_use]
    pub const fn timing(&self) -> Timing {
        self.timing
    }
}
/// Original failed/refused native attempt, retaining the unconsumed effect.
pub struct ApplyFailure {
    /// Exact original intent, available to an explicit external port.
    pub effect: Effect,
    /// Actual native errno or explicit stale/unsupported rejection.
    pub error: io::Error,
    /// A native configuration path was attempted; no success is implied.
    /// Earlier steps may have changed the kernel. Do not infer rollback or
    /// automatically replay the retained effect.
    pub attempted: bool,
}
impl std::fmt::Debug for ApplyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplyFailure")
            .field("id", &self.effect.id)
            .field("action", &self.effect.action)
            .field("error", &self.error)
            .field("attempted", &self.attempted)
            .finish()
    }
}
impl std::fmt::Display for ApplyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for ApplyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl OwnedTun {
    /// Issue one bounded original configuration effect. No native change occurs.
    pub fn plan(&mut self, action: Action, until: Instant) -> io::Result<Effect> {
        action.validate()?;
        if Instant::now() >= until || !self.epoch.current() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TUN effect deadline/source",
            ));
        }
        self.next_effect = self
            .next_effect
            .checked_add(1)
            .ok_or_else(|| invalid("effect identity exhausted"))?;
        Ok(Effect {
            id: EffectId {
                epoch: self.epoch.clone(),
                serial: self.next_effect,
            },
            info: self.info.clone(),
            action,
            until,
        })
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
