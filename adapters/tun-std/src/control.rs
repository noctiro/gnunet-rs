//! Original caller-owned configuration intents; external reports never become
//! native route/address ACKs. Every action is explicit and tied to one device.
use crate::{Epoch, Info, OwnedTun, platform};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::time::Instant;
/// One explicit administrative action. Address/netmask are separate atomic calls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Set MTU using the native interface ioctl.
    Mtu(u32),
    /// Toggle IFF_UP while retaining other observed flags.
    LinkUp(bool),
    /// Set primary IPv4 address via native ioctl.
    Ipv4Address(Ipv4Addr),
    /// Set IPv4 netmask via native ioctl.
    Ipv4Netmask(Ipv4Addr),
    /// Assign an IPv6 address/prefix using the actual native interface ioctl.
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
    fn validate(&self) -> io::Result<()> {
        match self {
            Self::Mtu(n) if *n == 0 || *n > 65535 => Err(platform::invalid("invalid MTU")),
            Self::Ipv6Address { prefix, .. } if *prefix > 128 => {
                Err(platform::invalid("invalid IPv6 prefix"))
            }
            Self::Route {
                destination,
                prefix,
                gateway,
                ..
            } if usize::from(*prefix) > if destination.is_ipv4() { 32 } else { 128 }
                || gateway.is_some_and(|g| g.is_ipv4() != destination.is_ipv4()) =>
            {
                Err(platform::invalid("invalid route prefix/family"))
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
/// Actual successful native ioctl completion only; not remote packet delivery.
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
    /// Original action whose actual ioctl returned success.
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
            .ok_or_else(|| platform::invalid("effect identity exhausted"))?;
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
    /// Execute one real interface ioctl, including IPv6 address assignment.
    /// Route effects use NativeRoute for bounded correlated kernel ACK handling.
    /// A successful address ioctl does not claim IPv6 DAD has completed.
    pub fn apply(&mut self, effect: Effect) -> Result<NativeApplied, ApplyFailure> {
        let fail = |effect, error, attempted| ApplyFailure {
            effect,
            error,
            attempted,
        };
        if effect.id.epoch != self.epoch || !effect.current() {
            return Err(fail(
                effect,
                io::Error::new(io::ErrorKind::TimedOut, "stale original TUN effect"),
                false,
            ));
        }
        if matches!(effect.action, Action::Route { .. }) {
            return Err(fail(
                effect,
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "use NativeRoute for correlated kernel route ACKs",
                ),
                false,
            ));
        }
        let checked = (|| {
            let fd = self
                .fd
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TUN closed"))?;
            let current = platform::verify(fd)?;
            if current.name != self.info.name || current.index != self.info.index {
                return Err(platform::invalid("original interface name/index changed"));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(fail(effect, error, false));
        }
        if let Err(error) = platform::apply(&self.info, &effect.action) {
            return Err(fail(effect, error, true));
        }
        let timing = if Instant::now() >= effect.until {
            Timing::Late
        } else {
            Timing::Timely
        };
        Ok(NativeApplied {
            id: effect.id,
            action: effect.action,
            timing,
        })
    }
}

impl OwnedTun {
    /// Begin one original bounded native interface-route request. Socket creation
    /// and registration do not submit the change; poll/drive performs the write.
    pub fn route(&mut self, effect: Effect) -> Result<crate::NativeRoute, ApplyFailure> {
        if effect.id.epoch != self.epoch || !effect.current() {
            return Err(ApplyFailure {
                effect,
                error: io::Error::new(io::ErrorKind::TimedOut, "stale original TUN route effect"),
                attempted: false,
            });
        }
        let checked = (|| {
            let fd = self
                .fd
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TUN closed"))?;
            let current = platform::verify(fd)?;
            if current.name != self.info.name || current.index != self.info.index {
                return Err(platform::invalid("original interface name/index changed"));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(ApplyFailure {
                effect,
                error,
                attempted: false,
            });
        }
        crate::NativeRoute::start(effect)
    }
}
