//! Original Wintun administration; native results never become socket ACKs.
use super::*;
use gnunet_native::wintun::Family;
impl OwnedTun {
    /// Execute the original explicit native administrative intent. Windows IP
    /// Helper calls are synchronous and cannot be interrupted by an async timer.
    /// Success is classified against the original deadline after the actual call.
    /// Address creation does not claim that duplicate-address detection finished.
    pub fn apply(&mut self, effect: Effect) -> Result<NativeApplied, ApplyFailure> {
        if effect.id.epoch != self.epoch || !effect.current() {
            return Err(ApplyFailure {
                effect,
                error: io::Error::new(io::ErrorKind::TimedOut, "stale original TUN effect"),
                attempted: false,
            });
        }
        if matches!(effect.action, Action::Route { .. }) {
            return Err(ApplyFailure {
                effect,
                error: invalid("use NativeRoute for the original route completion"),
                attempted: false,
            });
        }
        let result = (|| {
            let port = self.session().adapter().port();
            match effect.action {
                Action::IpMtu { version, bytes } => {
                    let family = match version {
                        crate::Version::V4 => Family::V4,
                        crate::Version::V6 => Family::V6,
                    };
                    port.set_mtu(family, bytes)
                }
                Action::LinkUp(up) => port.set_link_up(up),
                Action::Ipv4Address(address) => {
                    port.create_address(address.into(), 32)?;
                    self.ipv4 = Some(address);
                    Ok(())
                }
                Action::Ipv4Netmask(mask) => {
                    let address = self.ipv4.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "no original created IPv4 address")
                    })?;
                    port.set_address_prefix(address.into(), u32::from(mask).count_ones() as u8)
                }
                Action::Ipv6Address { address, prefix } => {
                    port.create_address(address.into(), prefix)
                }
                Action::Route { .. } => Err(invalid("route effect reached interface dispatcher")),
            }
        })();
        if let Err(error) = result {
            return Err(ApplyFailure {
                effect,
                error,
                attempted: true,
            });
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
    /// Prepare one original route operation without submitting a mutation.
    /// Polling performs the synchronous native call once; cancellation before
    /// polling remains Unsent. The job retains no session, adapter or DLL.
    pub fn route(&mut self, effect: Effect) -> Result<crate::NativeRoute, ApplyFailure> {
        let port = (|| {
            if effect.id.epoch != self.epoch || !effect.current() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stale original TUN route effect",
                ));
            }
            if !matches!(effect.action, Action::Route { .. }) {
                return Err(invalid("not a route effect"));
            }
            let port = self.session().adapter().port();
            port.interface()?;
            Ok(port)
        })();
        match port {
            Ok(port) => Ok(crate::NativeRoute::start(effect, port)),
            Err(error) => Err(ApplyFailure {
                effect,
                error,
                attempted: false,
            }),
        }
    }
}
