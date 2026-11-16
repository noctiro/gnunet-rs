//! Unix configuration calls and original-device route qualification.
use super::*;
use crate::platform;
impl OwnedTun {
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
            let fd = self.native_fd()?;
            let current = platform::verify(fd)?;
            if current.name != self.info.name || current.index != self.info.index {
                return Err(invalid("original interface name/index changed"));
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
            let fd = self.native_fd()?;
            let current = platform::verify(fd)?;
            if current.name != self.info.name || current.index != self.info.index {
                return Err(invalid("original interface name/index changed"));
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
