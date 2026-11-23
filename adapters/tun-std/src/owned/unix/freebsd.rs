//! In-process packet recovery on one original checkpointed FreeBSD TUN.
use super::*;
use crate::AsyncTun;
use std::fmt;
mod recreate;
mod reopen;
pub use recreate::{
    FreeBsdRecreate, FreeBsdRecreateStartError, FreeBsdRecreated, FreeBsdRouteKey, FreeBsdVacancy,
};
pub use reopen::{
    FreeBsdReopen, FreeBsdReopenError, FreeBsdReopenStage, FreeBsdReopenStartError,
    FreeBsdReopened, FreeBsdUnconfirmedClose,
};

/// Retired packet epoch and its still-owned TUN descriptor, control socket and
/// active checkpoint. Dropping releases the descriptors and checkpoint lock.
/// Persistent cleanup remains recoverable from the checkpoint.
#[derive(Debug)]
#[must_use]
pub struct FreeBsdRecovery {
    tun: OwnedTun,
    original: Epoch,
}

/// Original boundary that refused a packet-source restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreeBsdRestartStage {
    /// Match the original checkpoint, native descriptor, framing and FIB.
    Qualify,
    /// Register the fresh packet epoch on the caller's reactor.
    Register,
}

/// The original ownership and cause from a refused packet-source restart.
#[derive(Debug)]
pub struct FreeBsdRestartError {
    recovery: Box<FreeBsdRecovery>,
    stage: FreeBsdRestartStage,
    error: io::Error,
}
impl FreeBsdRestartError {
    /// Recover the original TUN and checkpoint for explicit retry or cleanup.
    pub fn into_parts(self) -> (FreeBsdRecovery, FreeBsdRestartStage, io::Error) {
        (*self.recovery, self.stage, self.error)
    }
}
impl fmt::Display for FreeBsdRestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FreeBSD TUN restart {:?}: {}", self.stage, self.error)
    }
}
impl std::error::Error for FreeBsdRestartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl OwnedTun {
    pub(crate) fn has_freebsd_checkpoint(&self) -> bool {
        self.handle
            .as_ref()
            .and_then(|handle| handle.interface.as_ref())
            .is_some_and(|lease| lease.recovery.is_some() && lease.checkpoint.is_some())
    }

    pub(crate) fn retain_freebsd(self) -> FreeBsdRecovery {
        self.epoch.0.alive.set(false);
        let original = self.epoch.clone();
        FreeBsdRecovery {
            tun: self,
            original,
        }
    }
}

impl FreeBsdRecovery {
    /// Retired source for correlating the original route and packet debts.
    #[must_use]
    pub const fn original_epoch(&self) -> &Epoch {
        &self.original
    }

    /// Defer potentially blocking interface destruction during surrounding drop.
    /// A subsequent close returns the original interface cleanup owner.
    pub fn defer_interface_cleanup(&mut self) {
        self.tun.defer_interface_cleanup();
    }

    /// Release the packet descriptor and settle original interface cleanup.
    /// Native destruction of a manual interface can wait for other users.
    ///
    /// # Errors
    /// Returns independent descriptor and interface errors in `DeviceCleanupError`.
    pub fn close(self) -> io::Result<()> {
        self.tun.close()
    }

    /// Requalify the same descriptor and register a fresh packet epoch on the
    /// caller's I/O runtime. Link, address and route readiness remain external.
    ///
    /// # Errors
    /// Returns the original owner on qualification or registration refusal.
    pub fn restart(mut self) -> Result<AsyncTun, FreeBsdRestartError> {
        let Some(handle) = self.tun.handle.as_mut() else {
            return Err(self.refused(
                FreeBsdRestartStage::Qualify,
                io::ErrorKind::NotConnected.into(),
            ));
        };
        let route_table = self.original.route_table();
        let info = &self.tun.info;
        if let Err(error) = platform::recovery::verify_retained_packet(handle, info, route_table) {
            return Err(self.refused(FreeBsdRestartStage::Qualify, error));
        }
        let Self { tun, original } = self;
        match register(tun, &original) {
            Ok(source) => Ok(source),
            Err(failure) => {
                let (tun, error) = registration_refusal(*failure);
                Err(Self { tun, original }.refused(FreeBsdRestartStage::Register, error))
            }
        }
    }

    fn refused(self, stage: FreeBsdRestartStage, error: io::Error) -> FreeBsdRestartError {
        FreeBsdRestartError {
            recovery: Box::new(self),
            stage,
            error,
        }
    }
}

fn register(
    mut tun: OwnedTun,
    original: &Epoch,
) -> Result<AsyncTun, Box<crate::RegistrationFailure>> {
    tun.epoch = Epoch(Rc::new(Stamp {
        alive: Cell::new(true),
        route_table: original.route_table(),
    }));
    tun.next_effect = 0;
    AsyncTun::try_new(tun).map(|mut source| {
        source.freebsd_recovery_enabled = true;
        source
    })
}

fn registration_refusal(failure: crate::RegistrationFailure) -> (OwnedTun, io::Error) {
    let (tun, error) = failure.into_parts();
    tun.epoch.0.alive.set(false);
    (tun, error)
}
