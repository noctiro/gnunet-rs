//! Caller-selected same-adapter recovery with one original outage budget.
use super::{Coordinator, Device, Error, Fault, Report, tun};
use std::time::Duration;
use tokio::time::Instant;
mod physical;
pub use physical::WintunPhysicalFailure;

#[derive(Default)]
pub(super) struct Recovery {
    enabled: bool,
    budget: tun::RecoveryBudget,
    pub(super) hard: Option<Instant>,
    configuring: bool,
    retired: Option<tun::Epoch>,
}

/// Recovery refusal preserves the actual owner at the stage that failed.
pub enum WintunRecoveryFailure {
    /// No native restart was attempted; the caller still owns the original adapter.
    Retained {
        /// Same original retained adapter.
        recovery: tun::WintunRecovery,
        /// Actual state, deadline or resource refusal. WouldBlock means old debt remains.
        error: Error,
    },
    /// Native session restart failed and returns its original adapter and stage.
    Restart(tun::WintunRestartError),
    /// Native restart succeeded but logical admission failed. The caller owns
    /// the newly qualified session and must close it rather than retry its old epoch.
    Prepared {
        /// Actual new packet owner on the original adapter.
        device: Box<Device>,
        /// Actual logical refusal; no configuration was replayed.
        error: Error,
    },
    /// The coordinator owns the new session; it must be shut down after its
    /// verification workflow could not be prepared. No owner is transferred twice.
    Installed(Error),
}
impl std::fmt::Debug for WintunRecoveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retained { recovery, error } => f
                .debug_struct("Retained")
                .field("recovery", recovery)
                .field("error", error)
                .finish(),
            Self::Restart(error) => f.debug_tuple("Restart").field(error).finish(),
            Self::Prepared { device, error } => f
                .debug_struct("Prepared")
                .field("epoch", &device.epoch())
                .field("error", error)
                .finish(),
            Self::Installed(error) => f.debug_tuple("Installed").field(error).finish(),
        }
    }
}
impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    /// Select caller-driven Wintun recovery before the first drive. The caller
    /// must consume returned recovery owners and continue driving old flow/debt
    /// retirement. The coordinator still enforces its original finite budget.
    ///
    /// # Errors
    /// Refuses policy changes after startup, shutdown, or close.
    pub fn enable_wintun_recovery(&mut self) -> Result<(), Error> {
        if self.source.is_some() || self.closed.is_some() || self.stopping.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.recovery.enabled = true;
        Ok(())
    }
    pub(super) fn arm_recovery(&mut self, loss: &tun::Loss) -> Result<bool, Error> {
        if !self.recovery.enabled
            || self.closed.is_some()
            || self.stopping.is_some()
            || loss.close_error.is_some()
            || self.control.unconfirmed_control_closes != 0
            || loss
                .recovery
                .as_ref()
                .is_none_or(|owner| *owner.original_epoch() != loss.epoch)
        {
            return Ok(false);
        }
        let now = Instant::now();
        // A completed native write can precede the loss in this same fair turn.
        self.recovery.budget.observe(
            now,
            (self.report.tun_read, self.report.tun_written),
            Duration::from_secs(1),
        );
        self.recovery.hard = Some(self.recovery.budget.begin(
            now,
            self.limits.control_timeout,
            Duration::from_secs(1),
        )?);
        self.recovery.configuring = false;
        self.recovery.retired = None;
        Ok(true)
    }
    pub(super) fn observe_recovery(&mut self) -> Result<(), Error> {
        if self.control.dead || !self.tun_ready()? {
            return Ok(());
        }
        let now = Instant::now();
        let Report {
            tun_read,
            tun_written,
            ..
        } = self.report;
        if self.recovery.configuring {
            self.recovery.budget.admitted(now, (tun_read, tun_written));
            self.recovery.configuring = false;
            self.recovery.hard = None;
        }
        self.recovery
            .budget
            .observe(now, (tun_read, tun_written), Duration::from_secs(1));
        Ok(())
    }
    /// Restart the retained original adapter and prepare read-only verification.
    /// A successful return is packet ownership admission, not route/DAD readiness;
    /// keep driving until [`Self::tun_ready`] observes the actual current plan.
    /// No old packet, route mutation, flow or operation deadline is replayed.
    ///
    /// # Errors
    /// Returns the original adapter while old jobs/flows remain, on a stale
    /// recovery capability, or after stop/deadline. Native refusal retains its
    /// exact stage. Post-restart failures identify who owns the new session.
    #[expect(
        clippy::result_large_err,
        reason = "A refusal returns the original linear adapter or session instead of dropping native ownership"
    )]
    pub fn recover_wintun(
        &mut self,
        recovery: tun::WintunRecovery,
    ) -> Result<(), WintunRecoveryFailure> {
        self.resume_wintun(recovery, false)
    }
    /// Refresh the packet handle on the exact retained interface scope.
    /// Old flows/jobs must quiesce, creator lifetime stays retained, and original
    /// owned route debt survives until fresh read-only verification succeeds.
    ///
    /// # Errors
    /// Preserves the same ownership and deadline classifications as
    /// [`Self::recover_wintun`]. Native scope changes are refused.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the original linear scope owner without another cleanup allocation"
    )]
    pub fn refresh_wintun(
        &mut self,
        recovery: tun::WintunRecovery,
    ) -> Result<(), WintunRecoveryFailure> {
        self.resume_wintun(recovery, true)
    }
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the original linear scope owner without another cleanup allocation"
    )]
    fn resume_wintun(
        &mut self,
        recovery: tun::WintunRecovery,
        refresh: bool,
    ) -> Result<(), WintunRecoveryFailure> {
        let check = || -> Result<(_, _), Error> {
            if !self.recovery.enabled || self.closed.is_some() || self.stopping.is_some() {
                return Err(Fault::Closed.into());
            }
            if *recovery.original_epoch() != self.device.epoch() || !self.control.dead {
                return Err(Fault::StaleGeneration.into());
            }
            if self.control.unconfirmed_control_closes != 0 {
                return Err(Fault::Io.into());
            }
            let hard = self.recovery.hard.ok_or(Fault::NotReady)?;
            if Instant::now() >= hard {
                return Err(Fault::Deadline.into());
            }
            let source = self.source.ok_or(Fault::NotReady)?;
            self.server.engine().can_rebind_tun(source)?;
            Ok((source, hard))
        };
        let (old, hard) = match check() {
            Ok(parts) => parts,
            Err(error) => return Err(WintunRecoveryFailure::Retained { recovery, error }),
        };
        let mut device = if refresh {
            Device::refresh_wintun(recovery)
        } else {
            Device::recover_wintun(recovery)
        }
        .map_err(WintunRecoveryFailure::Restart)?;
        if Instant::now() >= hard {
            return Err(WintunRecoveryFailure::Prepared {
                device: Box::new(device),
                error: Fault::Deadline.into(),
            });
        }
        let source = match self.server.engine_mut().rebind_tun_same_interface(old) {
            Ok(source) => source,
            Err(error) => {
                return Err(WintunRecoveryFailure::Prepared {
                    device: Box::new(device),
                    error: error.into(),
                });
            }
        };
        // Packet-session replacement keeps original route cleanup ownership.
        // Device::recover_wintun alone cannot acquire that authority.
        device.provenance = self.device.provenance;
        self.device = device;
        self.source = Some(source);
        self.recovery.configuring = true;
        if let Err(error) = self.start_recovery_verification(source, hard) {
            self.request_shutdown();
            return Err(WintunRecoveryFailure::Installed(error));
        }
        Ok(())
    }
}
