//! Old route scope retirement is independent of new borrowed device readiness.
use super::super::device::Provenance;
use super::super::{Coordinator, Device, Error, Event, Fault, PacketIo, core, tun};
use tokio::time::Instant;

/// Physical admission refusal identifies the actual remaining owner.
pub enum WintunPhysicalFailure {
    /// No provisional device was admitted; original physical intent is returned.
    Retained {
        /// Exact original selector/provider and any observed old-scope fact.
        owner: Box<tun::WintunReopen>,
        /// Actual stop, state, deadline or independent native refusal.
        error: Error,
    },
    /// A native reopen failed; actual intent, stage and cause remain owned here.
    Open(tun::WintunReopenError),
    /// Native reopen failed and old-scope reconciliation independently failed.
    Reconcile {
        /// Original native failure and physical intent, never discarded.
        original: tun::WintunReopenError,
        /// Independent logical scope/retirement refusal.
        error: Error,
    },
    /// New qualified session belongs to the caller after logical admission refusal.
    Prepared {
        /// Actual qualified new packet owner, never an old epoch rebind.
        source: Box<tun::AsyncTun>,
        /// Actual logical/deadline refusal.
        error: Error,
    },
    /// Coordinator owns the new session and must shut down after setup refusal.
    Installed(Error),
}
impl std::fmt::Debug for WintunPhysicalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retained { owner, error } => f
                .debug_struct("Retained")
                .field("owner", owner)
                .field("error", error)
                .finish(),
            Self::Open(error) => f.debug_tuple("Open").field(error).finish(),
            Self::Reconcile { original, error } => f
                .debug_struct("Reconcile")
                .field("original", original)
                .field("error", error)
                .finish(),
            Self::Prepared { source, error } => f
                .debug_struct("Prepared")
                .field("epoch", &source.epoch())
                .field("error", error)
                .finish(),
            Self::Installed(error) => f.debug_tuple("Installed").field(error).finish(),
        }
    }
}
impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    fn physical_scope(
        &mut self,
        receipt: &tun::WintunScopeRetirement,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        if receipt.original_epoch() != &self.device.epoch()
            || !self.control.dead
            || self.control.unconfirmed_control_closes != 0
        {
            return Err(Fault::StaleGeneration.into());
        }
        if self.recovery.retired.as_ref() == Some(receipt.original_epoch()) {
            return Ok(());
        }
        let source = self.source.ok_or(Fault::NotReady)?;
        let state = self.server.engine().route_state(source)?;
        if state.is_borrowed() {
            if state != core::RouteState::BorrowedReleased {
                self.server.engine_mut().release_borrowed_routes(source)?;
            }
        } else if state != core::RouteState::Absent {
            self.server.engine_mut().confirm_routes_absent(source)?;
        }
        self.control.uncertain = false;
        self.recovery.retired = Some(receipt.original_epoch().clone());
        observe(Event::InterfaceRetired(receipt.clone()));
        Ok(())
    }
    /// Open the selected reappearing interface after actual old-scope retirement.
    /// Old jobs/flows must quiesce; sealed native absence settles only old route
    /// debt. The new device is borrowed and requires fresh configuration/DAD
    /// verification through the normal control state machine.
    ///
    /// # Errors
    /// Returns physical intent while debt remains, original native stage/cause
    /// on failure, or the exact provisional/installed owner after later refusal.
    pub fn reopen_wintun(
        &mut self,
        owner: tun::WintunReopen,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), WintunPhysicalFailure> {
        self.replace_wintun(owner, false, observe)
    }
    /// Reopen an external interface, or recreate a missing original creator's
    /// device. Creation is sealed by its real native provenance and old-scope
    /// absence; the new scope receives fresh configuration and route jobs.
    ///
    /// # Errors
    /// Retains the same physical/native/provisional/installed owners as reopen.
    pub fn restore_wintun(
        &mut self,
        owner: tun::WintunReopen,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), WintunPhysicalFailure> {
        self.replace_wintun(owner, true, observe)
    }
    fn replace_wintun(
        &mut self,
        owner: tun::WintunReopen,
        recreate: bool,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), WintunPhysicalFailure> {
        let check = || -> Result<_, Error> {
            if !self.recovery.enabled || self.closed.is_some() || self.stopping.is_some() {
                return Err(Fault::Closed.into());
            }
            if owner.original_epoch() != &self.device.epoch() || !self.control.dead {
                return Err(Fault::StaleGeneration.into());
            }
            if self.control.unconfirmed_control_closes != 0 {
                return Err(Fault::Io.into());
            }
            let hard = self.recovery.hard.ok_or(Fault::NotReady)?;
            if Instant::now() >= hard {
                return Err(Fault::Deadline.into());
            }
            let old = self.source.ok_or(Fault::NotReady)?;
            if matches!(
                self.server.engine().route_state(old)?,
                core::RouteState::Absent | core::RouteState::BorrowedReleased
            ) {
                self.server.engine().can_retire_tun(old)?;
            } else {
                self.server.engine().can_rebind_tun(old)?;
            }
            Ok((old, hard))
        };
        let (old, hard) = match check() {
            Ok(parts) => parts,
            Err(error) => {
                return Err(WintunPhysicalFailure::Retained {
                    owner: Box::new(owner),
                    error,
                });
            }
        };
        let attempt = if recreate {
            owner.open_or_recreate(hard)
        } else {
            owner.open(hard)
        };
        let replacement = match attempt {
            Ok(replacement) => replacement,
            Err(original) => {
                if let Some(receipt) = original.owner().retirement()
                    && let Err(error) = self.physical_scope(receipt, observe)
                {
                    self.request_shutdown();
                    return Err(WintunPhysicalFailure::Reconcile { original, error });
                }
                return Err(WintunPhysicalFailure::Open(original));
            }
        };
        let kind = replacement.kind();
        let (source, receipt) = replacement.into_parts();
        if let Err(error) = self.physical_scope(&receipt, observe) {
            return Err(WintunPhysicalFailure::Prepared {
                source: Box::new(source),
                error,
            });
        }
        if Instant::now() >= hard {
            return Err(WintunPhysicalFailure::Prepared {
                source: Box::new(source),
                error: Fault::Deadline.into(),
            });
        }
        if let Err(error) = self.server.engine_mut().retire_tun(old) {
            return Err(WintunPhysicalFailure::Prepared {
                source: Box::new(source),
                error: error.into(),
            });
        }
        self.source = None;
        let current = match self.server.engine_mut().attach_tun() {
            Ok(current) => current,
            Err(error) => {
                return Err(WintunPhysicalFailure::Prepared {
                    source: Box::new(source),
                    error: error.into(),
                });
            }
        };
        self.device = Device {
            io: PacketIo::Native(source),
            provenance: match kind {
                tun::WintunReplacementKind::Created => Provenance::Created,
                tun::WintunReplacementKind::Reopened => Provenance::Borrowed,
            },
        };
        self.source = Some(current);
        self.recovery.configuring = true;
        let setup = match kind {
            tun::WintunReplacementKind::Created => self.start_recovery_configuration(current, hard),
            tun::WintunReplacementKind::Reopened => self.start_recovery_verification(current, hard),
        };
        if let Err(error) = setup {
            self.request_shutdown();
            return Err(WintunPhysicalFailure::Installed(error));
        }
        Ok(())
    }
    pub(in super::super) fn retire_missing_interface(
        &mut self,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if !self.recovery.enabled
            || self.stopping.is_some()
            || self.closed.is_some()
            || self.control.dead
        {
            return Ok(false);
        }
        let loss = match &mut self.device.io {
            PacketIo::Native(io) => io.retire_missing_wintun()?,
        };
        if let Some(loss) = loss {
            self.tun_lost(loss, observe)?;
            return Ok(true);
        }
        Ok(false)
    }
}
