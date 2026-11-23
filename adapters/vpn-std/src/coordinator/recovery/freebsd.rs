//! Recover packet I/O on the original checkpointed FreeBSD interface.
use super::{Coordinator, Error, Fault, tun};
use crate::coordinator::{Event, FreeBsdRecoveryStage, PacketIo, Provenance, core};
use std::{
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

pub(super) const RETRY_INTERVAL: Duration = Duration::from_millis(100);

pub(in crate::coordinator) enum PacketRecovery {
    Retained(Box<tun::FreeBsdRecovery>),
    Reopen(Box<tun::FreeBsdReopen>),
    Recreate(Box<tun::FreeBsdRecreate>),
    Unconfirmed(Box<tun::FreeBsdUnconfirmedClose>),
}

impl PacketRecovery {
    pub(in crate::coordinator) fn close(self) -> io::Result<()> {
        match self {
            Self::Retained(owner) => owner.close(),
            Self::Reopen(owner) => owner.defer_cleanup(),
            Self::Recreate(owner) => owner.cancel(),
            Self::Unconfirmed(owner) => {
                let (close, cleanup) = owner.defer_cleanup();
                let error = match cleanup {
                    Ok(()) => close,
                    Err(cleanup) => {
                        io::Error::new(close.kind(), UnconfirmedClose { close, cleanup })
                    }
                };
                Err(error)
            }
        }
    }
}

enum Candidate {
    Retained(tun::AsyncTun),
    Reopened(tun::FreeBsdReopened),
    Recreated(tun::FreeBsdRecreated),
}

#[derive(Clone, Copy)]
enum Configuration {
    Verify,
    Restore,
    Install,
}

impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    /// Enable live packet recovery for the original managed FreeBSD TUN.
    /// Recovery keeps the interface, checkpoint, FIB and original outage bound.
    ///
    /// # Errors
    /// Refuses changes after startup and devices without a managed checkpoint.
    pub fn enable_freebsd_recovery(&mut self) -> Result<(), Error> {
        if self.source.is_some() || self.closed.is_some() || self.stopping.is_some() {
            return Err(Fault::Conflict.into());
        }
        if self.device.provenance != Provenance::Created {
            return Err(Fault::PermissionDenied.into());
        }
        let PacketIo::Native(io) = &mut self.device.io else {
            return Err(Fault::Unsupported.into());
        };
        io.enable_freebsd_recovery()?;
        self.recovery.enabled = true;
        Ok(())
    }

    pub(in crate::coordinator) fn retire_missing_interface(
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
        if let PacketIo::Native(io) = &mut self.device.io
            && let Some(loss) = io.retire_missing_freebsd()?
        {
            self.tun_lost(loss, observe)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(in crate::coordinator) fn poll_freebsd_recovery(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if self.stopping.is_some() || self.recovery.packet.is_none() {
            return Ok(false);
        }
        let now = Instant::now();
        if self.recovery.retry_at.is_some_and(|at| now < at) {
            return Ok(false);
        }
        self.recovery.retry_at = None;
        let old = self.source.ok_or(Fault::NotReady)?;
        let hard = self.recovery.hard.ok_or(Fault::NotReady)?;
        if now >= hard {
            return Err(Fault::Deadline.into());
        }
        if !self.control.dead || self.control.unconfirmed_control_closes != 0 {
            return Err(Fault::Conflict.into());
        }
        match self.server.engine().can_rebind_tun(old) {
            Ok(()) => {}
            Err(Fault::WouldBlock) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        let epoch = self.device.epoch().ok_or(Fault::NotReady)?;
        let owner = self.recovery.packet.take().ok_or(Fault::NotReady)?;
        let owner = match owner {
            PacketRecovery::Retained(owner) if owner.original_epoch() == &epoch => owner,
            PacketRecovery::Retained(owner) => {
                self.recovery.packet = Some(PacketRecovery::Retained(owner));
                return Err(Fault::StaleGeneration.into());
            }
            PacketRecovery::Reopen(owner) => {
                return self.finish_freebsd_reopen(*owner, old, hard, observe);
            }
            PacketRecovery::Recreate(mut owner) => match owner.poll(cx) {
                Poll::Pending => {
                    self.recovery.packet = Some(PacketRecovery::Recreate(owner));
                    return Ok(false);
                }
                Poll::Ready(Err(error)) => {
                    self.recovery.packet = Some(PacketRecovery::Recreate(owner));
                    return Err(error.into());
                }
                Poll::Ready(Ok(vacancy)) => {
                    if vacancy.original_epoch() != &epoch || vacancy.deadline() != hard {
                        return Err(Fault::StaleGeneration.into());
                    }
                    self.server.engine_mut().confirm_routes_absent(old)?;
                    self.control.uncertain = false;
                    return self.admit_freebsd_candidate(
                        Candidate::Recreated(vacancy.create()?),
                        old,
                        hard,
                    );
                }
            },
            PacketRecovery::Unconfirmed(owner) => {
                self.recovery.packet = Some(PacketRecovery::Unconfirmed(owner));
                return Err(Fault::Io.into());
            }
        };
        match owner.begin_reopen(hard) {
            Ok(owner) => self.finish_freebsd_reopen(owner, old, hard, observe),
            Err(tun::FreeBsdReopenStartError::Transient(owner)) => match owner.restart() {
                Ok(source) => self.admit_freebsd_candidate(Candidate::Retained(source), old, hard),
                Err(failure) => {
                    let (owner, stage, error) = failure.into_parts();
                    if error.kind() == io::ErrorKind::NotFound {
                        return self.begin_freebsd_recreation(
                            owner,
                            |owner, keys| owner.begin_recreate(keys, hard),
                            PacketRecovery::Retained,
                            hard,
                            observe,
                        );
                    }
                    self.retry_freebsd(
                        PacketRecovery::Retained(Box::new(owner)),
                        FreeBsdRecoveryStage::Restart(stage),
                        error,
                        hard,
                        observe,
                    )
                }
            },
            Err(tun::FreeBsdReopenStartError::BeforeClose { owner, error })
                if error.kind() == io::ErrorKind::NotFound =>
            {
                self.begin_freebsd_recreation(
                    *owner,
                    |owner, keys| owner.begin_recreate(keys, hard),
                    PacketRecovery::Retained,
                    hard,
                    observe,
                )
            }
            Err(tun::FreeBsdReopenStartError::BeforeClose { owner, error }) => self.retry_freebsd(
                PacketRecovery::Retained(owner),
                FreeBsdRecoveryStage::BeforeClose,
                error,
                hard,
                observe,
            ),
            Err(tun::FreeBsdReopenStartError::CloseUnconfirmed(owner)) => {
                self.recovery.packet = Some(PacketRecovery::Unconfirmed(owner));
                Err(Fault::Io.into())
            }
        }
    }

    fn finish_freebsd_reopen(
        &mut self,
        owner: tun::FreeBsdReopen,
        old: core::Tun<'id>,
        hard: Instant,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        match owner.open() {
            Ok(reopened) => self.admit_freebsd_candidate(Candidate::Reopened(reopened), old, hard),
            Err(failure) => {
                let (owner, stage, error) = failure.into_parts();
                if error.kind() == io::ErrorKind::NotFound {
                    return self.begin_freebsd_recreation(
                        owner,
                        tun::FreeBsdReopen::begin_recreate,
                        PacketRecovery::Reopen,
                        hard,
                        observe,
                    );
                }
                self.retry_freebsd(
                    PacketRecovery::Reopen(Box::new(owner)),
                    FreeBsdRecoveryStage::Reopen(stage),
                    error,
                    hard,
                    observe,
                )
            }
        }
    }

    fn begin_freebsd_recreation<S>(
        &mut self,
        owner: S,
        start: impl FnOnce(
            S,
            Vec<tun::FreeBsdRouteKey>,
        ) -> Result<tun::FreeBsdRecreate, tun::FreeBsdRecreateStartError<S>>,
        retained: impl FnOnce(Box<S>) -> PacketRecovery,
        hard: Instant,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let keys = match self.freebsd_owned_route_keys() {
            Ok(keys) => keys,
            Err(error) => {
                self.recovery.packet = Some(retained(Box::new(owner)));
                return Err(error);
            }
        };
        match start(owner, keys) {
            Ok(owner) => {
                self.recovery.packet = Some(PacketRecovery::Recreate(Box::new(owner)));
                Ok(true)
            }
            Err(tun::FreeBsdRecreateStartError::Refused { owner, error }) => self.retry_freebsd(
                retained(owner),
                FreeBsdRecoveryStage::RecreatePreflight,
                error,
                hard,
                observe,
            ),
            Err(tun::FreeBsdRecreateStartError::CloseUnconfirmed(owner)) => {
                self.recovery.packet = Some(PacketRecovery::Unconfirmed(owner));
                Err(Fault::Io.into())
            }
        }
    }

    fn retry_freebsd(
        &mut self,
        owner: PacketRecovery,
        stage: FreeBsdRecoveryStage,
        error: io::Error,
        hard: Instant,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        self.recovery.packet = Some(owner);
        if !matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::ResourceBusy
        ) {
            return Err(io::Error::new(error.kind(), FreeBsdRefusal { stage, error }).into());
        }
        self.recovery.retry_at = Some(Self::deadline(RETRY_INTERVAL)?.min(hard));
        observe(Event::FreeBsdRecoveryRetry { stage, error });
        Ok(true)
    }

    fn admit_freebsd_candidate(
        &mut self,
        candidate: Candidate,
        old: core::Tun<'id>,
        hard: Instant,
    ) -> Result<bool, Error> {
        let (mut source, configuration, scope_matches) = match candidate {
            Candidate::Retained(source) => (source, Configuration::Verify, true),
            Candidate::Reopened(candidate) => {
                let (source, original, until) = candidate.into_parts();
                let exact_scope = self.freebsd_candidate_matches(&source, &original, until, hard);
                (source, Configuration::Restore, exact_scope)
            }
            Candidate::Recreated(candidate) => {
                let (source, original, until) = candidate.into_parts();
                let exact_scope = self.freebsd_candidate_matches(&source, &original, until, hard);
                (source, Configuration::Install, exact_scope)
            }
        };
        // The native owner still requires explicit close if logical admission
        // is refused. It must not become a new packet source after the bound.
        let replacement = if !scope_matches {
            Err(Fault::StaleGeneration)
        } else if Instant::now() >= hard {
            Err(Fault::Deadline)
        } else if matches!(configuration, Configuration::Install) {
            let engine = self.server.engine_mut();
            engine.retire_tun(old).and_then(|()| engine.attach_tun())
        } else {
            self.server.engine_mut().rebind_tun_same_interface(old)
        };
        let current = match replacement {
            Ok(current) => current,
            Err(reason) => {
                source.defer_interface_cleanup();
                let loss = source.close();
                if let Some(error) = loss.close_error {
                    self.control.prior_tun_close_error.get_or_insert(error);
                }
                return Err(reason.into());
            }
        };
        self.device.io = PacketIo::Native(source);
        self.source = Some(current);
        self.recovery.configuring = true;
        match configuration {
            Configuration::Verify => self.start_recovery_verification(current, hard)?,
            Configuration::Restore => self.start_recovery_restoration(current, hard)?,
            Configuration::Install => {
                self.start_recovery_configuration(current, hard)?;
            }
        }
        Ok(true)
    }

    fn freebsd_candidate_matches(
        &self,
        source: &tun::AsyncTun,
        original: &tun::Epoch,
        until: Instant,
        hard: Instant,
    ) -> bool {
        let current = source.epoch();
        self.device.epoch().as_ref() == Some(original)
            && !original.current()
            && &current != original
            && current.route_table().is_some()
            && current.route_table() == original.route_table()
            && until == hard
    }
}

#[derive(Debug)]
struct FreeBsdRefusal {
    stage: FreeBsdRecoveryStage,
    error: io::Error,
}

#[derive(Debug)]
struct UnconfirmedClose {
    close: io::Error,
    cleanup: io::Error,
}
impl std::fmt::Display for UnconfirmedClose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FreeBSD TUN close: {}; original interface cleanup: {}",
            self.close, self.cleanup
        )
    }
}
impl std::error::Error for UnconfirmedClose {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cleanup)
    }
}
impl std::fmt::Display for FreeBsdRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FreeBSD TUN recovery {:?}: {}", self.stage, self.error)
    }
}
impl std::error::Error for FreeBsdRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
