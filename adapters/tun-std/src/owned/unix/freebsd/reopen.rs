//! One-shot closure of a manual TUN FD followed by recoverable native open.
use super::{AsyncTun, Epoch, FreeBsdRecovery, OwnedTun, platform, register, registration_refusal};
use std::{fmt, io};
use tokio::time::Instant;

enum Preflight {
    Transient,
    CloseAttempt(io::Result<()>),
}

/// A checkpointed manual TUN after confirmed retirement of its original FD.
/// The owner retains the same interface and any FD already opened for it.
#[derive(Debug)]
#[must_use]
pub struct FreeBsdReopen {
    tun: OwnedTun,
    original: Epoch,
    until: Instant,
}

/// Refusal to begin physical recovery of the original persistent interface.
#[derive(Debug)]
pub enum FreeBsdReopenStartError {
    /// The original descriptor and checkpoint verify a transient interface.
    /// Its FD remains live so the owner can register another packet epoch.
    Transient(Box<FreeBsdRecovery>),
    /// The original FD remains live. No close was attempted.
    BeforeClose {
        /// Original retained packet descriptor and interface checkpoint.
        owner: Box<FreeBsdRecovery>,
        /// Actual qualification or deadline failure.
        error: io::Error,
    },
    /// The close failed and consumed the original local FD owner.
    CloseUnconfirmed(Box<FreeBsdUnconfirmedClose>),
}

/// An uncertain original FD close with its exact errno and interface custody.
/// This owner cannot mint a replacement FD. Dropping leaves the active
/// checkpoint available for later independently qualified cleanup.
#[derive(Debug)]
#[must_use]
pub struct FreeBsdUnconfirmedClose {
    tun: OwnedTun,
    original: Epoch,
    error: io::Error,
}

impl FreeBsdUnconfirmedClose {
    pub(super) fn new(tun: OwnedTun, original: Epoch, error: io::Error) -> Self {
        Self {
            tun,
            original,
            error,
        }
    }
    /// Permanently retired original packet epoch.
    #[must_use]
    pub const fn original_epoch(&self) -> &Epoch {
        &self.original
    }

    /// Actual original close failure.
    #[must_use]
    pub const fn error(&self) -> &io::Error {
        &self.error
    }

    /// Return the original failure and the separately retained cleanup result.
    /// No further FD close or administrative ioctl is attempted. The cleanup
    /// error holds the original interface and active checkpoint.
    pub fn defer_cleanup(self) -> (io::Error, io::Result<()>) {
        (self.error, defer_cleanup(self.tun))
    }
}

impl fmt::Display for FreeBsdReopenStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(_) => f.write_str("FreeBSD TUN is an owned transient interface"),
            Self::BeforeClose { error, .. } => write!(f, "FreeBSD TUN reopen preflight: {error}"),
            Self::CloseUnconfirmed(owner) => {
                write!(
                    f,
                    "FreeBSD TUN original close unconfirmed: {}",
                    owner.error()
                )
            }
        }
    }
}
impl std::error::Error for FreeBsdReopenStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transient(_) => None,
            Self::BeforeClose { error, .. } => Some(error),
            Self::CloseUnconfirmed(owner) => Some(owner.error()),
        }
    }
}

/// The boundary that refused a physically reopened packet candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreeBsdReopenStage {
    /// The original absolute recovery deadline has passed.
    Deadline,
    /// Resolve and open the exact original persistent device.
    Open,
    /// Verify the opened descriptor, active checkpoint, framing and original FIB.
    Qualify,
    /// Register the qualified descriptor on the caller's reactor.
    Register,
}

/// The unchanged physical recovery owner and actual refusal.
#[derive(Debug)]
pub struct FreeBsdReopenError {
    owner: Box<FreeBsdReopen>,
    stage: FreeBsdReopenStage,
    error: io::Error,
}

impl FreeBsdReopenError {
    /// Resume the same operation or retain its exact interface cleanup owner.
    pub fn into_parts(self) -> (FreeBsdReopen, FreeBsdReopenStage, io::Error) {
        (*self.owner, self.stage, self.error)
    }
}
impl fmt::Display for FreeBsdReopenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FreeBSD TUN physical reopen {:?}: {}",
            self.stage, self.error
        )
    }
}
impl std::error::Error for FreeBsdReopenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The exact original manual interface under a new native packet descriptor.
/// Link, address, route and packet admission decisions still belong to the
/// recovery controller. Closing the old FD can have changed that configuration.
#[must_use]
pub struct FreeBsdReopened {
    source: AsyncTun,
    original: Epoch,
    until: Instant,
}

impl fmt::Debug for FreeBsdReopened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FreeBsdReopened")
            .field("original", &self.original)
            .field("current", &self.source.epoch())
            .field("until", &self.until)
            .finish()
    }
}

impl FreeBsdReopened {
    /// Transfer the candidate FD, retired epoch and unchanged deadline for
    /// configuration observation and controlled packet admission.
    #[must_use]
    pub fn into_parts(self) -> (AsyncTun, Epoch, Instant) {
        (self.source, self.original, self.until)
    }
}

impl FreeBsdRecovery {
    /// Validate the managed manual interface, then close its old FD exactly once.
    /// The caller must retire original route operations and serialize native
    /// interface/device administration throughout this recovery.
    ///
    /// # Errors
    /// Verified transient lifetime and preflight refusal retain the open FD.
    /// An unconfirmed close retains the original checkpoint with no authority
    /// to open a new FD.
    pub fn begin_reopen(
        mut self,
        until: Instant,
    ) -> Result<FreeBsdReopen, FreeBsdReopenStartError> {
        let prepared = (|| {
            let handle = self
                .tun
                .handle
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?;
            check_deadline(until)?;
            let scope = platform::recovery::prepare_reopen_packet(
                handle,
                &self.tun.info,
                self.original.route_table(),
            )?;
            check_deadline(until)?;
            Ok::<_, io::Error>(match scope {
                platform::recovery::ReopenScope::Transient => Preflight::Transient,
                platform::recovery::ReopenScope::Manual => {
                    Preflight::CloseAttempt(handle.close_packet_fd())
                }
            })
        })();
        let FreeBsdRecovery { tun, original } = self;
        match prepared {
            Err(error) => Err(FreeBsdReopenStartError::BeforeClose {
                owner: Box::new(FreeBsdRecovery { tun, original }),
                error,
            }),
            Ok(Preflight::Transient) => Err(FreeBsdReopenStartError::Transient(Box::new(
                FreeBsdRecovery { tun, original },
            ))),
            Ok(Preflight::CloseAttempt(Err(error))) => Err(
                FreeBsdReopenStartError::CloseUnconfirmed(Box::new(FreeBsdUnconfirmedClose {
                    tun,
                    original,
                    error,
                })),
            ),
            Ok(Preflight::CloseAttempt(Ok(()))) => Ok(FreeBsdReopen {
                tun,
                original,
                until,
            }),
        }
    }
}

impl FreeBsdReopen {
    /// Begin absence verification after a confirmed descriptor close.
    /// The caller provides every original owned route key and serializes native
    /// route and interface administration through recreation.
    pub fn begin_recreate(
        self,
        keys: Vec<super::FreeBsdRouteKey>,
    ) -> Result<super::FreeBsdRecreate, super::FreeBsdRecreateStartError<Self>> {
        let Self {
            tun,
            original,
            until,
        } = self;
        super::recreate::begin(tun, original, keys, until, |tun, original| Self {
            tun,
            original,
            until,
        })
    }

    /// Open and register the original unit. An already opened candidate FD is
    /// requalified and reused if a previous attempt failed after open.
    ///
    /// # Errors
    /// Retains the original interface, checkpoint and any opened FD. Native
    /// operations cannot be preempted. Check the returned deadline again before
    /// exposing packet readiness.
    pub fn open(mut self) -> Result<FreeBsdReopened, FreeBsdReopenError> {
        if let Err(error) = check_deadline(self.until) {
            return Err(self.refused(FreeBsdReopenStage::Deadline, error));
        }
        let Some(handle) = self.tun.handle.as_mut() else {
            return Err(self.refused(FreeBsdReopenStage::Open, io::ErrorKind::NotConnected.into()));
        };
        let fib = self.original.route_table();
        if handle.fd().is_err()
            && let Err(error) =
                platform::recovery::open_retained_packet(handle, &self.tun.info, fib)
        {
            return Err(self.refused(FreeBsdReopenStage::Open, error));
        }
        if let Err(error) = check_deadline(self.until) {
            return Err(self.refused(FreeBsdReopenStage::Deadline, error));
        }
        if let Err(error) = platform::recovery::verify_retained_packet(handle, &self.tun.info, fib)
        {
            return Err(self.refused(FreeBsdReopenStage::Qualify, error));
        }
        if let Err(error) = check_deadline(self.until) {
            return Err(self.refused(FreeBsdReopenStage::Deadline, error));
        }
        let Self {
            tun,
            original,
            until,
        } = self;
        match register(tun, &original) {
            Ok(source) => Ok(FreeBsdReopened {
                source,
                original,
                until,
            }),
            Err(failure) => {
                let (tun, error) = registration_refusal(*failure);
                Err(Self {
                    tun,
                    original,
                    until,
                }
                .refused(FreeBsdReopenStage::Register, error))
            }
        }
    }

    /// Close the candidate FD if present, deferring administrative interface
    /// destruction with the original checkpoint still attached to its owner.
    ///
    /// # Errors
    /// Returns the retained interface cleanup owner and any actual FD error.
    pub fn defer_cleanup(self) -> io::Result<()> {
        defer_cleanup(self.tun)
    }

    fn refused(self, stage: FreeBsdReopenStage, error: io::Error) -> FreeBsdReopenError {
        FreeBsdReopenError {
            owner: Box::new(self),
            stage,
            error,
        }
    }
}

fn check_deadline(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

pub(super) fn defer_cleanup(mut tun: OwnedTun) -> io::Result<()> {
    tun.defer_interface_cleanup();
    tun.close()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceHandle, Info, Limits, Mode, Stamp};
    use std::{
        cell::Cell,
        os::fd::{AsRawFd, OwnedFd},
        rc::Rc,
        time::Duration,
    };

    fn owner() -> io::Result<FreeBsdRecovery> {
        let fd = OwnedFd::from(std::fs::File::open("/dev/null")?);
        let tun = OwnedTun {
            handle: Some(DeviceHandle::from_fd(fd)),
            info: Info {
                name: String::from("tun42"),
                index: 42,
                mode: Mode::FreeBsd,
            },
            limits: Limits::default(),
            epoch: Epoch(Rc::new(Stamp {
                alive: Cell::new(true),
                route_table: Some(0),
            })),
            next_effect: 0,
        };
        Ok(tun.retain_freebsd())
    }

    #[test]
    fn refused_preflight_keeps_the_original_fd() -> io::Result<()> {
        let owner = owner()?;
        let original_fd = owner.tun.descriptor()?.as_raw_fd();
        let original_epoch = owner.original_epoch().clone();
        let until = Instant::now() + Duration::from_secs(5);
        let Err(FreeBsdReopenStartError::BeforeClose { owner, .. }) = owner.begin_reopen(until)
        else {
            return Err(io::Error::other(
                "unmanaged descriptor passed reopen preflight",
            ));
        };
        if owner.original_epoch() != &original_epoch
            || original_epoch.current()
            || owner.tun.descriptor()?.as_raw_fd() != original_fd
        {
            return Err(io::Error::other(
                "preflight lost the original descriptor or epoch",
            ));
        }
        owner.close()
    }

    #[test]
    fn physical_retry_preserves_an_existing_candidate_fd() -> io::Result<()> {
        let FreeBsdRecovery { tun, original } = owner()?;
        let candidate_fd = tun.descriptor()?.as_raw_fd();
        let until = Instant::now() + Duration::from_secs(5);
        // Model a previously opened candidate without a managed interface.
        // Qualification must fail before any attempt to close or reopen it.
        let reopen = FreeBsdReopen {
            tun,
            original,
            until,
        };
        let failure = reopen
            .open()
            .err()
            .ok_or_else(|| io::Error::other("unqualified candidate was accepted"))?;
        let (reopen, stage, _) = failure.into_parts();
        if stage != FreeBsdReopenStage::Qualify
            || reopen.until != until
            || reopen.tun.descriptor()?.as_raw_fd() != candidate_fd
        {
            return Err(io::Error::other(
                "physical qualification replaced the candidate or extended the deadline",
            ));
        }
        reopen.defer_cleanup()
    }
}
