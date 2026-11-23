//! Checkpointed replacement after independent interface and FIB absence.
use super::{
    AsyncTun, Epoch, FreeBsdRecovery, FreeBsdUnconfirmedClose, OwnedTun, platform, register,
    registration_refusal, reopen::defer_cleanup,
};
use crate::{
    RouteQuery, RouteQueryCompletion, RouteQueryEvidence, RouteQueryOutcome, RouteQueryProgress,
    RouteQuerySubmission,
};
use std::{
    io,
    net::IpAddr,
    task::{Context, Poll},
};
use tokio::time::Instant;

/// One exact route key from the original owned FreeBSD plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreeBsdRouteKey {
    destination: IpAddr,
    prefix: u8,
}

impl FreeBsdRouteKey {
    /// Validate a canonical network and prefix length.
    pub fn new(destination: IpAddr, prefix: u8) -> io::Result<Self> {
        crate::routes::network(destination, prefix)?;
        Ok(Self {
            destination,
            prefix,
        })
    }
}

/// Recreation was refused during native absence and close preflight.
#[derive(Debug)]
pub enum FreeBsdRecreateStartError<S> {
    /// The original recovery owner remains intact.
    Refused {
        /// Original recovery stage and descriptor ownership.
        owner: Box<S>,
        /// Actual preflight error, including an occupied index.
        error: io::Error,
    },
    /// The original packet descriptor close was attempted and is unconfirmed.
    CloseUnconfirmed(Box<FreeBsdUnconfirmedClose>),
}

struct Original {
    tun: OwnedTun,
    epoch: Epoch,
    fib: u32,
    until: Instant,
}

impl Original {
    fn check(&mut self) -> io::Result<()> {
        check_deadline(self.until)?;
        let handle = self
            .tun
            .handle
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?;
        platform::recovery::fence_missing(handle, &self.tun.info)?;
        check_deadline(self.until)
    }
}

/// Read-only verification of every original owned route key in the old FIB.
/// Progress retains the original checkpoint lock and the same outage deadline.
#[must_use]
pub struct FreeBsdRecreate {
    original: Option<Original>,
    keys: Vec<FreeBsdRouteKey>,
    cursor: usize,
    route: Option<Box<RouteQuery>>,
    failed: bool,
}

/// Original packet close and route absence have been established. The original
/// checkpoint stays locked until exclusive provisioning or a terminal failure.
#[must_use]
pub struct FreeBsdVacancy(Original);

/// A new interface with its own native identity and an active checkpoint.
/// Native addresses, routes and packet admission are still the caller's work.
#[must_use]
pub struct FreeBsdRecreated {
    source: AsyncTun,
    original: Epoch,
    until: Instant,
}

impl FreeBsdRecreated {
    /// Transfer the new source, retired packet identity and original deadline.
    #[must_use]
    pub fn into_parts(self) -> (AsyncTun, Epoch, Instant) {
        (self.source, self.original, self.until)
    }
}

impl FreeBsdRecovery {
    /// Begin verification after the recorded interface has disappeared.
    /// Supply all owned route keys and serialize native interface and route
    /// administration through the returned owner. No route mutation occurs.
    pub fn begin_recreate(
        self,
        keys: Vec<FreeBsdRouteKey>,
        until: Instant,
    ) -> Result<FreeBsdRecreate, FreeBsdRecreateStartError<Self>> {
        let Self { tun, original } = self;
        begin(tun, original, keys, until, |tun, original| Self {
            tun,
            original,
        })
    }
}

pub(super) fn begin<S>(
    tun: OwnedTun,
    epoch: Epoch,
    keys: Vec<FreeBsdRouteKey>,
    until: Instant,
    restore: impl FnOnce(OwnedTun, Epoch) -> S,
) -> Result<FreeBsdRecreate, FreeBsdRecreateStartError<S>> {
    let Some(fib) = epoch.route_table().filter(|_| !epoch.current()) else {
        return Err(FreeBsdRecreateStartError::Refused {
            owner: Box::new(restore(tun, epoch)),
            error: io::ErrorKind::InvalidInput.into(),
        });
    };
    let mut original = Original {
        tun,
        epoch,
        fib,
        until,
    };
    let checked = if keys.len() > 256 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many original FreeBSD route keys",
        ))
    } else {
        original.check()
    };
    if let Err(error) = checked {
        return Err(FreeBsdRecreateStartError::Refused {
            owner: Box::new(restore(original.tun, original.epoch)),
            error,
        });
    }
    if let Some(handle) = original.tun.handle.as_mut()
        && let Err(error) = handle.close_packet_fd()
    {
        return Err(FreeBsdRecreateStartError::CloseUnconfirmed(Box::new(
            FreeBsdUnconfirmedClose::new(original.tun, original.epoch, error),
        )));
    }
    Ok(FreeBsdRecreate {
        original: Some(original),
        keys,
        cursor: 0,
        route: None,
        failed: false,
    })
}

fn check_deadline(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}

impl FreeBsdRecreate {
    /// Advance the original read-only proof. Every query must complete with a
    /// clean, correlated absent receipt from a full FIB dump.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<FreeBsdVacancy>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::other("FreeBSD route proof already failed")));
        }
        let result = self.advance(cx);
        self.failed = matches!(&result, Poll::Ready(Err(_)));
        result
    }

    fn advance(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<FreeBsdVacancy>> {
        let original = self.original.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        check_deadline(original.until)?;
        if let Some(route) = &mut self.route {
            match route.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(RouteQueryProgress::Complete(receipt)) => {
                    self.route = None;
                    require_absent(receipt)?;
                    self.cursor += 1;
                }
                Poll::Ready(RouteQueryProgress::Finished) => {
                    return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
                }
                Poll::Ready(_) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
        if let Some(key) = self.keys.get(self.cursor) {
            self.route = Some(Box::new(crate::routes::query_vacant(
                original.epoch.clone(),
                original.tun.info.clone(),
                key.destination,
                key.prefix,
                original.until,
            )?));
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        original.check()?;
        self.original.take().map(FreeBsdVacancy).map_or_else(
            || Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
            |proof| Poll::Ready(Ok(proof)),
        )
    }

    /// Close the active read-only query and defer any remaining original
    /// interface and checkpoint cleanup. No replacement is created.
    pub fn cancel(mut self) -> io::Result<()> {
        let close = self
            .route
            .take()
            .and_then(|mut route| match route.cancel() {
                RouteQueryProgress::Complete(receipt) => receipt.close_error,
                _ => None,
            });
        let deferred = self
            .original
            .take()
            .map_or(Ok(()), |original| defer_cleanup(original.tun));
        match (close, deferred) {
            (None, deferred) => deferred,
            (Some(error), deferred) => Err(with_cleanup(error, deferred)),
        }
    }
}

fn require_absent(receipt: RouteQueryCompletion) -> io::Result<()> {
    match (receipt.write_error, receipt.close_error) {
        (None, None) => {}
        (Some(error), None) | (None, Some(error)) => return Err(error),
        (Some(error), Some(cleanup)) => return Err(with_cleanup(error, Err(cleanup))),
    }
    if receipt.evidence == Some(RouteQueryEvidence::FreeBsdDump)
        && matches!(receipt.submission, RouteQuerySubmission::Whole { .. })
        && matches!(receipt.outcome, RouteQueryOutcome::Absent)
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "old FreeBSD route key is not proven absent: {:?}",
            receipt.outcome
        )))
    }
}

impl FreeBsdVacancy {
    /// The old epoch whose native route effects were proved absent.
    #[must_use]
    pub const fn original_epoch(&self) -> &Epoch {
        &self.0.epoch
    }

    /// The original absolute recovery deadline.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.0.until
    }

    /// Confirm vacancy once more, then provision under the original lock and
    /// in the original FIB with a new allocation intent and marker.
    pub fn create(self) -> io::Result<FreeBsdRecreated> {
        let Original {
            mut tun,
            epoch,
            fib,
            until,
        } = self.0;
        check_deadline(until)?;
        let handle = tun.handle.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        let journal = platform::recovery::retire_missing(handle, &tun.info)?;
        check_deadline(until)?;
        let mut candidate = crate::recovery::managed::create(
            journal,
            Some(&tun.info.name),
            tun.limits,
            crate::recovery::managed::Scope::Recreation { fib, until },
        )
        .map_err(io::Error::other)?;
        let invalid = if Instant::now() >= until {
            Some(io::Error::from(io::ErrorKind::TimedOut))
        } else if candidate.epoch().route_table() != Some(fib) {
            Some(io::Error::other(
                "new FreeBSD TUN is outside the original FIB",
            ))
        } else {
            None
        };
        if let Some(error) = invalid {
            candidate.defer_interface_cleanup();
            return Err(with_cleanup(error, candidate.close()));
        }
        let source = match register(candidate, &epoch) {
            Ok(source) => source,
            Err(failure) => {
                let (mut candidate, error) = registration_refusal(*failure);
                candidate.defer_interface_cleanup();
                return Err(with_cleanup(error, candidate.close()));
            }
        };
        Ok(FreeBsdRecreated {
            source,
            original: epoch,
            until,
        })
    }
}

fn with_cleanup(original: io::Error, cleanup: io::Result<()>) -> io::Error {
    match cleanup {
        Ok(()) => original,
        Err(cleanup) => io::Error::new(
            original.kind(),
            Cleanup {
                operation: original,
                cleanup,
            },
        ),
    }
}

#[derive(Debug)]
struct Cleanup {
    operation: io::Error,
    cleanup: io::Error,
}

impl std::fmt::Display for Cleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (cleanup: {})", self.operation, self.cleanup)
    }
}

impl std::error::Error for Cleanup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.operation)
    }
}
