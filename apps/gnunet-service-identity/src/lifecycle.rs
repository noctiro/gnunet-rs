//! Original selected diagnostics, finite MQ grace, and owned terminal facts.
use crate::Failure;
use gnunet_identity_host::server;
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Driver, Progress};
use std::{
    cell::RefCell,
    fmt,
    future::Future,
    io,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Only diagnostic causes are retained here, never private inventory or frames.
#[derive(Debug, Default)]
pub(super) struct Diagnostics {
    errors: [Option<server::Error>; 4],
    additional: u64,
}
impl Diagnostics {
    fn push(&mut self, error: server::Error) {
        if let Some(slot) = self.errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.additional = self.additional.saturating_add(1);
        }
    }
    fn first(&self) -> Option<&server::Error> {
        self.errors.iter().find_map(Option::as_ref)
    }
}

#[derive(Clone)]
pub(super) struct Notes {
    reporter: Reporter,
    diagnostics: Rc<RefCell<Diagnostics>>,
}
impl Notes {
    pub fn new(reporter: Reporter) -> Self {
        Self {
            reporter,
            diagnostics: Rc::new(RefCell::new(Diagnostics::default())),
        }
    }
    pub fn observe(&self, event: server::Event) {
        match event {
            server::Event::StorageFailed(error) => {
                self.reporter.warning(
                    "identity.store.failed",
                    format_args!("IDENTITY original store failure: {error}"),
                );
                self.diagnostics
                    .borrow_mut()
                    .push(server::Error::Storage(error));
            }
            server::Event::CleanupFailed(error) => {
                self.reporter.warning(
                    "identity.cleanup.failed",
                    format_args!("IDENTITY independent cleanup failure: {error}"),
                );
                self.diagnostics.borrow_mut().push(error.into());
            }
            other => self.reporter.debug(
                "identity.server.activity",
                format_args!("IDENTITY original Server event: {other:?}"),
            ),
        }
    }
    pub fn take(&self) -> Diagnostics {
        std::mem::take(&mut *self.diagnostics.borrow_mut())
    }
}

/// One original Broker, physically retired even when disconnect itself fails.
pub(super) struct Resolver {
    original: Option<Driver<8, 256>>,
}
impl Resolver {
    pub fn new(original: Driver<8, 256>) -> Self {
        Self {
            original: Some(original),
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        reports: &Reporter,
    ) -> Poll<Result<Progress, BrokerError>> {
        let Some(original) = &mut self.original else {
            return Poll::Pending;
        };
        let mut driving = std::pin::pin!(original.drive_waiting(until, |event| {
            reports.debug(
                "identity.resolver.activity",
                format_args!("IDENTITY original Resolver event: {event:?}"),
            );
        }));
        driving.as_mut().poll(cx)
    }
    pub fn close(&mut self) -> Option<BrokerError> {
        let mut original = self.original.take()?;
        let error = original.disconnect().err();
        // Driver::drop clears the original physical owner independently of the
        // canonical clock, including when disconnect refused or lost its lock.
        drop(original);
        error
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        // Emergency unwinding is physical retirement, never a successful report.
        let _actual = self.close();
    }
}

/// Created once at the original stop/error, never renewed by worker progress.
pub(super) struct Grace {
    pub hard: Instant,
    alarm: Pin<Box<Sleep>>,
    observed: bool,
}
impl Grace {
    pub fn new(lifetime: Duration) -> io::Result<Self> {
        let hard = Instant::now()
            .checked_add(lifetime)
            .ok_or_else(|| io::Error::other("IDENTITY shutdown deadline overflow"))?;
        Ok(Self {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
            observed: false,
        })
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        if self.observed {
            return true;
        }
        if Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready() {
            self.observed = true;
        }
        self.observed
    }
}

/// This owns actual reports even if logging is the only final failure.
#[derive(Debug, Default)]
pub(super) struct Terminal {
    pub operation: Option<Failure>,
    pub server: Option<server::Shutdown>,
    pub constructor_worker: Option<Result<gnunet_identity_host::worker::Stopped, server::Error>>,
    pub resolver: Option<BrokerError>,
    pub output: Option<io::Error>,
    pub logging: Option<io::Error>,
    pub deadline: Option<io::Error>,
    pub grace_elapsed: bool,
    pub diagnostics: Diagnostics,
}
impl Terminal {
    fn failed(&self) -> bool {
        self.operation.is_some()
            || self.server.as_ref().is_some_and(|stopped| {
                stopped.failure.is_some()
                    || stopped
                        .worker
                        .as_ref()
                        .is_none_or(|worker| worker.failure.is_some())
            })
            || self
                .constructor_worker
                .as_ref()
                .is_some_and(|result| match result {
                    Ok(worker) => worker.failure.is_some(),
                    Err(_) => true,
                })
            || self.resolver.is_some()
            || self.output.is_some()
            || self.logging.is_some()
            || self.deadline.is_some()
            || self.diagnostics.first().is_some()
            || self.diagnostics.additional != 0
    }
    pub fn finish(mut self, logging: Option<io::Error>) -> Result<Self, Failure> {
        self.logging = logging;
        if self.failed() {
            Err(Box::new(self))
        } else {
            Ok(self)
        }
    }
}
impl fmt::Display for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IDENTITY original lifecycle: {self:?}")
    }
}
impl std::error::Error for Terminal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.operation
            .as_deref()
            .or_else(|| {
                self.server
                    .as_ref()
                    .and_then(|stopped| stopped.failure.as_ref())
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.server
                    .as_ref()
                    .and_then(|stopped| stopped.worker.as_ref())
                    .and_then(|worker| worker.failure.as_ref())
                    .map(|error| error.as_ref() as &dyn std::error::Error)
            })
            .or_else(|| {
                self.constructor_worker
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.constructor_worker
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .and_then(|worker| worker.failure.as_ref())
                    .map(|error| error.as_ref() as &dyn std::error::Error)
            })
            .or_else(|| {
                self.resolver
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.output
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.logging
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.deadline
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.diagnostics
                    .first()
                    .map(|error| error as &dyn std::error::Error)
            })
    }
}

/// The selected Logger already handled the terminal diagnostic.
#[derive(Debug)]
pub(super) struct Reported(pub Failure);
impl fmt::Display for Reported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for Reported {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
