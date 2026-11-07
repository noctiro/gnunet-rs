//! One selected PROGRAM logger; actual cleanup and output failures stay owned.
use crate::Failure;
use gnunet_program_host::{
    logging::Logger, policy::Level, program, reporting::Reporter, service,
    shared_clock::SharedClock,
};
use std::{cell::RefCell, fmt, rc::Rc, task::Context};
struct Inner {
    reporter: Reporter,
    cleanup: RefCell<CleanupErrors>,
}
#[derive(Debug, Default)]
struct CleanupErrors {
    monitor: Option<Failure>,
    resolver: Option<Failure>,
}
impl CleanupErrors {
    fn is_empty(&self) -> bool {
        self.monitor.is_none() && self.resolver.is_none()
    }
}
#[derive(Clone, Copy)]
pub(super) enum Cleanup {
    Monitor,
    Resolver,
}
#[derive(Debug)]
struct CleanupFailure {
    original: Option<Failure>,
    cleanup: CleanupErrors,
}
impl fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CORE original={:?}; independent drop cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.monitor.as_deref())
            .or(self.cleanup.resolver.as_deref())
    }
}
/// Terminal selected-route marker. Even a filtered or failed selected write must
/// not be retried through main's unselected stderr fallback.
#[derive(Debug)]
struct Reported(Failure);
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
pub(super) fn was_reported(error: &Failure) -> bool {
    error.is::<Reported>()
}
#[derive(Debug)]
struct PreparationFailure(program::Stopped);
impl fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CORE CLI PROGRAM stopped: {:?} (source code {})",
            self.0.reason, self.0.code
        )
    }
}
impl std::error::Error for PreparationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0.reason {
            program::StoppedReason::Logging(error) => Some(error),
            program::StoppedReason::Malformed(error) => Some(error),
            _ => None,
        }
    }
}
#[derive(Clone)]
pub(super) struct Reports(Rc<Inner>);
impl Reports {
    pub(super) fn new(logger: Logger<'static>, clock: SharedClock) -> Self {
        Self(Rc::new(Inner {
            reporter: Reporter::new(logger, clock),
            cleanup: RefCell::new(CleanupErrors::default()),
        }))
    }
    /// PROGRAM already emitted parser/configuration diagnostics to their proper
    /// route. Keep the typed original stop without repeating it on raw stderr.
    /// An actual setup failure still needs its cause reported through this same
    /// Logger; its prior/default destination stays owned by that original object.
    pub(super) fn stopped(&self, stopped: program::Stopped) -> Result<(), Failure> {
        let setup_failed = matches!(&stopped.reason, program::StoppedReason::Logging(_));
        let error = Box::new(PreparationFailure(stopped)) as Failure;
        if setup_failed {
            self.finish(Err(error))
        } else {
            Err(Box::new(Reported(error)))
        }
    }
    pub(super) fn register(&self, cx: &Context<'_>) {
        self.0.reporter.register(cx);
    }
    pub(super) fn failed(&self) -> bool {
        self.0.reporter.failed()
    }
    pub(super) fn warning(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.0.reporter.warning(site, args);
    }
    pub(super) fn debug(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.0.reporter.debug(site, args);
    }
    /// Drop cleanup has one original observation per owner; keep the cause even
    /// when its selected diagnostic destination has already failed.
    pub(super) fn cleanup(&self, owner: Cleanup, error: Failure) {
        self.warning(
            "core-cli.drop.cleanup",
            format_args!("core-cli original cleanup: {error}"),
        );
        let mut cleanup = self.0.cleanup.borrow_mut();
        let slot = match owner {
            Cleanup::Monitor => &mut cleanup.monitor,
            Cleanup::Resolver => &mut cleanup.resolver,
        };
        if slot.is_none() {
            *slot = Some(error);
        }
    }
    /// Called after the original runtime and its owners have completed or
    /// dropped. Logging never cancels those owners or replaces their result.
    pub(super) fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        if let Err(error) = &result {
            self.0.reporter.message(
                Level::ERROR,
                "core-cli.program.failed",
                format_args!("gnunet-core: {error}"),
            );
        }
        let result = service::retain_diagnostic(result, self.0.reporter.take_error());
        let cleanup = std::mem::take(&mut *self.0.cleanup.borrow_mut());
        let result = if cleanup.is_empty() {
            result
        } else {
            Err(Box::new(CleanupFailure {
                original: result.err(),
                cleanup,
            }) as Failure)
        };
        result.map_err(|error| Box::new(Reported(error)) as Failure)
    }
}
