//! One selected PROGRAM Logger; diagnostic and cleanup failures stay independent.
use crate::Failure;
use gnunet_program_host::{
    logging::Logger, policy::Level, reporting::Reporter, service, shared_clock::SharedClock,
};
use std::{cell::RefCell, fmt, rc::Rc, task::Context};
struct Inner {
    reporter: Reporter,
    cleanup: RefCell<CleanupErrors>,
}
#[derive(Debug, Default)]
struct CleanupErrors {
    runtime: Option<Failure>,
    resolver: Option<Failure>,
    observed: [Option<ProviderCleanup>; 8],
    observed_overflow: usize,
}
impl CleanupErrors {
    fn is_empty(&self) -> bool {
        self.runtime.is_none()
            && self.resolver.is_none()
            && self.observed.iter().all(Option::is_none)
            && self.observed_overflow == 0
    }
}
#[derive(Debug)]
struct ProviderCleanup {
    owner: &'static str,
    error: Failure,
}
impl fmt::Display for ProviderCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.owner, self.error)
    }
}
impl std::error::Error for ProviderCleanup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}
#[derive(Clone, Copy)]
pub(super) enum Cleanup {
    Runtime,
    Resolver,
}
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    cleanup: CleanupErrors,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HOSTLIST original={:?}; independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.runtime.as_deref())
            .or(self.cleanup.resolver.as_deref())
            .or_else(|| {
                self.cleanup
                    .observed
                    .iter()
                    .flatten()
                    .next()
                    .map(|error| error as &dyn std::error::Error)
            })
    }
}
/// A private app marker: the selected/default owned Logger has handled this
/// result. Keep the entire original business/cleanup/diagnostic error chain.
#[derive(Debug)]
pub(super) struct SelectedFailure(Failure);
impl fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
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
    pub(super) fn register(&self, cx: &Context<'_>) {
        self.0.reporter.register(cx);
    }
    pub(super) fn failed(&self) -> bool {
        self.0.reporter.failed() || !self.0.cleanup.borrow().is_empty()
    }
    pub(super) fn warning(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.0.reporter.warning(site, args);
    }
    pub(super) fn debug(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.0.reporter.debug(site, args);
    }
    /// Drop closes the physical owners first and records the actual first cause
    /// from each owner, independently of any already failed Logger.
    pub(super) fn cleanup(&self, owner: Cleanup, error: Failure) {
        self.warning(
            "hostlist.drop.cleanup",
            format_args!("hostlist original cleanup: {error}"),
        );
        let mut retained = self.0.cleanup.borrow_mut();
        let slot = match owner {
            Cleanup::Runtime => &mut retained.runtime,
            Cleanup::Resolver => &mut retained.resolver,
        };
        if slot.is_none() {
            *slot = Some(error);
        }
    }
    /// Retain up to eight terminal HTTP/PEERSTORE/CORE secondary causes, with
    /// explicit overflow accounting rather than unbounded allocation. The first
    /// such error stops the next foreground turn; physical cleanup still runs.
    pub(super) fn provider_cleanup(&self, owner: &'static str, error: Failure) {
        self.warning(
            "hostlist.provider.cleanup",
            format_args!("hostlist original {owner}: {error}"),
        );
        let mut retained = self.0.cleanup.borrow_mut();
        if let Some(slot) = retained.observed.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(ProviderCleanup { owner, error });
        } else {
            retained.observed_overflow = retained.observed_overflow.saturating_add(1);
        }
    }
    /// A diagnostic failure never replaces the real business/cleanup cause.
    pub(super) fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        let cleanup = std::mem::take(&mut *self.0.cleanup.borrow_mut());
        if let Err(error) = &result {
            self.0.reporter.message(
                Level::ERROR,
                "hostlist.program.failed",
                format_args!("gnunet-daemon-hostlist: {error}"),
            );
        }
        if !cleanup.is_empty() {
            self.0.reporter.message(
                Level::ERROR,
                "hostlist.cleanup.failed",
                format_args!("hostlist independent cleanup: {cleanup:?}"),
            );
        }
        let result = service::retain_diagnostic(result, self.0.reporter.take_error());
        let result = if cleanup.is_empty() {
            result
        } else {
            Err(Box::new(Failed {
                original: result.err(),
                cleanup,
            }) as Failure)
        };
        result.map_err(|original| Box::new(SelectedFailure(original)) as Failure)
    }
}
