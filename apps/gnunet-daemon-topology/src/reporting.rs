//! Explicit PROGRAM-selected logger and independently retained output failure.
use crate::Failure;
use gnunet_program_host::{
    logging::Logger, reporting::Reporter, service, shared_clock::SharedClock,
};
use std::{cell::RefCell, fmt, rc::Rc, task::Context};
struct Inner {
    reporter: Reporter,
    cleanup: RefCell<CleanupErrors>,
}
#[derive(Debug, Default)]
struct CleanupErrors {
    runtime: Option<Failure>,
    deferred_runtime: Option<Failure>,
    statistics: Option<Failure>,
    resolver: Option<Failure>,
    observed: [Option<ProviderCleanup>; 6],
    observed_overflow: usize,
}
impl CleanupErrors {
    fn is_empty(&self) -> bool {
        self.runtime.is_none()
            && self.deferred_runtime.is_none()
            && self.statistics.is_none()
            && self.resolver.is_none()
            && self.observed.iter().all(Option::is_none)
            && self.observed_overflow == 0
    }
}
#[derive(Debug)]
struct ProviderCleanup {
    owner: &'static str,
    error: gnunet_topology_host::Error,
}
impl fmt::Display for ProviderCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.owner, self.error)
    }
}
impl std::error::Error for ProviderCleanup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
#[derive(Clone, Copy)]
pub(super) enum Cleanup {
    Runtime,
    DeferredRuntime,
    Statistics,
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
            "TOPOLOGY original={:?}; independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.runtime.as_deref())
            .or(self.cleanup.deferred_runtime.as_deref())
            .or(self.cleanup.statistics.as_deref())
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
        self.0.reporter.failed()
    }
    pub(super) fn warning(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.0.reporter.warning(site, args);
    }
    pub(super) fn debug(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.0.reporter.debug(site, args);
    }
    /// Clock-free Drop cleanup keeps one actual cause per original native owner;
    /// recording it does not pretend that close/join succeeded.
    pub(super) fn cleanup(&self, owner: Cleanup, error: Failure) {
        self.warning(
            "topology.drop.cleanup",
            format_args!("topology original cleanup: {error}"),
        );
        let mut retained = self.0.cleanup.borrow_mut();
        let slot = match owner {
            Cleanup::Runtime => &mut retained.runtime,
            Cleanup::DeferredRuntime => &mut retained.deferred_runtime,
            Cleanup::Statistics => &mut retained.statistics,
            Cleanup::Resolver => &mut retained.resolver,
        };
        if slot.is_none() {
            *slot = Some(error);
        }
    }
    /// A failed rotation emits at most three secondary causes before terminating;
    /// the ensuing close can emit one more. PEERSTORE's independent monitor can
    /// contribute one at each stage. Keep all six independently of the returned
    /// runtime error and the Logger, including when logging has failed.
    pub(super) fn provider_cleanup(&self, owner: &'static str, error: gnunet_topology_host::Error) {
        self.warning(
            "topology.provider.cleanup",
            format_args!("topology original {owner}: {error}"),
        );
        let mut retained = self.0.cleanup.borrow_mut();
        if let Some(slot) = retained.observed.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(ProviderCleanup { owner, error });
        } else {
            // Defensive accounting if a future provider adds more observations.
            retained.observed_overflow = retained.observed_overflow.saturating_add(1);
        }
    }
    /// A failed diagnostic remains independent of the original business result.
    pub(super) fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        let result = service::retain_diagnostic(result, self.0.reporter.take_error());
        let cleanup = std::mem::take(&mut *self.0.cleanup.borrow_mut());
        if cleanup.is_empty() {
            result
        } else {
            Err(Box::new(Failed {
                original: result.err(),
                cleanup,
            }))
        }
    }
}
