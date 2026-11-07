//! Standalone standard ARM SERVICE. Early foreign descriptor capture and fork
//! remain with the fresh-process app; every later owner and cleanup is explicit.
use gnunet_program_host::{
    logging::Logger, policy::Level, service as lifecycle, shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, BoundListeners, process::ChildRegistry};
use gnunet_service_startup::{
    ControlNotice, GroupsProfile, ParentControl, RebindHold, apply_privileges, configured_user,
    daemon::ChildReady, resolve_user,
};
use std::{error::Error, fmt};
mod control;
mod foreground;
mod reporting;
mod settings;
mod usage;
/// Actual startup/driver/IO failure; secret configuration values are not printed.
pub type Failure = Box<dyn Error>;
/// Explicit original owners captured/selected by the fresh main process.
pub struct Startup<'a, 'log> {
    /// Actual standard SERVICE selection (not PROGRAM/GNUNET_ARGS).
    pub selected: &'a lifecycle::Selected,
    /// ARM-self CLOSE_LSOCKS route; never adopted as service listener sockets.
    pub inherited: RebindHold,
    /// Original optional parent-to-child signal control descriptor.
    pub parent: Option<ParentControl>,
    /// Actual ignored malformed original control declaration.
    pub notice: Option<ControlNotice>,
    /// The same process clock used by logger, native reactor and timer wakeups.
    pub clock: &'a SharedClock,
    /// Explicit selected log destination/policy, no global fd2 replacement.
    pub logger: &'a mut Logger<'log>,
    /// Only real full ARM initialization may signal this daemon parent.
    pub ready: &'a mut ChildReady,
}
#[derive(Debug)]
pub(super) struct Failures {
    pub(super) original: Option<Failure>,
    pub(super) cleanup: Vec<Failure>,
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ARM original={:?}; independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref()
    }
}
/// Actual remaining native child debt. Never called successful ARM shutdown.
/// The original registry survives in this error so an embedding caller can
/// explicitly continue original-PID consuming waits without a reconstructed PID.
pub struct Unreaped {
    registry: ChildRegistry,
    original: Option<Failure>,
    cleanup: Vec<Failure>,
}
impl Unreaped {
    pub(super) fn new(
        registry: ChildRegistry,
        original: Option<Failure>,
        cleanup: Vec<Failure>,
    ) -> Self {
        Self {
            registry,
            original,
            cleanup,
        }
    }
    /// Actual owned original children still awaiting a consuming native wait.
    pub fn registry(&mut self) -> &mut ChildRegistry {
        &mut self.registry
    }
    /// Transfer that same registry; a new one would not own these children.
    pub fn into_registry(self) -> ChildRegistry {
        self.registry
    }
}
impl fmt::Debug for Unreaped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnreapedArmChildren")
            .field("pending", &self.registry.pending_children())
            .field("original", &self.original)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}
impl fmt::Display for Unreaped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ARM shutdown retains {} actual unreaped children; original={:?}; cleanup={:?}",
            self.registry.pending_children(),
            self.original,
            self.cleanup
        )
    }
}
impl Error for Unreaped {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref()
    }
}
/// Run the actual standard service in a fresh single-threaded service child.
/// Call only after the app's once-only early capture/daemon split. This function
/// changes configured process credentials and owns a current-thread runtime;
/// it must not be nested inside an existing runtime or concurrent application.
/// No child, listener, clock, signal or readiness result is fabricated.
pub fn run(input: Startup<'_, '_>) -> Result<(), Failure> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err("ARM SERVICE must start before an existing runtime".into());
    }
    let Startup {
        selected,
        inherited,
        parent,
        notice,
        clock,
        logger,
        ready,
    } = input;
    let reports = reporting::Reports::new(logger, clock);
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            reports.warning(
                "arm.parent",
                format_args!("ARM original parent-control declaration: {notice:?}"),
            );
            reports.startup_check()?
        }
        let config = settings::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        let user = configured_user(&config, b"arm")?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let prepared = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, b"arm", Activation::default())?
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "arm.identity",
                format_args!("ARM actual configured process identity: {privileges:?}"),
            );
            reports.startup_check()?
        }
        // Unix is created under the actual target account, avoiding root-owned0700
        // sockets unusable after USER. CLOSE_LSOCKS EOF is only an early-bind fact,
        // never a replacement for the separate daemon parent's ready byte.
        let bound = runtime.block_on(prepared.finish())?;
        for error in bound.failures() {
            reports.warning(
                "arm.listener.alternate",
                format_args!("ARM actual alternate control listener: {error}"),
            )
        }
        let release = inherited.complete_after_bind(&bound);
        reports.message(Level::DEBUG,"arm.inherited.released",format_args!("ARM original inherited close-set released: {release:?}; application readiness not claimed"));
        reports.startup_check()?;
        runtime.block_on(foreground::run(foreground::Inputs {
            bound,
            parent,
            settings: &settings,
            config: &config,
            clock,
            reports: &reports,
            ready,
        }))
    })();
    lifecycle::retain_diagnostic(result, reports.take_failure())
}
