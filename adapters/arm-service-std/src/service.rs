//! Standalone ARM SERVICE composition over shared native supervision.
/// Original listener ownership accepted by native SERVICE startup.
pub use gnunet_service_runtime::Activation;
use gnunet_service_runtime::process::ChildRegistry;
use std::{error::Error, fmt, io};
mod control;
mod foreground;
mod readiness;
mod reporting;
mod settings;
#[cfg(unix)]
mod unix;
mod usage;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::{Startup, run};
#[cfg(windows)]
pub use windows::{Startup, run};
/// Actual startup, driver or I/O failure, retaining its original source.
pub type Failure = Box<dyn Error>;
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
/// explicitly continue original-process consuming waits without PID lookup.
pub struct Unreaped {
    recovery: Recovery,
    original: Option<Failure>,
    cleanup: Vec<Failure>,
}
impl Unreaped {
    pub(super) fn new(
        registry: ChildRegistry,
        controls: Vec<crate::process::RetainedChild>,
        original: Option<Failure>,
        cleanup: Vec<Failure>,
    ) -> Self {
        Self {
            recovery: Recovery { registry, controls },
            original,
            cleanup,
        }
    }
    /// Continue native cleanup without separating the original registry from
    /// its dependent publisher/control owners.
    pub fn recovery(&mut self) -> &mut Recovery {
        &mut self.recovery
    }
    /// Transfer the same registry together with auxiliary native resources.
    /// Source descriptors remain owned through explicit original-child cleanup.
    pub fn into_recovery(self) -> Recovery {
        self.recovery
    }
}
impl fmt::Debug for Unreaped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnreapedArmChildren")
            .field("pending", &self.recovery.registry.pending_children())
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
            self.recovery.registry.pending_children(),
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

/// Preserve direct recovery of the original registry when independent reporting
/// or readiness cleanup fails after the main operation returned native debt.
pub(super) fn retain_cleanup(original: Failure, cleanup: Failure) -> Failure {
    match original.downcast::<Unreaped>() {
        Ok(mut debt) => {
            debt.cleanup.push(cleanup);
            debt
        }
        Err(original) => Box::new(Failures {
            original: Some(original),
            cleanup: vec![cleanup],
        }),
    }
}
pub(super) fn retain_diagnostic(
    result: Result<(), Failure>,
    diagnostic: Option<io::Error>,
) -> Result<(), Failure> {
    let diagnostic = diagnostic.map(|error| Box::new(error) as Failure);
    match (result, diagnostic) {
        (result, None) => result,
        (Ok(()), Some(error)) => Err(error),
        (Err(original), Some(error)) => Err(retain_cleanup(original, error)),
    }
}

/// Original process authority plus dependent transfer/control owners after a
/// failed bounded shutdown. Drop closes local owners only; it never kills/waits.
pub struct Recovery {
    registry: ChildRegistry,
    controls: Vec<crate::process::RetainedChild>,
}
impl Recovery {
    /// Native children still awaiting consuming exit observation.
    pub fn pending_children(&self) -> usize {
        self.registry.pending_children()
    }
    /// Borrow original lookup capabilities; a numeric PID grants no action.
    pub fn children(&self) -> impl Iterator<Item = &crate::process::OriginalChild> {
        self.registry.children()
    }
    /// Request a direct native stop for an original child. This bypasses the
    /// abandoned service control loop and does not prove exit.
    pub fn request_stop(
        &mut self,
        child: &crate::process::OriginalChild,
    ) -> Result<(), crate::process::LaunchError> {
        crate::process::force_stop(&mut self.registry, child)
    }
    /// Force native termination of an original child, independently of reaping.
    pub fn kill(
        &mut self,
        child: &crate::process::OriginalChild,
    ) -> Result<(), crate::process::LaunchError> {
        crate::process::kill(&mut self.registry, child)
    }
    /// Consume completed originals and release only their auxiliary owners.
    /// Earlier completions remain available if a later native query fails.
    pub fn reap_completed(&mut self) -> Result<(), crate::process::LaunchError> {
        let result = crate::process::reap_completed(&mut self.registry);
        self.release_completed();
        result
    }
    /// Take one retained native exit and optional actual resource observation.
    pub fn take_completed_with_usage(
        &mut self,
    ) -> Option<(
        crate::process::Reaped,
        Option<crate::process::ResourceUsage>,
    )> {
        self.registry.take_completed_with_usage()
    }
    /// Register original exit notifications on the caller's enabled runtime.
    /// Canceling a wait retains this owner and all pending native resources.
    pub fn poll_exit(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), crate::process::LaunchError>> {
        crate::process::poll_exit(&mut self.registry, cx)
    }
    /// Release auxiliary owners only for children already consumed by this
    /// registry. This performs no native wait and infers no child exit.
    pub fn release_completed(&mut self) -> usize {
        let before = self.controls.len();
        let registry = &self.registry;
        self.controls.retain(|child| registry.owns(&child.original));
        before - self.controls.len()
    }
}
