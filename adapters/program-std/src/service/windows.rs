//! Native service re-exec and recoverable original-child startup failures.
use gnunet_service_runtime::{
    Activation,
    process::{ChildRegistry, LaunchLimits, OriginalChild, Reaped, RegistryError, Stdio},
};
use gnunet_service_startup::{
    ParentFailure,
    daemon::{self, LaunchFailure, Parent, Reexec, RetirementFailure},
};
use std::{error::Error, fmt, io, sync::Mutex};

/// Original input, admission or startup failure; cleanup never replaces it.
#[derive(Debug)]
pub enum DetachCause {
    /// Preparing current image, arguments or working directory failed.
    Prepare(io::Error),
    /// Allocating the private original-child registry failed.
    Registry(RegistryError),
    /// Native launch/setup failed, retaining its actual source owners.
    Launch(LaunchFailure),
    /// The qualified original child did not supply successful readiness.
    Readiness(ParentFailure),
}
impl fmt::Display for DetachCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare(e) => e.fmt(f),
            Self::Registry(e) => e.fmt(f),
            Self::Launch(e) => e.fmt(f),
            Self::Readiness(e) => e.fmt(f),
        }
    }
}
impl Error for DetachCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::Prepare(e) => e,
            Self::Registry(e) => e,
            Self::Launch(e) => e,
            Self::Readiness(e) => e,
        })
    }
}
struct Recovery {
    registry: ChildRegistry,
    child: OriginalChild,
    // Retain activation/bootstrap owners until this original is physically reaped.
    _parent: Option<Parent>,
}
/// Original failure and independent cleanup outcome. Failed retirement retains
/// original registry/process/bootstrap authority for explicit retry. Drop only
/// closes local owners; it never kills or waits for a live child.
pub struct DetachFailure {
    cause: DetachCause,
    cleanup: Option<RetirementFailure>,
    reaped: Option<Reaped>,
    // Native wait registrations are Send, not Sync. Shared error inspection
    // exposes no registrations; exclusive recovery uses Mutex::get_mut only.
    recovery: Option<Mutex<Recovery>>,
}
impl fmt::Debug for DetachFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetachFailure")
            .field("cause", &self.cause)
            .field("cleanup", &self.cleanup)
            .field("reaped", &self.reaped)
            .field("recovery_retained", &self.recovery.is_some())
            .finish()
    }
}
impl fmt::Display for DetachFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)?;
        if let Some(cleanup) = &self.cleanup {
            write!(f, "; independent child retirement: {cleanup}")?;
        }
        Ok(())
    }
}
impl Error for DetachFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}
impl DetachFailure {
    /// Original preparation/admission/readiness failure.
    pub fn cause(&self) -> &DetachCause {
        &self.cause
    }
    /// Latest independent native cleanup failure, if retirement remains unsettled.
    pub fn cleanup_error(&self) -> Option<&RetirementFailure> {
        self.cleanup.as_ref()
    }
    /// Actual consumed original-child exit receipt, if retirement completed.
    pub fn reaped(&self) -> Option<&Reaped> {
        self.reaped.as_ref()
    }
    /// Retry only the retained original child under the same explicit runtime.
    /// Call outside an asynchronous context. Failed retry preserves all original
    /// owners and the new error; successful retry records an actual exit receipt.
    pub fn retry_retirement(
        &mut self,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(), &RetirementFailure> {
        let Some(recovery) = &mut self.recovery else {
            return Ok(());
        };
        // This mutex is never locked: only an exclusive error owner can recover.
        let recovery = recovery
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match runtime.block_on(daemon::retire_child(
            &mut recovery.registry,
            &recovery.child,
            1,
        )) {
            Ok(receipt) => {
                self.reaped = Some(receipt);
                self.recovery = None;
                self.cleanup = None;
                Ok(())
            }
            Err(error) => Err(self.cleanup.insert(error)),
        }
    }
}
/// Re-exec the current image with original arguments, environment and directory,
/// awaiting actual original-child readiness. Call outside an asynchronous context
/// after fresh startup capture. Failure explicitly attempts original-child
/// termination/reaping; unsettled owners remain recoverable in the error.
pub fn detach(
    runtime: &tokio::runtime::Runtime,
    activation: Activation,
) -> Result<(), Box<DetachFailure>> {
    // Reserve error ownership before any native child can exist.
    let reserved = Box::<DetachFailure>::new_uninit();
    let prepare = || -> io::Result<_> {
        let executable = std::env::current_exe()?;
        let directory = std::env::current_dir()?;
        let mut args = std::env::args_os();
        let argv0 = args
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing original argv0"))?;
        Ok((executable, directory, argv0, args.collect::<Vec<_>>()))
    };
    let (executable, directory, argv0, arguments) = match prepare() {
        Ok(inputs) => inputs,
        Err(error) => {
            return Err(Box::write(
                reserved,
                DetachFailure {
                    cause: DetachCause::Prepare(error),
                    cleanup: None,
                    reaped: None,
                    recovery: None,
                },
            ));
        }
    };
    let mut registry = match ChildRegistry::new(1) {
        Ok(registry) => registry,
        Err(error) => {
            return Err(Box::write(
                reserved,
                DetachFailure {
                    cause: DetachCause::Registry(error),
                    cleanup: None,
                    reaped: None,
                    recovery: None,
                },
            ));
        }
    };
    let launched = {
        let _entered = runtime.enter();
        daemon::launch(
            &mut registry,
            Reexec {
                executable: &executable,
                argv0: &argv0,
                arguments: &arguments,
                environment: std::env::vars_os().collect(),
                directory: &directory,
                stderr: Stdio::Inherit,
                activation,
            },
            LaunchLimits::default(),
        )
    };
    let (cause, recovery) = match launched {
        Ok(mut parent) => match runtime.block_on(parent.wait()) {
            Ok(_) => return Ok(()),
            Err(error) => (
                DetachCause::Readiness(error),
                Some(Recovery {
                    child: parent.child().clone(),
                    registry,
                    _parent: Some(parent),
                }),
            ),
        },
        Err(error) => {
            let recovery = error.child.clone().map(|child| Recovery {
                registry,
                child,
                _parent: None,
            });
            (DetachCause::Launch(error), recovery)
        }
    };
    let mut failure = Box::write(
        reserved,
        DetachFailure {
            cause,
            cleanup: None,
            reaped: None,
            recovery: recovery.map(Mutex::new),
        },
    );
    let _outcome = failure.retry_retirement(runtime);
    Err(failure)
}
