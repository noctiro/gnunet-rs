//! Detached re-exec policy over the shared original-child launch port.
pub use super::super::launch::LaunchCause;
use super::super::parent::{ParentFailure, ReadyReceipt};
use gnunet_native::process::{Console, LaunchLimits, Stdio};
use gnunet_service_runtime::{
    Activation,
    process::{ChildRegistry, OriginalChild, RegistryError},
};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt, io,
    path::Path,
};
/// Explicit immutable image/argument/working-directory inputs and a uniquely
/// owned child environment. No shell, PATH lookup or process-global mutation.
pub struct Reexec<'a> {
    /// Absolute executable image to create.
    pub executable: &'a Path,
    /// Literal argv0, independent of the image path.
    pub argv0: &'a OsStr,
    /// Original arguments after argv0, including the daemon option.
    pub arguments: &'a [OsString],
    /// Owned explicit environment, extended only for this private child.
    pub environment: Vec<(OsString, OsString)>,
    /// Absolute working directory retained by the child.
    pub directory: &'a Path,
    /// Explicit stderr source. Files/pipes are retained by original handle;
    /// character devices become NUL and absent stderr stays closed. stdin/stdout
    /// always use NUL, so an inherited console handle cannot break detachment.
    pub stderr: Stdio<'a>,
    /// Owned unregistered original listeners. Source use must be quiescent and
    /// creator path leases must outlive the receiving child. Never rebinds.
    pub activation: Activation,
}
/// Launch failure retaining any already admitted original child. That child's
/// process owner remains in the caller's registry for explicit cleanup/drain.
/// Retains source listeners until this failure is dropped; retire any admitted
/// original child before dropping it. Drop never kills or waits for that child.
#[derive(Debug)]
pub struct LaunchFailure {
    /// Original preparation/admission/registration failure.
    pub cause: LaunchCause,
    /// Admitted original child, if native creation already succeeded.
    pub child: Option<OriginalChild>,
    /// Independent refusal to revoke start permission after setup failed.
    /// The original child still requires explicit termination and reaping.
    pub revocation: Option<RegistryError>,
    // Keep source descriptors through explicit failed-child retirement. Dropping
    // this failure abandons those copies; it never retires the child itself.
    _sources: Activation,
}
impl fmt::Display for LaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "detached launch: {}", self.cause)?;
        if let Some(error) = &self.revocation {
            write!(f, "; independent start revocation failure: {error}")?;
        }
        Ok(())
    }
}
impl Error for LaunchFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}
/// One detached child's original startup owner. Drop releases local bootstrap
/// resources only. The caller retains its registry and never implicitly kills,
/// waits for, or reaps a live daemon by dropping this value. Before readiness,
/// dropping this owner abandons source listener copies too: explicitly retire
/// the original child first if startup will not be continued.
pub struct Parent {
    bootstrap: super::super::launch::Parent,
    sources: Activation,
}
impl Parent {
    /// Exact registry-branded child created by this launch.
    pub fn child(&self) -> &OriginalChild {
        self.bootstrap.child()
    }
    /// Transfer the original control outbox once after connection qualification.
    /// The bootstrap keeps its read/exit owners; this does not report readiness.
    pub fn take_control(&mut self) -> Option<super::super::ControlSender> {
        self.bootstrap.take_control()
    }
    /// Await actual '.' from the qualified original child. Pre-connect child
    /// exit, EOF, I/S and native failures are failures, never synthetic readiness.
    /// Cancellation retains the original pipe, identity, wait, read and source
    /// listener owners. Actual readiness releases source copies after import.
    pub async fn wait(&mut self) -> Result<ReadyReceipt, ParentFailure> {
        let receipt = self.bootstrap.wait().await?;
        drop(std::mem::take(&mut self.sources));
        Ok(receipt)
    }
}
/// Create one detached re-exec using the shared original-child launch port.
/// Source listeners remain owned until actual qualified readiness, or in the
/// failure until explicit original-child retirement. No destructor kills/waits.
pub fn launch(
    registry: &mut ChildRegistry,
    command: Reexec<'_>,
    limits: LaunchLimits,
) -> Result<Parent, LaunchFailure> {
    let mut sockets = Vec::new();
    let prepared = sockets
        .try_reserve_exact(command.activation.len())
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))
        .and_then(|()| gnunet_native::stdio::PreparedStderr::new(command.stderr));
    let stderr = match prepared {
        Ok(stderr) => stderr,
        Err(error) => {
            return Err(LaunchFailure {
                cause: LaunchCause::Prepare(error),
                child: None,
                revocation: None,
                _sources: command.activation,
            });
        }
    };
    sockets.extend(
        command
            .activation
            .sockets()
            .iter()
            .map(|socket| socket.as_socket()),
    );
    let launched = super::super::launch::launch(
        registry,
        super::super::launch::Command {
            executable: command.executable,
            argv0: command.argv0,
            arguments: command.arguments,
            environment: command.environment,
            directory: command.directory,
            stdio: [Stdio::Null, Stdio::Null, stderr.stdio()],
            console: Console::Detached,
            role: super::super::ParentRole::DetachLauncher,
            listeners: &sockets,
        },
        limits,
    );
    match launched {
        Ok(bootstrap) => Ok(Parent {
            bootstrap,
            sources: command.activation,
        }),
        Err(failure) => Err(LaunchFailure {
            cause: failure.cause,
            child: failure.child,
            revocation: failure.revocation,
            _sources: command.activation,
        }),
    }
}
