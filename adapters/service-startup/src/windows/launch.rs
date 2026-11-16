//! Native supervised child creation, bootstrap and socket publication.
use super::{
    ParentRole,
    capture::{ACTIVATION, DETACH},
    parent::{ParentBootstrap, ParentFailure, ReadyReceipt},
};
use gnunet_native::{
    process::{Console, ExportedHandle, LaunchLimits, Spawn, Stdio},
    socket_activation::{ExportSection, PublishFailure},
};
use gnunet_service_runtime::{
    pipe::PipeListener,
    process::{ChildRegistry, OriginalChild, RegistryError},
};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt, io,
    os::windows::io::{AsHandle, BorrowedSocket},
    path::Path,
    task::{Context, Poll},
};

/// Explicit process inputs. This port changes neither process-global environment
/// nor working directory and never invokes a shell or searches PATH.
pub struct Command<'a> {
    /// Absolute native executable path.
    pub executable: &'a Path,
    /// Literal argv0, independent of the executable path.
    pub argv0: &'a OsStr,
    /// Literal arguments after argv0, preserving native UTF-16 units.
    pub arguments: &'a [OsString],
    /// Owned child environment; generated bootstrap hints override inherited ones
    /// using native case-insensitive name ordering, without global mutation.
    pub environment: Vec<(OsString, OsString)>,
    /// Absolute child working directory.
    pub directory: &'a Path,
    /// Explicit stdin, stdout and stderr selections.
    pub stdio: [Stdio<'a>; 3],
    /// Actual console relationship selected at process creation.
    pub console: Console,
    /// Supervisor or one-shot launcher declaration, independent of console state.
    pub role: ParentRole,
    /// Original overlapped stream listeners in import order, never attached to
    /// IOCP or event-selection registration. Exclude concurrent I/O, option and
    /// registration changes during publication. Keep these sources alive until
    /// actual qualified readiness, or explicitly retire the child on failure or
    /// abandonment. Publication does not transfer pathname cleanup ownership.
    pub listeners: &'a [BorrowedSocket<'a>],
}
/// Native launch failure, retaining original diagnostics and provider reservations.
#[derive(Debug)]
pub enum LaunchCause {
    /// Native preparation error before child creation.
    Prepare(io::Error),
    /// Native child creation, registration, resume or registry error.
    Registry(RegistryError),
    /// Provider publication failure with the original export count and error.
    Activation(Box<PublishFailure>),
}
impl fmt::Display for LaunchCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare(error) => error.fmt(f),
            Self::Registry(error) => error.fmt(f),
            Self::Activation(error) => error.fmt(f),
        }
    }
}
impl Error for LaunchCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Prepare(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::Activation(error) => Some(error.as_ref()),
        }
    }
}
/// A failed launch may have admitted an original child. Its owner remains in the
/// caller's registry for explicit termination and consuming reap. Retain source
/// listeners and this failure through that retirement; Drop never kills/waits.
#[derive(Debug)]
pub struct LaunchFailure {
    /// Original preparation, publication or admission error.
    pub cause: LaunchCause,
    /// Exact original child when creation had already succeeded.
    pub child: Option<OriginalChild>,
    /// Independent failure to revoke start permission after setup failed.
    pub revocation: Option<RegistryError>,
}
impl fmt::Display for LaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "child launch: {}", self.cause)?;
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
/// One original child's bootstrap. Creation does not imply exec or readiness.
/// Drop closes local channel/wait owners only; the registry retains the process.
pub struct Parent {
    bootstrap: ParentBootstrap,
}
impl Parent {
    /// Exact registry-branded child created by this launch.
    pub fn child(&self) -> &OriginalChild {
        self.bootstrap.child()
    }
    /// Drive original peer qualification on the caller's reactor without a task.
    /// Cancellation retains the endpoint, process pin and exit observation.
    pub fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ParentFailure>> {
        self.bootstrap.poll_connect(cx)
    }
    /// Readiness poll that first drives original connection qualification.
    /// Native child creation, pipe connection and actual '.' remain distinct.
    pub fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReadyReceipt, ParentFailure>> {
        match self.poll_connect(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => self.bootstrap.poll_status(cx),
        }
    }
    /// Await actual qualified readiness, preserving all progress on cancellation.
    pub async fn wait(&mut self) -> Result<ReadyReceipt, ParentFailure> {
        std::future::poll_fn(|cx| self.poll_ready(cx)).await
    }
    /// Transfer the unique qualified control outbox once. Not a readiness receipt.
    pub fn take_control(&mut self) -> Option<super::ControlSender> {
        self.bootstrap.take_control()
    }
}
struct PreparedExport {
    section: ExportSection,
    // Reserve error-owner backing before admitting a suspended child. Filling
    // the cold error variant after native publication needs no extra allocation.
    failure: Box<std::mem::MaybeUninit<PublishFailure>>,
}
/// Create under an entered I/O-enabled runtime. Reserve bootstrap and transfer
/// backing before admitting a process. Nonempty listeners require suspended
/// creation, provider publication and one resume. Any failure after creation
/// retains the original child for explicit cleanup, never a no-child refusal.
pub fn launch(
    registry: &mut ChildRegistry,
    mut command: Command<'_>,
    limits: LaunchLimits,
) -> Result<Parent, LaunchFailure> {
    let prepare = |error| LaunchFailure {
        cause: LaunchCause::Prepare(error),
        child: None,
        revocation: None,
    };
    let sockets = command.listeners;
    let section = if sockets.is_empty() {
        None
    } else {
        Some(PreparedExport {
            section: ExportSection::new(sockets.len()).map_err(prepare)?,
            failure: Box::new_uninit(),
        })
    };
    // Five explicit private hints plus one generated section-handle hint when
    // active. Native environment encoding makes generated exports win by name.
    let additions = 5 + usize::from(section.is_some());
    if command
        .environment
        .len()
        .checked_add(additions)
        .is_none_or(|count| count > limits.environment_entries)
    {
        return Err(prepare(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child bootstrap environment entry capacity",
        )));
    }
    command
        .environment
        .try_reserve_exact(5)
        .map_err(|_| prepare(io::ErrorKind::OutOfMemory.into()))?;
    let listener = PipeListener::bind().map_err(prepare)?;
    let endpoint = listener.endpoint().as_os_str();
    command
        .environment
        .push(("GNUNET_OS_CONTROL_PIPE".into(), endpoint.into()));
    let detach = match command.role {
        ParentRole::Supervisor => OsString::new(),
        ParentRole::DetachLauncher => endpoint.into(),
    };
    command.environment.push((DETACH.into(), detach));
    command
        .environment
        .push(("LISTEN_FDS".into(), OsString::new()));
    command
        .environment
        .push(("LISTEN_FDNAMES".into(), OsString::new()));
    command
        .environment
        .push((ACTIVATION.into(), OsString::new()));
    let export = section.as_ref().map(|section| ExportedHandle {
        handle: section.section.as_handle(),
        environment_key: OsStr::new(ACTIVATION),
    });
    let spawn = Spawn {
        executable: command.executable,
        argv0: command.argv0,
        arguments: command.arguments,
        environment: &command.environment,
        directory: command.directory,
        stdio: command.stdio,
        exported_handles: export.as_slice(),
        console: command.console,
    };
    let suspended = section.is_some();
    let child = if suspended {
        registry.spawn_suspended(spawn, limits)
    } else {
        registry.spawn(spawn, limits)
    }
    .map_err(|error| LaunchFailure {
        cause: LaunchCause::Registry(error),
        child: None,
        revocation: None,
    })?;
    let bootstrap = ParentBootstrap::new(listener, registry, &child).map_err(|error| {
        if suspended {
            failed_preparation(registry, &child, LaunchCause::Registry(error))
        } else {
            LaunchFailure {
                cause: LaunchCause::Registry(error),
                child: Some(child.clone()),
                revocation: None,
            }
        }
    })?;
    if let Some(PreparedExport { section, failure }) = section {
        let publication = match registry.original(&child) {
            Ok(original) => section
                .publish(original, sockets)
                .map_err(|error| LaunchCause::Activation(Box::write(failure, error))),
            Err(error) => Err(LaunchCause::Registry(error)),
        };
        publication.map_err(|cause| failed_preparation(registry, &child, cause))?;
        registry.resume(&child).map_err(|error| LaunchFailure {
            cause: LaunchCause::Registry(error),
            child: Some(child.clone()),
            revocation: None,
        })?;
    }
    Ok(Parent { bootstrap })
}
fn failed_preparation(
    registry: &mut ChildRegistry,
    child: &OriginalChild,
    cause: LaunchCause,
) -> LaunchFailure {
    LaunchFailure {
        cause,
        child: Some(child.clone()),
        revocation: registry.cancel_preparation(child).err(),
    }
}
