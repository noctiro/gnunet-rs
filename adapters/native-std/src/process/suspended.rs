//! Original suspended child ownership and one explicit primary-thread resume.
use super::launch::{Created, Process};
use std::{
    error::Error,
    fmt, io,
    os::windows::io::{AsRawHandle, OwnedHandle},
};
use windows_sys::Win32::System::Threading::ResumeThread;

/// Original process and primary-thread owners returned by CREATE_SUSPENDED.
/// The thread handle is never exposed. Drop closes owners only; callers must
/// resume or explicitly terminate/drain the child, including after setup failure.
#[must_use = "a suspended child must be explicitly resumed or terminated and drained"]
pub struct SuspendedProcess {
    process: Process,
    thread: OwnedHandle,
    activation: Activation,
}

#[derive(Debug)]
enum Activation {
    Unmanaged,
    AwaitingPublication,
    Published,
}

/// Unique publication authority for an original child with pending activation.
/// While held, the child remains owned by its suspended process or registry.
pub struct ActivationTarget<'a>(&'a mut SuspendedProcess);

impl ActivationTarget<'_> {
    pub(crate) fn process(&self) -> &Process {
        &self.0.process
    }

    pub(crate) fn published(self) {
        self.0.activation = Activation::Published;
    }
}
impl fmt::Debug for SuspendedProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuspendedProcess")
            .field("process", &self.process)
            .field("activation", &self.activation)
            .finish_non_exhaustive()
    }
}
/// Failed resume preserves the original process/thread owners for handling.
/// Unexpected prior counts indicate external suspension interference; no state
/// or readiness is inferred from them, and blind repeated resume is invalid.
#[derive(Debug)]
pub struct ResumeFailure {
    /// Original native error or unexpected suspension-count refusal.
    pub error: io::Error,
    /// Original owners, including a possibly externally resumed process.
    pub original: SuspendedProcess,
}
impl fmt::Display for ResumeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl Error for ResumeFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}
impl SuspendedProcess {
    pub(super) fn from_created(created: Created) -> Self {
        Self {
            process: created.process,
            thread: created.thread,
            activation: Activation::Unmanaged,
        }
    }

    pub(super) fn for_activation(created: Created) -> Self {
        Self {
            activation: Activation::AwaitingPublication,
            ..Self::from_created(created)
        }
    }

    /// Borrow original publication authority without releasing process or
    /// primary-thread ownership.
    pub fn activation_target(&mut self) -> Option<ActivationTarget<'_>> {
        matches!(self.activation, Activation::AwaitingPublication).then_some(ActivationTarget(self))
    }
    /// Borrow original process identity/wait/termination authority during setup.
    pub fn process(&self) -> &Process {
        &self.process
    }
    /// Resume the original primary thread exactly once and release its handle.
    /// Callers exclude external thread suspension/resume/debugger interference.
    /// Success observes the expected prior count one, never image/service READY.
    #[expect(
        unsafe_code,
        reason = "ResumeThread borrows the privately owned original primary-thread handle, retaining no pointer or ownership"
    )]
    pub fn resume(self) -> Result<Process, ResumeFailure> {
        if matches!(self.activation, Activation::AwaitingPublication) {
            return Err(ResumeFailure {
                error: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "original socket activation has not been published",
                ),
                original: self,
            });
        }
        // SAFETY: original primary-thread handle is live throughout this call.
        let previous = unsafe { ResumeThread(self.thread.as_raw_handle()) };
        if previous == u32::MAX {
            return Err(ResumeFailure {
                error: io::Error::last_os_error(),
                original: self,
            });
        }
        if previous != 1 {
            return Err(ResumeFailure {
                error: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "original primary-thread suspension count was externally changed",
                ),
                original: self,
            });
        }
        Ok(self.process)
    }
}
