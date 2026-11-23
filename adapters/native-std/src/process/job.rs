//! Original Windows watchdog process and private job ownership.
use super::{LaunchLimits, Process, ProcessWait, ResumeFailure, Spawn, SuspendedProcess};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    task::{Context, Poll},
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};

struct Job(OwnedHandle);
impl Job {
    #[expect(
        unsafe_code,
        reason = "CreateJobObjectW allocates one unnamed noninheritable job handle"
    )]
    fn new() -> io::Result<Self> {
        // SAFETY: null inputs create an unnamed noninheritable object.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: success transfers the original job handle to this sole owner.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        job.set_limits(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)?;
        Ok(job)
    }

    #[expect(
        unsafe_code,
        reason = "SetInformationJobObject copies initialized exact native limit storage"
    )]
    fn set_limits(&self, flags: u32) -> io::Result<()> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = flags;
        // SAFETY: original job and initialized native data remain valid through the call.
        if unsafe {
            SetInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "AssignProcessToJobObject borrows only the original job and suspended process handles"
    )]
    fn assign(&self, child: &SuspendedProcess) -> io::Result<()> {
        // SAFETY: handles remain owned and the original primary thread is suspended.
        if unsafe {
            AssignProcessToJobObject(
                self.0.as_raw_handle(),
                child.process().0.handle.as_raw_handle(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "TerminateJobObject acts only on this private original job handle"
    )]
    fn terminate(&self, code: u32) -> io::Result<()> {
        // SAFETY: the uniquely owned job handle stays live through this request.
        if unsafe { TerminateJobObject(self.0.as_raw_handle(), code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Failed watchdog setup, with optional retirement of an actual original child.
pub struct JobStartError {
    /// Original native preparation or startup error.
    pub error: io::Error,
    /// Suspended child ownership after failed setup. The original must not be resumed.
    pub retirement: Option<JobRetirement>,
}
impl From<io::Error> for JobStartError {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            retirement: None,
        }
    }
}

/// Original failed startup. Drop requests direct termination if exit is still unconfirmed.
pub struct JobRetirement {
    child: SuspendedProcess,
    _job: Job,
    exited: bool,
}
impl JobRetirement {
    fn failed(child: SuspendedProcess, job: Job, error: io::Error) -> JobStartError {
        JobStartError {
            error,
            retirement: Some(Self {
                child,
                _job: job,
                exited: false,
            }),
        }
    }

    /// Observe the exact original exit, or request its termination once.
    pub fn request_stop(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_none() {
            self.child.process().terminate(255)?;
        }
        Ok(())
    }

    /// Observe only the original child, avoiding a PID lookup or replacement.
    pub fn try_wait(&mut self) -> io::Result<Option<u32>> {
        let exit = self.child.process().try_wait()?;
        self.exited = exit.is_some();
        Ok(exit)
    }
}
impl Drop for JobRetirement {
    fn drop(&mut self) {
        if !self.exited {
            let _termination = self.child.process().terminate(255);
        }
    }
}

/// Original watchdog child with a private kill-on-close Windows job.
pub struct JobProcess {
    job: Job,
    wait: ProcessWait,
    child: Process,
}
impl JobProcess {
    /// Reserve the job, create the original child suspended, assign it, then resume once.
    /// Assignment, wait setup or resume failure retains exact failed-child ownership.
    pub fn launch(command: Spawn<'_>, limits: LaunchLimits) -> Result<Self, JobStartError> {
        let job = Job::new()?;
        let suspended = command.suspend(limits)?;
        if let Err(error) = job.assign(&suspended) {
            return Err(JobRetirement::failed(suspended, job, error));
        }
        let wait = match ProcessWait::new(suspended.process()) {
            Ok(wait) => wait,
            Err(error) => return Err(JobRetirement::failed(suspended, job, error)),
        };
        match suspended.resume() {
            Ok(child) => Ok(Self { job, wait, child }),
            Err(ResumeFailure { original, error }) => {
                Err(JobRetirement::failed(original, job, error))
            }
        }
    }

    /// Poll actual exit of this original child. Timeout never fabricates a child status.
    pub fn poll_exit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
        self.wait.poll_exit(cx)
    }

    /// Request termination of all members of the original private job.
    pub fn terminate(&self, code: u32) -> io::Result<()> {
        self.job.terminate(code)
    }

    /// Release watchdog ownership after physical exit, preserving existing descendants.
    pub fn release_after_exit(self) -> io::Result<()> {
        if self.child.try_wait()?.is_none() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.job.set_limits(0)
    }
}
