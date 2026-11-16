//! Explicit single file worker. It receives only bounded zeroizing INI bytes.
use super::target::Target;
use gnunet_types::Error;
use std::{
    io,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, SyncSender},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
};
use tokio::sync::mpsc as async_mpsc;
use zeroize::Zeroizing;
/// Actual point reached by a failed original file job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exposure {
    /// No rename was attempted; the canonical target was not published by this job.
    NotPublished,
    /// Rename was attempted or succeeded, but full completion is unproven.
    Unknown,
}
/// Actual original error family from the shared writer or directory boundary.
#[derive(Debug)]
pub enum Cause {
    /// Exact shared anchored publication and its independent cleanup facts.
    Publication(gnunet_native::filesystem::publication::Failure),
    /// Exact independent native metadata/sync error.
    Io(io::Error),
    /// Exact original runtime clock fault before publication.
    Clock(gnunet_types::Error),
}
/// What the shared source exposed about its own temporary cleanup.
#[derive(Debug)]
pub enum Cleanup {
    /// The shared publication retained its actual cleanup result in Cause.
    Reported,
    /// Successful publication already retired its original staged link.
    Retired,
    /// No shared write/temporary operation was started.
    NotNeeded,
}
/// Original write/close/rename/sync cause and independent temporary cleanup.
#[derive(Debug)]
pub struct Failure {
    /// Actual stage, with no file contents or private diagnostic operands.
    pub stage: &'static str,
    /// Original native I/O error.
    pub cause: Cause,
    /// Original publication uncertainty.
    pub exposure: Exposure,
    /// Independent cleanup error, retained without hiding the primary cause.
    pub cleanup: Cleanup,
}
/// Exact private worker admission token. No public success constructor exists.
#[derive(Clone, Debug)]
pub struct Job {
    domain: Arc<()>,
    serial: u64,
    pub(super) until: u64,
    pub(super) hard: tokio::time::Instant,
}
impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Job {}
impl Job {
    /// Diagnostic allocation only, never completion authority.
    pub const fn serial(&self) -> u64 {
        self.serial
    }
    /// Original canonical request bound, retained even after callback loss.
    pub const fn until(&self) -> u64 {
        self.until
    }
    /// Original finite native request bound; this job never renews it.
    pub const fn hard(&self) -> tokio::time::Instant {
        self.hard
    }
}
/// Actual successful file-sync, writer-close and name-publication receipt.
#[derive(Debug)]
pub struct Committed {
    pub(super) job: Job,
    pub(super) generation: u64,
    pub(super) directory_sync: gnunet_native::DirectorySync,
}
impl Committed {
    /// Original worker admission.
    pub fn job(&self) -> &Job {
        &self.job
    }
    /// Actual native directory barrier, independently of successful file publication.
    pub const fn directory_sync(&self) -> gnunet_native::DirectorySync {
        self.directory_sync
    }
    /// Exact new committed generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
/// Original completion, even when its HTTP callback was dropped.
pub struct Completion {
    pub(super) job: Job,
    pub(super) result: Result<(Committed, gnunet_config::Configuration), Arc<Failure>>,
}
impl Completion {
    /// Original actual admitted job, never a replacement generation.
    pub fn job(&self) -> &Job {
        &self.job
    }
    /// Move the actual receipt/planned config or original failure. No write,
    /// reload, synthetic success or new admission occurs when observing this.
    pub fn into_parts(
        self,
    ) -> (
        Job,
        Result<(Committed, gnunet_config::Configuration), Arc<Failure>>,
    ) {
        (self.job, self.result)
    }
}
/// Only joining the original native thread creates this report.
#[derive(Debug)]
pub struct Stopped {
    /// Number of actually completed commands.
    pub completed: u64,
    /// Last completely committed generation.
    pub generation: u64,
    /// Original uncertainty that latched this writer, if any.
    pub failure: Option<Arc<Failure>>,
}
struct Command {
    job: Job,
    expected: u64,
    body: Zeroizing<Vec<u8>>,
    configuration: gnunet_config::Configuration,
}
/// Refused admission retains the exact original configuration and serialized body.
pub struct Refusal {
    /// Local admission failure; no write was admitted.
    pub reason: Error,
    /// Original serialized update, erased when dropped.
    pub body: Zeroizing<Vec<u8>>,
    /// Original configuration corresponding to that update.
    pub configuration: gnunet_config::Configuration,
}
/// One explicit storage thread, one admitted body and one completion. The target
/// is caller-owned configuration output, never discovered from a key store.
pub struct Worker {
    domain: Arc<()>,
    sender: Option<SyncSender<Command>>,
    receiver: async_mpsc::Receiver<Completion>,
    thread: Option<JoinHandle<Stopped>>,
    next: u64,
    inflight: bool,
    max_bytes: usize,
    join_alarm: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}
impl Worker {
    /// Claim an explicit owned configuration target/parent and start its sole writer.
    /// This is a native effect; callers invoke it only after applying privileges.
    pub fn start(
        path: PathBuf,
        max_bytes: usize,
        clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    ) -> io::Result<Self> {
        if max_bytes == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut target = Target::open(path)?;
        let (sender, commands) = mpsc::sync_channel::<Command>(1);
        let (results, receiver) = async_mpsc::channel(1);
        let domain = Arc::new(());
        let thread = thread::Builder::new()
            .name("gnunet-rest-config".into())
            .spawn(move || {
                let mut completed = 0u64;
                while let Ok(command) = commands.recv() {
                    let mut configuration = command.configuration;
                    let result = target
                        .commit(
                            command.job.clone(),
                            command.expected,
                            &command.body,
                            &mut configuration,
                            clock.as_ref(),
                        )
                        .map(|committed| (committed, configuration));
                    completed = completed.saturating_add(1);
                    if results
                        .blocking_send(Completion {
                            job: command.job,
                            result,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Stopped {
                    completed,
                    generation: target.generation,
                    failure: target.blocked,
                }
            })?;
        Ok(Self {
            domain,
            sender: Some(sender),
            receiver,
            thread: Some(thread),
            next: 1,
            inflight: false,
            max_bytes,
            join_alarm: None,
        })
    }
    /// Actual immutable single-job admission. Refusal returns the original body.
    pub fn submit(
        &mut self,
        expected: u64,
        body: Zeroizing<Vec<u8>>,
        configuration: gnunet_config::Configuration,
        until: u64,
        hard: tokio::time::Instant,
    ) -> Result<Job, Box<Refusal>> {
        let refuse = |reason, (body, configuration)| {
            Box::new(Refusal {
                reason,
                body,
                configuration,
            })
        };
        if body.len() > self.max_bytes {
            return Err(refuse(Error::Capacity, (body, configuration)));
        }
        if self.inflight {
            return Err(refuse(Error::WouldBlock, (body, configuration)));
        }
        let Some(next) = self.next.checked_add(1) else {
            return Err(refuse(Error::Overflow, (body, configuration)));
        };
        let Some(sender) = &self.sender else {
            return Err(refuse(Error::Closed, (body, configuration)));
        };
        let job = Job {
            domain: self.domain.clone(),
            serial: self.next,
            until,
            hard,
        };
        let command = Command {
            job: job.clone(),
            expected,
            body,
            configuration,
        };
        if let Err(error) = sender.try_send(command) {
            let (reason, command) = match error {
                mpsc::TrySendError::Full(command) => (Error::WouldBlock, command),
                mpsc::TrySendError::Disconnected(command) => (Error::Closed, command),
            };
            return Err(refuse(reason, (command.body, command.configuration)));
        }
        self.next = next;
        self.inflight = true;
        Ok(job)
    }
    /// Poll the sole actual completion channel; no successful receipt is fabricated.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<Completion>> {
        let result = self.receiver.poll_recv(cx);
        if result.is_ready() {
            self.inflight = false;
        }
        result
    }
    /// Stop admission, while retaining the original admitted command/result.
    pub fn request_stop(&mut self) {
        self.sender = None;
    }
    /// Drain results before joining. Pending native syscalls cannot be falsely
    /// canceled: this polls actual thread completion, retaining the original owner.
    pub fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<Result<Stopped, Error>> {
        self.request_stop();
        if self.inflight {
            return Poll::Ready(Err(Error::WouldBlock));
        }
        let Some(thread) = self.thread.as_ref() else {
            return Poll::Ready(Err(Error::Closed));
        };
        if !thread.is_finished() {
            use std::future::Future;
            let timer = self.join_alarm.get_or_insert_with(|| {
                Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1)))
            });
            if timer.as_mut().poll(cx).is_ready() {
                self.join_alarm = None;
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        self.join_alarm = None;
        let Some(thread) = self.thread.take() else {
            return Poll::Ready(Err(Error::Closed));
        };
        Poll::Ready(thread.join().map_err(|_| Error::NotReady))
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.request_stop();
        // Closing the receiver releases a blocked native result sender. Never
        // call blocking_recv inside the foreground Tokio runtime during Drop.
        self.receiver.close();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}
