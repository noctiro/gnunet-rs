//! Explicit single file worker. It receives only bounded zeroizing INI bytes.
use gnunet_types::Error;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
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
    /// Exact shared Configuration writer error.
    Configuration(gnunet_config::Error),
    /// Exact independent native metadata/sync error.
    Io(io::Error),
    /// Exact original runtime clock fault before publication.
    Clock(gnunet_types::Error),
}
/// What the shared source exposed about its own temporary cleanup.
#[derive(Debug)]
pub enum Cleanup {
    /// Existing atomic writer does not return a cleanup receipt.
    NotReported,
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
    until: u64,
    hard: tokio::time::Instant,
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
/// Actual successful original file and directory sync/rename receipt.
#[derive(Debug)]
pub struct Committed {
    job: Job,
    generation: u64,
}
impl Committed {
    /// Original worker admission.
    pub fn job(&self) -> &Job {
        &self.job
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
#[derive(Clone, Copy, Eq, PartialEq)]
struct Inode {
    dev: u64,
    ino: u64,
}
fn id(m: &fs::Metadata) -> Inode {
    Inode {
        dev: m.dev(),
        ino: m.ino(),
    }
}
struct Target {
    path: PathBuf,
    parent: PathBuf,
    directory: File,
    directory_id: Inode,
    lock: File,
    lock_id: Inode,
    expected: Option<Inode>,
    generation: u64,
    blocked: Option<Arc<Failure>>,
}
impl Target {
    fn open(path: PathBuf) -> io::Result<Self> {
        if !path.is_absolute()
            || path.file_name().is_none()
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let parent = path
            .parent()
            .ok_or(io::ErrorKind::InvalidInput)?
            .to_path_buf();
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&parent)?;
        let meta = directory.metadata()?;
        if meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let directory_id = id(&meta);
        let lock_path = parent.join(".gnunet-rest-configuration.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(lock_path)?;
        let meta = lock.metadata()?;
        if !meta.is_file()
            || meta.uid() != nix::unistd::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let lock_id = id(&meta);
        lock.try_lock().map_err(io::Error::other)?;
        let expected = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() && m.uid() == nix::unistd::geteuid().as_raw() => Some(id(&m)),
            Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let target = Self {
            path,
            parent,
            directory,
            directory_id,
            lock,
            lock_id,
            expected,
            generation: 0,
            blocked: None,
        };
        target.fence()?;
        Ok(target)
    }
    fn fence(&self) -> io::Result<()> {
        let p = fs::symlink_metadata(&self.parent)?;
        let l = fs::symlink_metadata(self.parent.join(".gnunet-rest-configuration.lock"))?;
        if !p.is_dir()
            || id(&p) != self.directory_id
            || id(&self.directory.metadata()?) != self.directory_id
            || !l.is_file()
            || id(&l) != self.lock_id
            || id(&self.lock.metadata()?) != self.lock_id
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let actual = match fs::symlink_metadata(&self.path) {
            Ok(m) if m.is_file() => Some(id(&m)),
            Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if actual != self.expected {
            return Err(io::Error::other("original configuration target changed"));
        }
        Ok(())
    }
    fn commit(
        &mut self,
        job: Job,
        expected: u64,
        body: &[u8],
        configuration: &mut gnunet_config::Configuration,
        clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
    ) -> Result<Committed, Arc<Failure>> {
        if let Some(failure) = &self.blocked {
            return Err(failure.clone());
        }
        let known = |stage, cause| {
            Arc::new(Failure {
                stage,
                cause: Cause::Io(cause),
                exposure: Exposure::NotPublished,
                cleanup: Cleanup::NotNeeded,
            })
        };
        if expected != self.generation {
            return Err(known(
                "generation",
                io::Error::other("original configuration generation is stale"),
            ));
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| known("generation", io::ErrorKind::InvalidInput.into()))?;
        if tokio::time::Instant::now() >= job.hard {
            return Err(known("original-deadline", io::ErrorKind::TimedOut.into()));
        }
        let sample = clock.sample().map_err(|cause| {
            Arc::new(Failure {
                stage: "original-clock",
                cause: Cause::Clock(cause),
                exposure: Exposure::NotPublished,
                cleanup: Cleanup::NotNeeded,
            })
        })?;
        if sample.now.as_micros() >= job.until {
            return Err(known(
                "original-logical-deadline",
                io::ErrorKind::TimedOut.into(),
            ));
        }
        self.fence()
            .map_err(|cause| known("original-target-fence", cause))?;
        // Use the existing shared native atomic writer: its exact existing
        // expansion/temp-file/write/fsync/close/mode/rename implementation is
        // authoritative. No parallel raw INI storage algorithm is introduced.
        if let Err(cause) = configuration.write_serialized(&self.path, body) {
            let failure = Arc::new(Failure {
                stage: "shared-atomic-write",
                cause: Cause::Configuration(cause),
                exposure: Exposure::Unknown,
                cleanup: Cleanup::NotReported,
            });
            self.blocked = Some(failure.clone());
            return Err(failure);
        }
        let finish = (|| -> io::Result<Inode> {
            let parent = fs::symlink_metadata(&self.parent)?;
            let lock = fs::symlink_metadata(self.parent.join(".gnunet-rest-configuration.lock"))?;
            if !parent.is_dir()
                || id(&parent) != self.directory_id
                || id(&self.directory.metadata()?) != self.directory_id
                || !lock.is_file()
                || id(&lock) != self.lock_id
                || id(&self.lock.metadata()?) != self.lock_id
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let metadata = fs::symlink_metadata(&self.path)?;
            if !metadata.is_file() {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let actual = id(&metadata);
            self.directory.sync_all()?;
            Ok(actual)
        })();
        match finish {
            Ok(actual) => {
                self.expected = Some(actual);
                self.generation = next;
                Ok(Committed {
                    job,
                    generation: next,
                })
            }
            Err(cause) => {
                let failure = Arc::new(Failure {
                    stage: "post-publication-directory-sync",
                    cause: Cause::Io(cause),
                    exposure: Exposure::Unknown,
                    cleanup: Cleanup::NotReported,
                });
                self.blocked = Some(failure.clone());
                Err(failure)
            }
        }
    }
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
