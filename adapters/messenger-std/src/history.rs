//! Explicit Rust-owned committed history store and one bounded storage worker.
//! Startup recovery alone owns Loaded; arbitrary network bytes have no constructor
//! for this production CommittedArchive provider. No fsync runs in socket polling.
use crate::core::{
    self,
    archive::{CommittedArchive, Recovered},
};
use gnunet_snapshot_host::{
    Namespace,
    backend::{self, Loaded, Store},
    worker::{Completion, Job, Stopped, Worker},
};
use gnunet_types::Error as Fault;
use std::{
    fmt,
    path::Path,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;
/// Exact storage, source and codec failures; bodies are never printable.
#[derive(Debug)]
pub enum Error {
    /// Invalid namespace/generation/resource state.
    Protocol(Fault),
    /// Actual historical graph/retained signature check failed.
    Core(core::Error),
    /// Actual original filesystem failure, including Unknown and cleanup errors.
    Store(Arc<backend::Failure>),
    /// Actual worker startup failure.
    Io(std::io::Error),
    /// Independent original completion and worker shutdown failures.
    Shutdown {
        /// Original admitted image completion failure.
        completion: Box<Error>,
        /// Independent worker drain/join failure.
        worker: Box<Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Core(e) => e.fmt(f),
            Self::Store(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Shutdown { completion, worker } => {
                write!(
                    f,
                    "history completion: {completion}; worker shutdown: {worker}"
                )
            }
        }
    }
}
impl std::error::Error for Error {}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<core::Error> for Error {
    fn from(e: core::Error) -> Self {
        Self::Core(e)
    }
}
/// Explicit maximum one retained image, microbatch interval and finite event cut.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Full serialized image including raw chat frames. Actual capacities stay bounded.
    pub image_bytes: usize,
    /// Maximum events gathered before forcing the next original snapshot admission.
    pub batch_events: u64,
    /// Maximum gathering interval; filesystem completion itself has no false deadline.
    pub batch_delay: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            image_bytes: 16 * 1024 * 1024,
            batch_events: 32,
            batch_delay: Duration::from_millis(16),
        }
    }
}
struct OwnedCommitted {
    generation: u64,
    body: Zeroizing<Vec<u8>>,
}
impl OwnedCommitted {
    fn from_loaded(loaded: Loaded) -> Result<Self, Error> {
        if loaded.namespace() != Namespace::Messenger || loaded.generation() == 0 {
            return Err(Fault::Authentication.into());
        }
        let generation = loaded.generation();
        Ok(Self {
            generation,
            body: loaded.into_body(),
        })
    }
}
impl CommittedArchive for OwnedCommitted {
    fn generation(&self) -> u64 {
        self.generation
    }
    fn expose_committed(&self) -> &[u8] {
        &self.body
    }
}
struct Pending {
    job: Job,
    cut: u64,
    peer: Option<[u8; 32]>,
}
struct Prepared {
    cut: u64,
    peer: Option<[u8; 32]>,
    body: Zeroizing<Vec<u8>>,
}
/// Original local observations. Queued is not a durable/publication receipt.
#[derive(Clone, Copy, Debug)]
pub enum Progress {
    /// Actual original image admitted to the one storage worker queue.
    Queued {
        /// Attempted next generation, not success.
        generation: u64,
        /// Original immutable image byte count.
        bytes: usize,
    },
    /// Actual private committed worker receipt, including real file/directory sync.
    Committed {
        /// Actual definitely committed generation.
        generation: u64,
    },
}
/// Source-free Core tied to the exact original owned History store. Private
/// construction prevents accidentally pairing another store/image generation.
pub struct Restored<'id> {
    pub(crate) core: core::Core<'id>,
    pub(crate) domain: Arc<()>,
}
impl<'id> Restored<'id> {
    pub(crate) fn profile(&self) -> core::wire::profile::Profile {
        self.core.local_profile()
    }
    pub(crate) fn into_core(self) -> core::Core<'id> {
        self.core
    }
}

/// One explicit worker and one original immutable pending image. No automatic
/// retries after Unknown; drop joins the actual original worker before release.
pub struct History {
    worker: Worker,
    domain: Arc<()>,
    limits: Limits,
    generation: u64,
    revision: u64,
    committed: u64,
    pending: Option<Pending>,
    prepared: Option<Prepared>,
    due: Option<Instant>,
    historical_peer: Option<[u8; 32]>,
    failed: bool,
}
impl History {
    /// Actually open only a new/exactly marked Rust Messenger directory, restore
    /// trusted committed history, and start the explicit sole writer. Call at
    /// PROGRAM startup after UID/GID setup, never from a socket poll callback.
    /// The caller supplies a separate original instance for the recovered Core;
    /// a still-borrowed initial Server core instance cannot be reused here.
    pub fn open<'id>(
        instance: &'id mut core::Instance,
        directory: impl AsRef<Path>,
        core_limits: core::Limits,
        profile: core::wire::profile::Profile,
        limits: Limits,
    ) -> Result<(Self, Restored<'id>), Error> {
        if limits.image_bytes == 0
            || limits.batch_events == 0
            || limits.batch_delay.is_zero()
            || Instant::now().checked_add(limits.batch_delay).is_none()
        {
            return Err(Fault::InvalidInput.into());
        }
        let (store, loaded) = Store::open(
            Namespace::Messenger,
            directory,
            backend::Limits {
                body_bytes: limits.image_bytes,
            },
        )
        .map_err(|e| Error::Store(Arc::new(e)))?;
        if loaded.namespace() != Namespace::Messenger {
            return Err(Fault::Authentication.into());
        }
        let generation = loaded.generation();
        let (core, historical_peer) = if generation == 0 {
            if !loaded.created_directory() {
                return Err(Fault::OutcomeUnknown.into());
            }
            drop(loaded);
            (
                core::Core::new(instance, core::Mode::Service, core_limits, profile)?,
                None,
            )
        } else {
            let source = OwnedCommitted::from_loaded(loaded)?;
            let recovered: Recovered<'id> = core::Core::recover_archive(
                instance,
                &source,
                core_limits,
                profile,
                limits.image_bytes,
            )?;
            let (core, actual, peer) = recovered.into_parts();
            if actual != generation {
                return Err(Fault::StaleGeneration.into());
            }
            (core, peer)
        };
        let worker = Worker::start(store).map_err(Error::Io)?;
        let dirty = u64::from(generation == 0);
        let due = (dirty != 0).then(Instant::now);
        let domain = Arc::new(());
        Ok((
            Self {
                domain: domain.clone(),
                worker,
                limits,
                generation,
                revision: dirty,
                committed: 0,
                pending: None,
                prepared: None,
                due,
                historical_peer,
                failed: false,
            },
            Restored { core, domain },
        ))
    }
    pub(crate) fn check_restored(&self, restored: &Restored<'_>) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.domain, &restored.domain) {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(())
    }
    /// Current known actual durable generation, never an attempted-write counter.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Last public local peer in the committed archive; historical metadata only.
    #[must_use]
    pub const fn historical_peer(&self) -> Option<[u8; 32]> {
        self.historical_peer
    }
    /// Whether this cut is committed and no preparation/commit remains outstanding.
    #[must_use]
    pub fn ready(&self) -> bool {
        !self.failed
            && self.revision == self.committed
            && self.pending.is_none()
            && self.prepared.is_none()
    }
    /// A worker/prepared immutable image freezes persisted Core mutations until its
    /// exact receipt; physical socket writes/close and owned PILS results can drain.
    #[must_use]
    pub fn frozen(&self) -> bool {
        self.pending.is_some() || self.prepared.is_some()
    }
    /// Record a real local business transition. This grants no durable acceptance.
    pub fn changed(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Fault::OutcomeUnknown.into());
        }
        self.revision = self.revision.checked_add(1).ok_or(Fault::Overflow)?;
        if self.due.is_none() {
            self.due = Some(
                Instant::now()
                    .checked_add(self.limits.batch_delay)
                    .ok_or(Fault::Overflow)?,
            )
        }
        Ok(())
    }
    /// A real local identity transition requires its own current checkpoint.
    /// Historical peer metadata is updated only by the original worker receipt.
    pub(crate) fn identity_changed(&mut self) -> Result<(), Error> {
        self.changed()?;
        self.due = Some(Instant::now());
        Ok(())
    }
    /// Select the original next scheduling wake; actual fsync never becomes success
    /// because this instant elapsed or because a waiting future was canceled.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        if self.pending.is_none()
            && self.prepared.is_none()
            && !self.failed
            && self.revision != self.committed
        {
            self.due
        } else {
            None
        }
    }
    /// Poll only actual worker completions and explicitly bounded serialization.
    /// Caller prevents persisted Core mutations while frozen() is true.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        core: &core::Core<'_>,
        force: bool,
    ) -> Poll<Result<Progress, Error>> {
        if self.failed {
            return Poll::Ready(Err(Fault::OutcomeUnknown.into()));
        }
        match self.worker.poll(cx) {
            Poll::Ready(Ok(Some(completion))) => {
                return Poll::Ready(self.completion(completion));
            }
            Poll::Ready(Ok(None)) => {
                self.failed = true;
                return Poll::Ready(Err(Fault::Closed.into()));
            }
            Poll::Ready(Err(e)) => {
                self.failed = true;
                return Poll::Ready(Err(e.into()));
            }
            Poll::Pending => {}
        }
        if self.pending.is_some() || self.revision == self.committed {
            return Poll::Pending;
        }
        if !force
            && self.revision - self.committed < self.limits.batch_events
            && self.due.is_some_and(|u| Instant::now() < u)
        {
            return Poll::Pending;
        }
        if self.prepared.is_none() {
            let image = match core.prepare_archive(self.limits.image_bytes) {
                Ok(image) => image,
                Err(core::Error::Protocol(Fault::WouldBlock)) if !force => return Poll::Pending,
                Err(core::Error::Protocol(Fault::WouldBlock)) => {
                    return Poll::Ready(Err(Fault::WouldBlock.into()));
                }
                Err(e) => return Poll::Ready(Err(e.into())),
            };
            self.prepared = Some(Prepared {
                cut: self.revision,
                peer: image.historical_peer(),
                body: image.into_body(),
            });
        }
        let Prepared { cut, peer, body } = self.prepared.take().ok_or(Fault::NotReady)?;
        let bytes = body.len();
        match self.worker.submit(self.generation, body) {
            Ok(job) => {
                self.pending = Some(Pending { job, cut, peer });
                Poll::Ready(Ok(Progress::Queued {
                    generation: self.generation.checked_add(1).ok_or(Fault::Overflow)?,
                    bytes,
                }))
            }
            Err((Fault::WouldBlock, body)) => {
                self.prepared = Some(Prepared { cut, peer, body });
                Poll::Pending
            }
            Err((e, _)) => {
                self.failed = true;
                Poll::Ready(Err(e.into()))
            }
        }
    }
    fn completion(&mut self, completion: Completion) -> Result<Progress, Error> {
        let (job, result) = completion.into_parts();
        let pending = self.pending.take().ok_or(Fault::StaleGeneration)?;
        if job != pending.job || job.namespace() != Namespace::Messenger {
            self.failed = true;
            return Err(Fault::StaleGeneration.into());
        }
        match result {
            Ok(receipt) => {
                let expected = self.generation.checked_add(1).ok_or(Fault::Overflow)?;
                if receipt.namespace() != Namespace::Messenger || receipt.generation() != expected {
                    self.failed = true;
                    return Err(Fault::StaleGeneration.into());
                }
                self.generation = expected;
                self.committed = pending.cut;
                self.historical_peer = pending.peer;
                if self.committed == self.revision {
                    self.due = None;
                }
                Ok(Progress::Committed {
                    generation: expected,
                })
            }
            Err(error) => {
                self.failed = true;
                Err(Error::Store(error))
            }
        }
    }
    /// Flush the exact final accepted image after real MQ stop, using no logical
    /// clock. The caller retains Core; an actual fsync can take unbounded OS time.
    pub async fn flush(
        &mut self,
        core: &core::Core<'_>,
        observe: &mut impl FnMut(Progress),
    ) -> Result<(), Error> {
        while !self.ready() {
            let p = std::future::poll_fn(|cx| self.poll(cx, core, true)).await?;
            observe(p)
        }
        Ok(())
    }
    /// Stop admission and join the actual original worker. This is independent of
    /// finite MQ shutdown grace and never claims an interrupted fsync was canceled.
    pub async fn shutdown(&mut self) -> Result<Stopped, Error> {
        // One admitted job and one completion by construction. Preserve that
        // original receipt even when final Core preparation previously failed.
        let mut completion = None;
        let mut duplicate = false;
        let stopped = self
            .worker
            .shutdown(|original| {
                if completion.is_some() {
                    duplicate = true;
                } else {
                    completion = Some(original);
                }
            })
            .await;
        let applied = completion
            .map(|original| self.completion(original))
            .transpose();
        let stopped = match (stopped, applied) {
            (Err(worker), Err(completion)) => {
                self.failed = true;
                return Err(Error::Shutdown {
                    completion: Box::new(completion),
                    worker: Box::new(worker.into()),
                });
            }
            (Err(worker), _) => {
                self.failed = true;
                return Err(worker.into());
            }
            (Ok(_), Err(error)) => {
                self.failed = true;
                return Err(error);
            }
            (Ok(stopped), Ok(_)) => stopped,
        };
        if duplicate
            || self.pending.is_some()
            || stopped.namespace != Namespace::Messenger
            || stopped.generation != self.generation
        {
            self.failed = true;
            return Err(Fault::OutcomeUnknown.into());
        }
        if let Some(error) = &stopped.failure {
            self.failed = true;
            return Err(Error::Store(error.clone()));
        }
        Ok(stopped)
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use gnunet_crypto::EddsaPrivateKey;
    use std::{
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Result<Self, std::io::Error> {
            let path = std::env::temp_dir().join(format!(
                "msg-history-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _removed = std::fs::remove_dir_all(&self.0);
        }
    }

    // Actual owned storage/worker receipts. There is no simulated network or
    // claim that these test-owned keys establish a live PILS source.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare committed identity cuts and historical-only restoration using the actual worker"
    )]
    fn identity_cuts_reopen_as_history_and_fresh_authority_requires_a_new_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let directory = Directory::new()?;
                let path = directory.0.join("history");
                let peers = [31, 32, 33].map(|seed| {
                    *EddsaPrivateKey::from_seed([seed; 32])
                        .public_key()
                        .as_bytes()
                });
                let profile = core::wire::profile::Profile::NATIVE_255;
                let mut instance = core::Instance::new();
                let (mut history, restored) = History::open(
                    &mut instance,
                    &path,
                    core::Limits::default(),
                    profile,
                    Limits::default(),
                )?;
                let mut state = restored.into_core();
                let result = async {
                    state.configure_local_peer(peers[0])?;
                    history.identity_changed()?;
                    assert!(!history.ready());
                    history.flush(&state, &mut |_| {}).await?;
                    assert_eq!(history.historical_peer(), Some(peers[0]));
                    assert!(state.rotate_local_peer(peers[1])?);
                    history.identity_changed()?;
                    assert!(!history.ready());
                    assert_eq!(history.historical_peer(), Some(peers[0]));
                    history.flush(&state, &mut |_| {}).await?;
                    assert_eq!(history.historical_peer(), Some(peers[1]));
                    Ok::<_, Error>(())
                }
                .await;
                let stopped = history.shutdown().await;
                result?;
                stopped?;
                drop(history);
                drop(state);

                let mut fresh = core::Instance::new();
                let (mut history, restored) = History::open(
                    &mut fresh,
                    &path,
                    core::Limits::default(),
                    profile,
                    Limits::default(),
                )?;
                let mut state = restored.into_core();
                let result = async {
                    assert!(history.ready());
                    assert_eq!(history.historical_peer(), Some(peers[1]));
                    assert!(state.is_own_signer(&peers[0]) && state.is_own_signer(&peers[1]));
                    assert!(matches!(
                        state.prepare_archive(65535),
                        Err(core::Error::Protocol(Fault::NotReady))
                    ));
                    // A newly authorized current source can adopt owned historical
                    // data without claiming a common master with its past authors.
                    state.configure_local_peer(peers[2])?;
                    history.identity_changed()?;
                    assert!(!history.ready());
                    assert_eq!(history.historical_peer(), Some(peers[1]));
                    history.flush(&state, &mut |_| {}).await?;
                    assert!(history.ready());
                    assert_eq!(history.historical_peer(), Some(peers[2]));
                    assert!(state.is_own_signer(&peers[0]) && state.is_own_signer(&peers[1]));
                    Ok::<_, Error>(())
                }
                .await;
                let stopped = history.shutdown().await;
                result?;
                stopped?;
                Ok(())
            })
    }
}
