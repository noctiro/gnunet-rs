//! Explicit task creation, attachment, execution and settled lifecycle.
use super::{
    Cause, Disposition, Failure, FileOptions, FileProgress, Manifest, Outcome, Phase, RootMode,
    TaskControl, TaskProgress,
};
use super::{
    codec,
    model::{Event, State},
    store::{self, Store},
};
use crate::network::tree_download::{TreeDownloadOptions, TreeDownloadProgress, driver};
use crate::{Buffers, FileIdentity, OutputDir, Repository};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{Uri, directory::walk};
use gnunet_types::AbsoluteTime;
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

pub(super) struct Session {
    pub store: Store,
    pub state: State,
    /// This object currently owns an executing run.
    pub active: bool,
    pub requested: Option<TaskControl>,
    pub control_error: Option<Cause>,
    pub historical_files: usize,
    pub revalidated: usize,
    pub new_files: usize,
    known_files: usize,
    cleanup_pending: usize,
    uncertain_commits: usize,
    pub(super) file: Option<FileProgress>,
}
pub(super) fn lock(session: &Mutex<Session>) -> Result<MutexGuard<'_, Session>, Cause> {
    session
        .lock()
        .map_err(|_| Cause::State("task state mutex poisoned"))
}
impl Session {
    pub fn append(&mut self, event: Event<'_>) -> Result<(), Cause> {
        if self.state.applied() != self.store.record_count() as u64 {
            return Err(Cause::State("unapplied original state record"));
        }
        self.state.check(&event)?;
        let id = match &event {
            Event::DirectoryIntent(binding) | Event::TempOwned { binding, .. } => Some(binding.id),
            Event::NamespaceSelected { binding, .. } => Some(binding.id),
            Event::DirectoryCreated { id, .. }
            | Event::DirectoryVerified { id }
            | Event::CommitIntent { id }
            | Event::FileCommitted { id, .. }
            | Event::Cleanup { id, .. }
            | Event::ResetPending { id } => Some(*id),
            Event::Manifest(_)
            | Event::RootAttached(_)
            | Event::FileAttached { .. }
            | Event::Phase(_) => None,
        };
        let before = self.counts(id);
        let (kind, bytes) = codec::encode_event(&event)?;
        let sequence = self.store.append(kind, &bytes)?;
        let index = self
            .store
            .record_count()
            .checked_sub(1)
            .ok_or(Cause::State("missing appended record"))?;
        self.state.apply(sequence, index, kind, &bytes)?;
        let after = self.counts(id);
        self.known_files = self.known_files - before.0 + after.0;
        self.cleanup_pending = self.cleanup_pending - before.1 + after.1;
        self.uncertain_commits = self.uncertain_commits - before.2 + after.2;
        Ok(())
    }
    fn counts(&self, id: Option<[u8; 64]>) -> (usize, usize, usize) {
        id.and_then(|id| self.state.entries.get(&id))
            .map(entry_counts)
            .unwrap_or_default()
    }
    pub fn progress(&self, output: TreeDownloadProgress) -> TaskProgress {
        TaskProgress {
            output,
            historical_files: self.historical_files,
            revalidated_files: self.revalidated,
            new_files: self.new_files,
            cleanup_pending: self.cleanup_pending,
            uncertain_commits: self.uncertain_commits,
            state_records: self.store.record_count(),
            file: self.file,
        }
    }
}
/// Cheap historical status. Inspecting starts no socket or output revalidation.
#[derive(Clone, Copy, Debug)]
pub struct Status {
    /// Last durable lifecycle phase; not evidence of live I/O.
    pub phase: Phase,
    /// This object currently owns an executing run.
    pub active: bool,
    /// Requested/running history remains without a settled outcome.
    pub interrupted: bool,
    /// Historically attached owned root identity (the private marked staging
    /// root for a file task, or output root for a directory task).
    pub root: Option<FileIdentity>,
    /// Known durable file records, without implicit current revalidation.
    pub known_files: usize,
    /// Recorded exact temporary cleanup debt.
    pub cleanup_pending: usize,
    /// Commit intents still requiring physical reconciliation.
    pub uncertain_commits: usize,
    /// Complete checked WAL record count.
    pub state_records: usize,
    /// An uncertain original append prevents further writes.
    pub fenced: bool,
}
/// A locked durable task. Opening loads facts only; output attachment and running
/// require explicit caller-owned descriptors and a newly supplied finite deadline.
pub struct Task {
    pub(super) session: Mutex<Session>,
    output: Option<AttachedOutput>,
}
enum AttachedOutput {
    Directory(OutputDir),
    File {
        parent: OutputDir,
        staging: OutputDir,
    },
}
struct RunDone {
    progress: TreeDownloadProgress,
    walk: Option<walk::Summary>,
    file: Option<crate::network::range::ReadRange>,
}
impl Task {
    #[cfg(feature = "network")]
    pub(crate) fn directory_identity(&self) -> std::io::Result<crate::FileIdentity> {
        let session = lock(&self.session).map_err(std::io::Error::other)?;
        crate::FileIdentity::of(session.store.directory())
    }
    /// Create a new task manifest before creating its owned output root.
    pub fn create(
        path: impl AsRef<Path>,
        parent: &mut OutputDir,
        relative: impl AsRef<Path>,
        root: Uri<'_>,
        options: TreeDownloadOptions,
        limits: store::Limits,
    ) -> Result<Self, Box<Failure>> {
        Self::create_root(
            path,
            parent,
            relative,
            root,
            options,
            RootMode::Directory,
            limits,
        )
    }
    /// Create an explicitly regular-file task. The original interval is frozen
    /// here; None selects the complete file. A signed LOC retains its real peer.
    pub fn create_file(
        path: impl AsRef<Path>,
        parent: &mut OutputDir,
        relative: impl AsRef<Path>,
        root: Uri<'_>,
        options: FileOptions,
        limits: store::Limits,
    ) -> Result<Self, Box<Failure>> {
        let content = match root {
            Uri::Content(content) => content,
            Uri::Location(location) => location.content(),
            _ => {
                return Err(failure(
                    relative.as_ref(),
                    Cause::State("a file root requires a CHK or LOC"),
                ));
            }
        };
        let selection = options.selection.unwrap_or(0..content.size);
        Self::create_root(
            path,
            parent,
            relative,
            root,
            TreeDownloadOptions::new(options.download),
            RootMode::File { selection },
            limits,
        )
    }
    fn create_root(
        path: impl AsRef<Path>,
        parent: &mut OutputDir,
        relative: impl AsRef<Path>,
        root: Uri<'_>,
        mut options: TreeDownloadOptions,
        mode: RootMode,
        limits: store::Limits,
    ) -> Result<Self, Box<Failure>> {
        let result = (|| -> Result<Self, Cause> {
            match root {
                Uri::Content(_) => {}
                Uri::Location(location) => options.transfer.target = *location.peer().as_bytes(),
                _ => {
                    return Err(Cause::State(
                        "a durable root must be a directory CHK or LOC",
                    ));
                }
            }
            options.transfer.deadline = AbsoluteTime::from_micros(0);
            let mut uri = vec![0; root.encoded_len().map_err(crate::Error::from)?];
            root.encode(&mut uri).map_err(crate::Error::from)?;
            let manifest = Manifest {
                root_uri: uri,
                relative: relative.as_ref().to_path_buf(),
                mode,
                options,
            };
            manifest.validate()?;
            let mut store = Store::create(path, limits)?;
            let (kind, body) = codec::encode_event(&Event::Manifest(manifest))?;
            store.append(kind, &body)?;
            let state = State::load(&mut store)?;
            Ok(Self::from_parts(store, state))
        })();
        let mut task = result.map_err(|cause| failure(relative.as_ref(), cause))?;
        task.attach(parent)?;
        Ok(task)
    }
    /// Lock and load an existing task; no runtime or output is started.
    pub fn open(path: impl AsRef<Path>, limits: store::Limits) -> Result<Self, Box<Failure>> {
        Self::open_with(|| Store::open(path, limits))
    }
    /// Open only the catalog's original directory before journal recovery can
    /// touch any replacement. The original typed history is then loaded normally.
    #[cfg(feature = "network")]
    pub(crate) fn open_registered(
        path: impl AsRef<Path>,
        limits: store::Limits,
        expected: crate::FileIdentity,
    ) -> Result<Self, Box<Failure>> {
        Self::open_with(|| Store::open_registered(path, limits, expected))
    }
    fn open_with(open: impl FnOnce() -> Result<Store, store::Error>) -> Result<Self, Box<Failure>> {
        let result = (|| -> Result<Self, Cause> {
            let mut store = open()?;
            let state = State::load(&mut store)?;
            Ok(Self::from_parts(store, state))
        })();
        result.map_err(|cause| failure(Path::new(""), cause))
    }
    fn from_parts(store: Store, state: State) -> Self {
        let (known_files, cleanup_pending, uncertain_commits) = state
            .entries
            .values()
            .map(entry_counts)
            .fold((0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2));
        Self {
            session: Mutex::new(Session {
                store,
                state,
                active: false,
                requested: None,
                control_error: None,
                historical_files: known_files,
                revalidated: 0,
                new_files: 0,
                known_files,
                cleanup_pending,
                uncertain_commits,
                file: None,
            }),
            output: None,
        }
    }
    /// Copy the immutable original task inputs and policy.
    pub fn manifest(&self) -> Result<Manifest, Cause> {
        Ok(lock(&self.session)?.state.manifest.clone())
    }
    /// Original random task identity used for output ownership markers.
    pub fn task_id(&self) -> Result<[u8; 32], Cause> {
        Ok(*lock(&self.session)?.store.task_id())
    }
    /// Inspect historical state cheaply without reopening files or sockets.
    pub fn status(&self) -> Result<Status, Cause> {
        let session = lock(&self.session)?;
        let p = session.progress(TreeDownloadProgress::default());
        Ok(Status {
            phase: session.state.phase,
            active: session.active,
            interrupted: !session.active
                && matches!(
                    session.state.phase,
                    Phase::Running | Phase::PauseRequested | Phase::CancelRequested
                ),
            root: session.state.root,
            known_files: session.known_files,
            cleanup_pending: p.cleanup_pending,
            uncertain_commits: p.uncertain_commits,
            state_records: p.state_records,
            fenced: session.store.fenced(),
        })
    }
    /// Attach only the recorded task-owned root, or complete its original creation intent.
    pub fn attach(&mut self, parent: &mut OutputDir) -> Result<(), Box<Failure>> {
        let file = lock(&self.session)
            .map(|session| matches!(session.state.manifest.mode, RootMode::File { .. }))
            .map_err(|cause| self.fail(cause, TreeDownloadProgress::default(), None))?;
        if file {
            return self.attach_file(parent);
        }
        let result = (|| -> Result<OutputDir, Cause> {
            let mut session = lock(&self.session)?;
            let relative = session.state.manifest.relative.clone();
            let owner = *session.store.task_id();
            let output = match parent.attach_owned_directory(&relative, owner, session.state.root) {
                Ok(output) => output,
                Err(error) if session.state.root.is_none() && is_missing(&error.operation) => {
                    parent
                        .create_owned_directory(&relative, owner)
                        .map_err(|e| Cause::Directory(Box::new(e)))?
                }
                Err(error) => return Err(Cause::Directory(Box::new(error))),
            };
            let identity = output.identity()?;
            if session.state.root.is_none() {
                session.append(Event::RootAttached(identity))?;
            }
            Ok(output)
        })();
        match result {
            Ok(output) => {
                self.output = Some(AttachedOutput::Directory(output));
                Ok(())
            }
            Err(cause) => Err(self.fail(cause, TreeDownloadProgress::default(), None)),
        }
    }
    fn attach_file(&mut self, parent: &mut OutputDir) -> Result<(), Box<Failure>> {
        let result = (|| -> Result<(OutputDir, OutputDir), Cause> {
            let mut session = lock(&self.session)?;
            let actual_parent = parent.identity()?;
            if session
                .state
                .file_parent
                .is_some_and(|known| known != actual_parent)
            {
                return Err(Cause::State("file destination parent identity changed"));
            }
            let owner = *session.store.task_id();
            let name = super::file::staging_name(&owner);
            let stage = match parent.attach_owned_directory(&name, owner, session.state.root) {
                Ok(stage) => stage,
                Err(error) if session.state.root.is_none() && is_missing(&error.operation) => {
                    parent
                        .create_owned_directory(&name, owner)
                        .map_err(|e| Cause::Directory(Box::new(e)))?
                }
                Err(error) => return Err(Cause::Directory(Box::new(error))),
            };
            if session.state.root.is_none() {
                session.append(Event::FileAttached {
                    parent: actual_parent,
                    staging: stage.identity()?,
                })?;
            }
            Ok((parent.duplicate()?, stage))
        })();
        match result {
            Ok((parent, staging)) => {
                self.output = Some(AttachedOutput::File { parent, staging });
                Ok(())
            }
            Err(cause) => Err(self.fail(cause, TreeDownloadProgress::default(), None)),
        }
    }
    /// Run/continue with a new deadline. Pause is settled only after original MQ
    /// and file work retire and no unresolved commit/cleanup remains in state.
    pub async fn run(
        &mut self,
        source: EndpointSource,
        buffers: &mut Buffers,
        cache: &mut Repository,
        deadline: AbsoluteTime,
        mut control: impl FnMut(TaskProgress) -> TaskControl,
    ) -> Result<Outcome, Box<Failure>> {
        let started = tokio::time::Instant::now();
        let setup = (|| -> Result<(Manifest, gnunet_fs::Content), Cause> {
            if self.output.is_none() {
                return Err(Cause::State("attach the task output before running"));
            }
            let mut session = lock(&self.session)?;
            if session.active {
                return Err(Cause::State("task already running"));
            }
            if matches!(
                session.state.phase,
                Phase::Cancelled | Phase::CancelRequested
            ) {
                return Err(Cause::State(
                    "cancel intent cannot be resumed; settle cancellation explicitly",
                ));
            }
            let manifest = session.state.manifest.clone();
            let content = manifest.root_content()?;
            session.append(Event::Phase(Phase::Running))?;
            session.active = true;
            session.requested = None;
            session.control_error = None;
            session.historical_files = session.known_files;
            session.revalidated = 0;
            session.new_files = 0;
            session.file = None;
            Ok((manifest, content))
        })();
        let (manifest, content) =
            setup.map_err(|cause| self.fail(cause, TreeDownloadProgress::default(), None))?;
        let guard = RunGuard(&self.session);
        let mut options = manifest.options;
        options.transfer.deadline = deadline;
        let session = &self.session;
        let controlled = |progress| {
            let snapshot = match lock(session) {
                Ok(s) => s.progress(progress),
                Err(_) => return crate::Control::Cancel,
            };
            let decision = control(snapshot);
            let mut state = match lock(session) {
                Ok(s) => s,
                Err(_) => return crate::Control::Cancel,
            };
            if state.requested.is_some() || state.control_error.is_some() {
                return crate::Control::Cancel;
            }
            if decision == TaskControl::Continue {
                return crate::Control::Continue;
            }
            let phase = if decision == TaskControl::Pause {
                Phase::PauseRequested
            } else {
                Phase::CancelRequested
            };
            match state.append(Event::Phase(phase)) {
                Ok(()) => state.requested = Some(decision),
                Err(error) => state.control_error = Some(error),
            }
            crate::Control::Cancel
        };
        let output = self
            .output
            .as_mut()
            .ok_or_else(|| failure(&manifest.relative, Cause::State("missing attached output")))?;
        let result = match (&manifest.mode, output) {
            (
                RootMode::File { .. },
                AttachedOutput::File {
                    parent: output,
                    staging,
                },
            ) => super::file::Run {
                state: session,
                output,
                staging,
                manifest: &manifest,
                source,
                started,
                deadline,
            }
            .run(buffers, cache, controlled)
            .await
            .map(|done| RunDone {
                progress: done.progress,
                walk: None,
                file: Some(done.read),
            }),
            (RootMode::Directory, AttachedOutput::Directory(output)) => {
                let mut target = super::target::Target::new(session, output);
                driver::run(
                    &mut target,
                    &manifest.relative,
                    source,
                    content,
                    buffers,
                    Some(cache),
                    options,
                    controlled,
                )
                .await
                .map(|done| RunDone {
                    progress: done.progress,
                    walk: Some(done.walk),
                    file: None,
                })
            }
            _ => Err(Box::new(driver::Failure {
                path: manifest.relative.clone(),
                progress: TreeDownloadProgress::default(),
                walk: None,
                cause: Cause::State("attached owner differs from original root mode"),
                interruption: None,
                namespace_cleanup: None,
            })),
        };
        drop(guard);
        match result {
            Ok(done) => {
                let mut state = lock(&self.session)
                    .map_err(|cause| self.fail(cause, done.progress, done.walk))?;
                if let Err(cause) = state.append(Event::Phase(Phase::Complete)) {
                    let p = state.progress(done.progress);
                    drop(state);
                    return Err(Box::new(Failure {
                        path: manifest.relative,
                        progress: p,
                        walk: done.walk,
                        file: done.file,
                        cause,
                        state_failure: None,
                        interruption: None,
                        namespace_cleanup: None,
                    }));
                }
                Ok(Outcome {
                    disposition: Disposition::Complete,
                    progress: state.progress(done.progress),
                    walk: done.walk,
                    file: done.file,
                })
            }
            Err(error) => {
                let mut state = lock(&self.session)
                    .map_err(|cause| self.fail(cause, error.progress, error.walk))?;
                let state_failure = state.control_error.take();
                let clean = error.cause.clean_cancel()
                    && error.namespace_cleanup.is_none()
                    // The directory driver retains the caller's original
                    // cooperative cancellation as an interruption too. Only
                    // that typed cancellation can settle a requested pause;
                    // deadline, clock and independent failures still refuse.
                    && error.interruption.as_ref().is_none_or(|cause| matches!(cause, crate::Error::Cancelled))
                    && state_failure.is_none();
                if clean && let Some(requested) = state.requested {
                    let phase = if requested == TaskControl::Pause {
                        Phase::Paused
                    } else {
                        Phase::Cancelled
                    };
                    match state.append(Event::Phase(phase)) {
                        Ok(()) => {
                            return Ok(Outcome {
                                disposition: if requested == TaskControl::Pause {
                                    Disposition::Paused
                                } else {
                                    Disposition::Cancelled
                                },
                                progress: state.progress(error.progress),
                                walk: error.walk,
                                file: error.cause.range_receipt().cloned(),
                            });
                        }
                        Err(cause) => {
                            return Err(Box::new(Failure {
                                path: error.path,
                                progress: state.progress(error.progress),
                                walk: error.walk,
                                file: error.cause.range_receipt().cloned(),
                                cause: error.cause,
                                state_failure: Some(cause),
                                interruption: error.interruption,
                                namespace_cleanup: error.namespace_cleanup,
                            }));
                        }
                    }
                }
                let mut secondary = state_failure;
                if !state.store.fenced()
                    && state.state.phase != Phase::CancelRequested
                    && let Err(cause) = state.append(Event::Phase(Phase::Failed))
                    && secondary.is_none()
                {
                    secondary = Some(cause);
                }
                let path = match &error.cause {
                    Cause::Reconcile { path, .. }
                        if matches!(manifest.mode, RootMode::Directory) =>
                    {
                        manifest.relative.join(path)
                    }
                    _ => error.path,
                };
                Err(Box::new(Failure {
                    path,
                    progress: state.progress(error.progress),
                    walk: error.walk,
                    file: error.cause.range_receipt().cloned(),
                    cause: error.cause,
                    state_failure: secondary,
                    interruption: error.interruption,
                    namespace_cleanup: error.namespace_cleanup,
                }))
            }
        }
    }
    /// Persist cancellation intent without starting runtime work or deleting output.
    /// Call `settle_cancel` to reconcile original recorded effects before Cancelled.
    pub fn request_cancel(&mut self) -> Result<(), Cause> {
        let mut state = lock(&self.session)?;
        if state.active {
            return Err(Cause::State("task already running"));
        }
        if matches!(state.state.phase, Phase::CancelRequested | Phase::Cancelled) {
            return Ok(());
        }
        state.append(Event::Phase(Phase::CancelRequested))
    }
    /// Settle an interrupted durable cancellation without starting a traversal,
    /// opening network connections, or authorizing any new output name.
    ///
    /// The caller explicitly reattaches the original owned root. Only recorded
    /// temporary/commit facts are reconciled; this does not authenticate a whole
    /// directory tree. Historical committed files are retained without claiming
    /// current revalidation. A caller-control, filesystem, or WAL failure leaves
    /// CancelRequested and its original facts available for another explicit
    /// settlement attempt. Dropping this operation never writes a settled phase.
    pub fn settle_cancel(
        &mut self,
        parent: &mut OutputDir,
        buffers: &mut Buffers,
        cache: &mut Repository,
        mut control: impl FnMut(TaskProgress) -> crate::Control,
    ) -> Result<Outcome, Box<Failure>> {
        // Check before attach, because a manifest without RootAttached must not
        // gain fresh effects merely by calling cancellation settlement.
        let setup = (|| -> Result<(), Cause> {
            let state = lock(&self.session)?;
            if state.active {
                return Err(Cause::State("task already running"));
            }
            if state.state.phase != Phase::CancelRequested {
                return Err(Cause::State(
                    "cancellation settlement requires CancelRequested",
                ));
            }
            if state.state.root.is_none() {
                return Err(Cause::State(
                    "cancellation has no previously attached output root",
                ));
            }
            if let Some(error) = state.store.failure() {
                return Err(Cause::Storage(error.clone()));
            }
            if state.state.applied() != state.store.record_count() as u64 {
                return Err(Cause::State("unapplied original state record"));
            }
            Ok(())
        })();
        setup.map_err(|cause| self.fail(cause, TreeDownloadProgress::default(), None))?;
        self.attach(parent)?;
        let setup = (|| -> Result<Manifest, Cause> {
            let mut state = lock(&self.session)?;
            // &mut self keeps this object exclusive; retain the explicit live
            // state guard so a panic/early exit never implies Cancelled.
            state.active = true;
            state.requested = Some(TaskControl::Cancel);
            state.control_error = None;
            state.historical_files = state.known_files;
            state.revalidated = 0;
            state.new_files = 0;
            Ok(state.state.manifest.clone())
        })();
        let manifest =
            setup.map_err(|cause| self.fail(cause, TreeDownloadProgress::default(), None))?;
        let guard = RunGuard(&self.session);
        let session = &self.session;
        if matches!(manifest.mode, RootMode::File { .. }) {
            let mut independent_control = None;
            let result = (|| -> Result<Option<crate::network::range::ReadRange>, Cause> {
                let Some(AttachedOutput::File {
                    parent: output,
                    staging,
                }) = self.output.as_mut()
                else {
                    return Err(Cause::State(
                        "file cancellation owner differs from root mode",
                    ));
                };
                let (result, control_error) = super::file::Settlement {
                    state: session,
                    output,
                    staging,
                    manifest: &manifest,
                }
                .run(buffers, cache, || {
                    let snapshot = lock(session)?.progress(TreeDownloadProgress::default());
                    if control(snapshot) == crate::Control::Cancel {
                        Err(crate::Error::Cancelled.into())
                    } else {
                        Ok(())
                    }
                });
                independent_control = control_error;
                result
            })();
            drop(guard);
            return match result {
                Ok(file) => {
                    let output = TreeDownloadProgress::default();
                    Ok(Outcome {
                        disposition: Disposition::Cancelled,
                        progress: lock(&self.session)
                            .map_err(|cause| self.fail(cause, output, None))?
                            .progress(output),
                        walk: None,
                        file,
                    })
                }
                Err(cause) => {
                    let mut failure = self.fail(cause, TreeDownloadProgress::default(), None);
                    failure.state_failure = independent_control;
                    Err(failure)
                }
            };
        }
        let mut output_progress = TreeDownloadProgress::default();
        let mut failed_path = manifest.relative.clone();
        let result = (|| -> Result<(), Cause> {
            let Some(AttachedOutput::Directory(output)) = self.output.as_mut() else {
                return Err(Cause::State(
                    "directory cancellation owner differs from root mode",
                ));
            };
            let mut cursor: Option<[u8; 64]> = None;
            loop {
                let pending = {
                    use std::ops::Bound::{Excluded, Unbounded};
                    let state = lock(session)?;
                    state
                        .state
                        .entries
                        .range((cursor.map(Excluded).unwrap_or(Unbounded), Unbounded))
                        .find(|(_, entry)| {
                            entry.temporary.is_some()
                                && (entry.committed.is_none() || !entry.cleanup)
                        })
                        .map(|(id, entry)| (*id, entry.clone()))
                };
                let Some((id, entry)) = pending else {
                    break;
                };
                cursor = Some(id);
                failed_path = manifest.relative.join(&entry.binding.path);
                // The original task mutex is released before caller code runs.
                let snapshot = lock(session)?.progress(output_progress);
                if control(snapshot) == crate::Control::Cancel {
                    return Err(crate::Error::Cancelled.into());
                }
                let temporary = entry
                    .temporary
                    .as_ref()
                    .ok_or(Cause::State("recorded temporary disappeared"))?;
                let relative_parent = entry
                    .binding
                    .path
                    .parent()
                    .ok_or(Cause::State("recorded file has no parent"))?;
                let relative_temp = relative_parent.join(&temporary.name);
                if entry.committed.is_some() {
                    // These are historical commit facts. Cleanup preserves that
                    // distinction and does not fabricate a new ReadFile receipt.
                    output.cleanup_recorded_temp(
                        &relative_temp,
                        temporary.parent,
                        temporary.identity,
                    )?;
                    lock(session)?.append(Event::Cleanup {
                        id,
                        success: true,
                        stage: crate::CommitStage::Durable,
                    })?;
                    continue;
                }
                match output.inspect_file(&entry.binding.path)? {
                    Some(identity) => {
                        if !entry.intent || identity != temporary.identity {
                            return Err(Cause::Reconcile {
                                path: entry.binding.path,
                                reason: "cancelled final name differs from original commit intent inode",
                            });
                        }
                        let known_parent = lock(session)?
                            .state
                            .entries
                            .get(
                                &entry
                                    .binding
                                    .parent
                                    .ok_or(Cause::State("recorded file parent missing"))?,
                            )
                            .and_then(|parent| parent.created)
                            .ok_or(Cause::State("recorded file parent is not attached"))?;
                        if known_parent != temporary.parent {
                            return Err(Cause::State(
                                "recorded temporary parent differs from original directory",
                            ));
                        }
                        let mut guarded = |_| {
                            let snapshot = match lock(session) {
                                Ok(state) => state.progress(output_progress),
                                Err(_) => return crate::Control::Cancel,
                            };
                            control(snapshot)
                        };
                        let verified = output
                            .revalidate_file(
                                &entry.binding.path,
                                entry.binding.content,
                                identity,
                                Some(temporary.parent),
                                buffers,
                                cache,
                                manifest.options.transfer.limits,
                                &mut guarded,
                            )
                            .map_err(Cause::Revalidate)?;
                        // Every increment below follows the actual refreshed
                        // naming barriers and genuine full-content reader receipt.
                        output_progress.files_committed += 1;
                        output_progress.file_bytes += u128::from(entry.binding.content.size);
                        lock(session)?.revalidated += 1;
                        if let Err(cause) =
                            lock(session)?.append(Event::FileCommitted { id, identity })
                        {
                            return Err(Cause::Committed(Box::new(super::CommitFailure {
                                identity,
                                receipt: verified.read,
                                cause: Box::new(cause),
                            })));
                        }
                        let cleaned = (|| -> Result<(), Cause> {
                            output.cleanup_recorded_temp(
                                &relative_temp,
                                temporary.parent,
                                temporary.identity,
                            )?;
                            lock(session)?.append(Event::Cleanup {
                                id,
                                success: true,
                                stage: crate::CommitStage::Durable,
                            })
                        })();
                        if let Err(cause) = cleaned {
                            return Err(Cause::Committed(Box::new(super::CommitFailure {
                                identity,
                                receipt: verified.read,
                                cause: Box::new(cause),
                            })));
                        }
                    }
                    None => {
                        // Actual final absence + exact original temp cleanup is
                        // the authority for clearing an uncommitted intent.
                        output.cleanup_recorded_temp(
                            &relative_temp,
                            temporary.parent,
                            temporary.identity,
                        )?;
                        let mut state = lock(session)?;
                        state.append(Event::Cleanup {
                            id,
                            success: true,
                            stage: entry.stage,
                        })?;
                        state.append(Event::ResetPending { id })?;
                    }
                }
            }
            failed_path = manifest.relative.clone();
            let snapshot = lock(session)?.progress(output_progress);
            if control(snapshot) == crate::Control::Cancel {
                return Err(crate::Error::Cancelled.into());
            }
            output.sync_directory()?;
            // Model rejects remaining recorded temporary/intent debts. No new
            // directory receipt or Complete claim is manufactured by settlement.
            lock(session)?.append(Event::Phase(Phase::Cancelled))
        })();
        drop(guard);
        match result {
            Ok(()) => {
                let progress = lock(&self.session)
                    .map_err(|cause| self.fail(cause, output_progress, None))?
                    .progress(output_progress);
                Ok(Outcome {
                    disposition: Disposition::Cancelled,
                    progress,
                    walk: None,
                    file: None,
                })
            }
            Err(cause) => {
                let path = match &cause {
                    Cause::Reconcile { path, .. } => manifest.relative.join(path),
                    _ => failed_path,
                };
                let mut failure = self.fail(cause, output_progress, None);
                failure.path = path;
                Err(failure)
            }
        }
    }

    fn fail(
        &self,
        cause: Cause,
        output: TreeDownloadProgress,
        walk: Option<walk::Summary>,
    ) -> Box<Failure> {
        match lock(&self.session) {
            Ok(s) => Box::new(Failure {
                path: s.state.manifest.relative.clone(),
                progress: s.progress(output),
                walk,
                file: cause.range_receipt().cloned(),
                cause,
                state_failure: None,
                interruption: None,
                namespace_cleanup: None,
            }),
            Err(_) => failure(Path::new(""), cause),
        }
    }
}
pub(super) fn failure(path: &Path, cause: Cause) -> Box<Failure> {
    Box::new(Failure {
        path: path.to_path_buf(),
        progress: TaskProgress::default(),
        walk: None,
        file: cause.range_receipt().cloned(),
        cause,
        state_failure: None,
        interruption: None,
        namespace_cleanup: None,
    })
}
fn is_missing(error: &crate::Error) -> bool {
    matches!(error,crate::Error::Io(e) if e.kind()==std::io::ErrorKind::NotFound)
}
struct RunGuard<'a>(&'a Mutex<Session>);
impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.active = false;
        }
    }
}

fn entry_counts(entry: &super::model::EntryState) -> (usize, usize, usize) {
    (
        usize::from(entry.committed.is_some()),
        usize::from(entry.temporary.is_some() && !entry.cleanup),
        usize::from(entry.intent && entry.committed.is_none()),
    )
}

#[cfg(test)]
mod tests;
