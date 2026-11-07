//! Regular-file durable execution over the existing selected transfer and the
//! original task WAL. A range receipt never becomes whole-file authentication.
use super::{
    Cause, Manifest, Phase, RangeCommitFailure, RootMode,
    model::{EntryBinding, Event, TempFact},
    task::{Session, lock},
};
use crate::{
    Buffers, CommitStage, Control, Error, OutputDir, Progress, Repository,
    network::{
        DownloadOptions,
        range::{Completion, ReadRange, Report},
        tree_download::{TreeDownloadProgress, driver, paths::root_id},
    },
    output::OutputObservation,
};
use gnunet_client_host::EndpointSource;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::{ffi::OsString, ops::Range, sync::Mutex, time::Duration};
use tokio::time::Instant;

/// Original file lookup policy and optional absolute selection.
#[derive(Clone, Debug)]
pub struct FileOptions {
    /// Original anonymous/local/LOC lookup and resource policy.
    pub download: DownloadOptions,
    /// None means all bytes; a selected interval is frozen at task creation.
    pub selection: Option<Range<u64>>,
}
pub(super) struct Settlement<'a> {
    pub state: &'a Mutex<Session>,
    pub output: &'a mut OutputDir,
    pub staging: &'a mut OutputDir,
    pub manifest: &'a Manifest,
}
impl Settlement<'_> {
    pub(super) fn run(
        &mut self,
        buffers: &mut Buffers,
        cache: &mut Repository,
        mut control: impl FnMut() -> Result<(), Cause>,
    ) -> (Result<Option<ReadRange>, Cause>, Option<Cause>) {
        let mut independent_control = None;
        let result = (|| -> Result<Option<ReadRange>, Cause> {
            control()?;
            let binding = binding(self.manifest)?;
            let RootMode::File { selection } = &self.manifest.mode else {
                return Err(Cause::State("file settlement requires file root"));
            };
            let (known, parent, stage) = {
                let session = lock(self.state)?;
                (
                    session
                        .state
                        .entry(&binding)?
                        .cloned()
                        .ok_or(Cause::State("file root missing"))?,
                    session
                        .state
                        .file_parent
                        .ok_or(Cause::State("file parent missing"))?,
                    session
                        .state
                        .root
                        .ok_or(Cause::State("file staging missing"))?,
                )
            };
            if self.output.identity()? != parent || self.staging.identity()? != stage {
                return Err(Cause::State("file settlement parent/staging changed"));
            }
            let mut receipt = None;
            if let Some(temp) = &known.temporary {
                if known.committed.is_some() {
                    if !known.cleanup {
                        clean(
                            self.state,
                            self.staging,
                            binding.id,
                            temp,
                            CommitStage::Durable,
                        )?;
                    }
                } else {
                    match self.output.inspect_file(&binding.path)? {
                        Some(identity) => {
                            if !known.intent || identity != temp.identity {
                                return Err(Cause::Reconcile {
                                    path: binding.path,
                                    reason: "cancelled file differs from original commit inode",
                                });
                            }
                            let mut control_error = None;
                            let mut guarded = |_| match control() {
                                Ok(()) => Control::Continue,
                                Err(error) => {
                                    control_error = Some(error);
                                    Control::Cancel
                                }
                            };
                            let result = self.output.revalidate_range(
                                &binding.path,
                                binding.content,
                                selection.clone(),
                                identity,
                                Some(parent),
                                buffers,
                                cache,
                                self.manifest.options.transfer.limits,
                                &mut guarded,
                            );
                            let verified = match (result, control_error) {
                                (Ok(verified), None) => verified,
                                (Err(error), control_error) => {
                                    independent_control = control_error;
                                    return Err(Cause::RangeRevalidate(error));
                                }
                                (Ok(verified), Some(error)) => {
                                    remember_read(self.state, &verified.read)?;
                                    return Err(error);
                                }
                            };
                            remember_read(self.state, &verified.read)?;
                            lock(self.state)?.revalidated += 1;
                            if let Err(cause) = lock(self.state)?.append(Event::FileCommitted {
                                id: binding.id,
                                identity,
                            }) {
                                return Err(Cause::RangeCommitted(Box::new(RangeCommitFailure {
                                    identity,
                                    receipt: verified.read,
                                    cause: Box::new(cause),
                                })));
                            }
                            if let Err(cause) = clean(
                                self.state,
                                self.staging,
                                binding.id,
                                temp,
                                CommitStage::Durable,
                            ) {
                                return Err(Cause::RangeCommitted(Box::new(RangeCommitFailure {
                                    identity,
                                    receipt: verified.read,
                                    cause: Box::new(cause),
                                })));
                            }
                            receipt = Some(verified.read);
                        }
                        None => {
                            clean(self.state, self.staging, binding.id, temp, known.stage)?;
                            lock(self.state)?.append(Event::ResetPending { id: binding.id })?;
                        }
                    }
                }
            }
            control()?;
            self.output.sync_directory()?;
            self.staging.sync_directory()?;
            lock(self.state)?.append(Event::Phase(Phase::Cancelled))?;
            Ok(receipt)
        })();
        (result, independent_control)
    }
}
impl FileOptions {
    /// Whole-file retrieval with the supplied original lookup policy.
    #[must_use]
    pub fn new(download: DownloadOptions) -> Self {
        Self {
            download,
            selection: None,
        }
    }
}
/// Actual current-run selected transfer counters, without a reusable proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileProgress {
    /// Exact original selected beginning.
    pub start: u64,
    /// Exact original selected exclusive end.
    pub end: u64,
    /// Actual blocks and selected plaintext authenticated in this run.
    pub authenticated: Progress,
    /// Complete accepted sink bytes, excluding an uncertain partial chunk.
    pub delivered_bytes: u64,
    /// Complete accepted sink chunks.
    pub delivered_chunks: u64,
    /// Original attempted sink interval which did not complete.
    pub pending_delivery: Option<(u64, u64)>,
    /// A genuine selected reader completion occurred in this run. This is a
    /// diagnostic snapshot, not a constructor for an authentication receipt.
    pub selection_verified: bool,
    /// The actual original sink completion future was started.
    pub finish_started: bool,
    /// Actual current output naming disposition, separate from authentication.
    pub output: CommitStage,
    /// Actual completed destination action, absent before such an observation.
    pub destination: Option<crate::network::range::Destination>,
}
impl FileProgress {
    fn read(read: &ReadRange) -> Self {
        let verified = matches!(read.completion, Completion::Verified(_));
        Self {
            start: read.selection.start,
            end: read.selection.end,
            authenticated: read.authenticated,
            delivered_bytes: read.delivered_bytes,
            delivered_chunks: read.delivered_chunks,
            pending_delivery: None,
            selection_verified: verified,
            finish_started: read.destination == crate::network::range::Destination::SinkCompleted,
            output: CommitStage::Durable,
            destination: Some(read.destination),
        }
    }
    fn report(report: &Report) -> Self {
        Self {
            start: report.selection.start,
            end: report.selection.end,
            authenticated: report.authenticated,
            delivered_bytes: report.delivered_bytes,
            delivered_chunks: report.delivered_chunks,
            pending_delivery: report
                .pending_delivery
                .as_ref()
                .map(|range| (range.start, range.end)),
            selection_verified: report.verified.is_some(),
            finish_started: report.finish_started,
            output: CommitStage::NotLinked,
            destination: None,
        }
    }
}
pub(super) fn staging_name(id: &[u8; 32]) -> OsString {
    let mut name = String::from(".gnunet-fs-task-");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in id {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 15) as usize] as char);
    }
    name.into()
}
pub(super) struct Done {
    pub read: ReadRange,
    pub progress: TreeDownloadProgress,
}
pub(super) struct Run<'a> {
    pub state: &'a Mutex<Session>,
    pub output: &'a mut OutputDir,
    pub staging: &'a mut OutputDir,
    pub manifest: &'a Manifest,
    pub source: EndpointSource,
    pub started: Instant,
    pub deadline: AbsoluteTime,
}
fn remember_read(state: &Mutex<Session>, read: &ReadRange) -> Result<(), Cause> {
    lock(state)?.file = Some(FileProgress::read(read));
    Ok(())
}
fn remember_failure(
    state: &Mutex<Session>,
    error: &crate::ObservedFailure<Cause, ReadRange>,
) -> Result<(), Cause> {
    let mut progress = error.receipt.as_ref().map(FileProgress::read);
    if progress.is_none()
        && let Some(Error::Range(error)) = &error.operation
    {
        progress = Some(FileProgress::report(&error.report));
    }
    if let Some(mut progress) = progress {
        progress.output = error.stage;
        lock(state)?.file = Some(progress);
    }
    Ok(())
}
fn binding(manifest: &Manifest) -> Result<EntryBinding, Cause> {
    let content = manifest.root_content()?;
    Ok(EntryBinding {
        id: root_id(content),
        parent: None,
        path: manifest.relative.clone(),
        kind: gnunet_fs::directory::walk::Kind::File,
        content,
    })
}
fn clean(
    state: &Mutex<Session>,
    staging: &OutputDir,
    id: [u8; 64],
    temporary: &TempFact,
    stage: CommitStage,
) -> Result<(), Cause> {
    staging.cleanup_recorded_temp(
        std::path::Path::new(&temporary.name),
        temporary.parent,
        temporary.identity,
    )?;
    lock(state)?.append(Event::Cleanup {
        id,
        success: true,
        stage,
    })
}
fn record(
    state: &Mutex<Session>,
    binding: &EntryBinding,
    observation: OutputObservation<'_, ReadRange>,
) -> Result<(), Cause> {
    let mut session = lock(state)?;
    let check = |temporary: crate::output::TempRecord<'_>| {
        if temporary.content != binding.content || Some(temporary.parent) != session.state.root {
            Err(Cause::State(
                "file output differs from its original staging/content",
            ))
        } else {
            Ok(())
        }
    };
    match observation {
        OutputObservation::TempOwned(temporary) => {
            check(temporary)?;
            session.append(Event::TempOwned {
                binding: binding.clone(),
                temporary: TempFact {
                    parent: temporary.parent,
                    identity: temporary.identity,
                    name: temporary.name.to_owned(),
                },
            })
        }
        OutputObservation::CommitIntent {
            temporary,
            final_name,
            final_parent,
        } => {
            check(temporary)?;
            if binding.path.file_name() != Some(final_name)
                || Some(final_parent) != session.state.file_parent
            {
                return Err(Cause::State(
                    "file commit differs from original target parent/name",
                ));
            }
            session.append(Event::CommitIntent { id: binding.id })
        }
        OutputObservation::FileCommitted {
            temporary,
            final_name,
            final_parent,
            identity,
            receipt,
        } => {
            check(temporary)?;
            let RootMode::File { selection } = &session.state.manifest.mode else {
                return Err(Cause::State("file observer has directory manifest"));
            };
            if binding.path.file_name() != Some(final_name)
                || Some(final_parent) != session.state.file_parent
                || receipt.content != binding.content
                || &receipt.selection != selection
            {
                return Err(Cause::State(
                    "file receipt differs from original interval/target",
                ));
            }
            session.new_files += 1;
            session.file = Some(FileProgress::read(&receipt));
            session.append(Event::FileCommitted {
                id: binding.id,
                identity,
            })
        }
        OutputObservation::Cleanup {
            temporary,
            stage,
            outcome,
        } => {
            check(temporary)?;
            session.append(Event::Cleanup {
                id: binding.id,
                success: outcome.is_ok(),
                stage,
            })
        }
    }
}
fn checkpoint(
    clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
    deadline: AbsoluteTime,
    hard: Instant,
) -> Result<(), Error> {
    if Instant::now() >= hard || clock.sample()?.now >= deadline {
        return Err(ProtocolError::Deadline.into());
    }
    Ok(())
}
impl Run<'_> {
    pub(super) async fn run(
        &mut self,
        buffers: &mut Buffers,
        cache: &mut Repository,
        mut control: impl FnMut(TreeDownloadProgress) -> Control,
    ) -> Result<Done, Box<driver::Failure<Cause>>> {
        let mut interruption = None;
        let progress = TreeDownloadProgress::default();
        let result = async {
            let binding = binding(self.manifest)?;
            let RootMode::File { selection } = &self.manifest.mode else {
                return Err(Cause::State("file runner requires file root"));
            };
            let clock = self.source.clock();
            let now = clock.sample().map_err(Error::from)?.now;
            if self.deadline.is_never() || now >= self.deadline {
                return Err(Cause::Operation(ProtocolError::Deadline.into()));
            }
            let remaining = self
                .deadline
                .as_micros()
                .checked_sub(now.as_micros())
                .ok_or_else(|| Error::from(ProtocolError::Deadline))?;
            let hard = self
                .started
                .checked_add(Duration::from_micros(remaining))
                .ok_or_else(|| Error::from(ProtocolError::Overflow))?;
            checkpoint(clock.as_ref(), self.deadline, hard)?;
            let (known, parent, stage) = {
                let session = lock(self.state)?;
                (
                    session
                        .state
                        .entry(&binding)?
                        .cloned()
                        .ok_or(Cause::State("file root missing"))?,
                    session
                        .state
                        .file_parent
                        .ok_or(Cause::State("file parent not attached"))?,
                    session
                        .state
                        .root
                        .ok_or(Cause::State("file stage not attached"))?,
                )
            };
            if self.output.identity()? != parent || self.staging.identity()? != stage {
                return Err(Cause::State("file parent/stage descriptor changed"));
            }
            let state = self.state;
            let mut guarded = |authenticated: Progress| {
                if let Ok(mut session) = lock(state) {
                    session.file = Some(FileProgress {
                        start: selection.start,
                        end: selection.end,
                        authenticated,
                        delivered_bytes: 0,
                        delivered_chunks: 0,
                        pending_delivery: None,
                        selection_verified: false,
                        finish_started: false,
                        output: CommitStage::NotLinked,
                        destination: None,
                    });
                }
                match checkpoint(clock.as_ref(), self.deadline, hard) {
                    Ok(()) => control(progress),
                    Err(error) => {
                        interruption = Some(error);
                        Control::Cancel
                    }
                }
            };
            let mut recovered = None;
            if let Some(identity) = known.committed {
                if let Some(temp) = known.temporary.as_ref().filter(|_| !known.cleanup) {
                    clean(state, self.staging, binding.id, temp, CommitStage::Durable)?;
                }
                let verified = self
                    .output
                    .revalidate_range(
                        &binding.path,
                        binding.content,
                        selection.clone(),
                        identity,
                        Some(parent),
                        buffers,
                        cache,
                        self.manifest.options.transfer.limits,
                        &mut guarded,
                    )
                    .map_err(Cause::RangeRevalidate)?;
                lock(state)?.revalidated += 1;
                recovered = Some(verified.read);
            } else if let Some(temp) = &known.temporary {
                match self.output.inspect_file(&binding.path)? {
                    Some(identity) => {
                        if !known.intent || identity != temp.identity {
                            return Err(Cause::Reconcile {
                                path: binding.path.clone(),
                                reason: "file final name differs from original commit inode",
                            });
                        }
                        let verified = self
                            .output
                            .revalidate_range(
                                &binding.path,
                                binding.content,
                                selection.clone(),
                                identity,
                                Some(parent),
                                buffers,
                                cache,
                                self.manifest.options.transfer.limits,
                                &mut guarded,
                            )
                            .map_err(Cause::RangeRevalidate)?;
                        lock(state)?.revalidated += 1;
                        if let Err(cause) = lock(state)?.append(Event::FileCommitted {
                            id: binding.id,
                            identity,
                        }) {
                            return Err(Cause::RangeCommitted(Box::new(RangeCommitFailure {
                                identity,
                                receipt: verified.read,
                                cause: Box::new(cause),
                            })));
                        }
                        if let Err(cause) =
                            clean(state, self.staging, binding.id, temp, CommitStage::Durable)
                        {
                            return Err(Cause::RangeCommitted(Box::new(RangeCommitFailure {
                                identity,
                                receipt: verified.read,
                                cause: Box::new(cause),
                            })));
                        }
                        recovered = Some(verified.read);
                    }
                    None => {
                        clean(state, self.staging, binding.id, temp, known.stage)?;
                        lock(state)?.append(Event::ResetPending { id: binding.id })?;
                    }
                }
            }
            let read = if let Some(read) = recovered {
                read
            } else {
                let mut options = self.manifest.options.transfer;
                options.deadline = self.deadline;
                let result = self
                    .output
                    .download_range_observed(
                        &binding.path,
                        self.staging,
                        self.source
                            .duplicate()
                            .map_err(crate::network::Error::from)
                            .map_err(Error::from)?,
                        binding.content,
                        selection.clone(),
                        buffers,
                        Some(cache),
                        crate::network::range::Options {
                            download: options,
                            native_deadline: hard,
                        },
                        &mut guarded,
                        |event| record(state, &binding, event),
                    )
                    .await;
                match result {
                    Ok(read) => read,
                    Err(mut error) => {
                        if let Err(cause) = remember_failure(state, &error)
                            && error.observer.is_none()
                        {
                            error.observer = Some(cause);
                        }
                        // A cancelled pre-link operation may have durably logged
                        // its intent. Clear it only after actual final absence.
                        if error.stage == CommitStage::NotLinked
                            && error.observer.is_none()
                            && error.cleanup.is_none()
                            && lock(state)?
                                .state
                                .entry(&binding)?
                                .is_some_and(|e| e.intent && e.committed.is_none() && e.cleanup)
                        {
                            let settled = match self.output.inspect_file(&binding.path) {
                                Ok(None) => {
                                    lock(state)?.append(Event::ResetPending { id: binding.id })
                                }
                                Ok(Some(_)) => Err(Cause::Reconcile {
                                    path: binding.path.clone(),
                                    reason: "file final appeared before original link",
                                }),
                                Err(error) => Err(error.into()),
                            };
                            if let Err(cause) = settled {
                                error.observer = Some(cause);
                            }
                        }
                        return Err(Cause::RangeOutput(error));
                    }
                }
            };
            remember_read(state, &read)?;
            Ok(read)
        }
        .await;
        match result {
            Ok(read) => Ok(Done { read, progress }),
            Err(cause) => Err(Box::new(driver::Failure {
                path: self.manifest.relative.clone(),
                progress,
                walk: None,
                cause,
                interruption,
                namespace_cleanup: None,
            })),
        }
    }
}
