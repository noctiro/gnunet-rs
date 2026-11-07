//! One retained source-authenticated traversal shared by immediate and durable output.
use super::inline::{InlineBlocks, inline_blocks};
use super::namespace::checkpoint;
use super::paths::{Job, Paths, root_id};
use super::{DownloadedTree, TreeDownloadOptions, TreeDownloadProgress};
use crate::{Buffers, Control, Error, ReadFile, Repository};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content, Namespace,
    directory::{VerifiedDirectory, VerifiedEntry, walk},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(crate) struct Failure<E> {
    pub path: PathBuf,
    pub progress: TreeDownloadProgress,
    pub walk: Option<walk::Summary>,
    pub cause: E,
    pub interruption: Option<Error>,
    pub namespace_cleanup: Option<crate::search::Error>,
}
#[expect(
    clippy::too_many_arguments,
    reason = "Shared native traversal keeps runtime, source proof, output and cancellation ports explicit"
)]
pub(crate) trait Target {
    type Failure: From<Error>;
    fn begin(&mut self) -> Result<bool, Self::Failure>;
    fn directory(&mut self, job: &Job, content: Content) -> Result<bool, Self::Failure>;
    fn directory_verified(
        &mut self,
        _job: &Job,
        _receipt: VerifiedDirectory,
    ) -> Result<(), Self::Failure> {
        Ok(())
    }
    async fn file(
        &mut self,
        job: &Job,
        content: Content,
        source: &EndpointSource,
        buffers: &mut Buffers,
        cache: Option<&mut Repository>,
        options: super::super::DownloadOptions,
        inline: Option<&mut InlineBlocks>,
        control: &mut impl FnMut(crate::Progress) -> Control,
    ) -> Result<ReadFile, Self::Failure>;
    async fn namespace(
        &mut self,
        job: &Job,
        source: &EndpointSource,
        namespace: Namespace<'_>,
        options: TreeDownloadOptions,
        progress: TreeDownloadProgress,
        last: &mut Option<AbsoluteTime>,
        control: &mut impl FnMut(TreeDownloadProgress) -> Control,
        cleanup: &mut Option<crate::search::Error>,
    ) -> Result<(Content, [u8; 32]), Self::Failure>;
    fn known_commit(error: &Self::Failure) -> bool;
    fn finish(&mut self) -> Result<(), Self::Failure>;
}
fn retain_interruption<T, E: From<Error>>(
    result: Result<T, E>,
    guard: &mut Option<Error>,
    interruption: &mut Option<Error>,
) -> Result<T, E> {
    if let Some(error) = guard.take() {
        *interruption = Some(error);
        return result.and(Err(Error::Cancelled.into()));
    }
    result
}
#[expect(
    clippy::too_many_arguments,
    reason = "Shared native traversal owns independent endpoint, output, cache and cancellation"
)]
pub(crate) async fn run<T: Target>(
    target: &mut T,
    relative: &Path,
    source: EndpointSource,
    content: Content,
    buffers: &mut Buffers,
    mut cache: Option<&mut Repository>,
    options: TreeDownloadOptions,
    mut control: impl FnMut(TreeDownloadProgress) -> Control,
) -> Result<DownloadedTree, Box<Failure<T::Failure>>> {
    let mut failed_path = relative.to_path_buf();
    let mut progress = TreeDownloadProgress::default();
    let mut summary = None;
    let mut cleanup = None;
    let mut interruption = None;
    let result: std::result::Result<walk::Summary, T::Failure> = async {
        if options.transfer.deadline.as_micros() == u64::MAX
            || options.namespace.queries == 0
            || options.namespace.queries > 64
            || options.namespace.results == 0
        {
            return Err(Error::from(ProtocolError::InvalidInput).into());
        }
        let capacity = options.max_entries.checked_add(1).ok_or(Error::Limit)?;
        let mut slots = Vec::new();
        crate::resize(&mut slots, capacity, walk::Slot::empty())?;
        let mut names = Vec::new();
        crate::resize(&mut names, options.max_namespace_bytes, 0)?;
        let mut identity = walk::Instance::new();
        let mut owner = walk::Walk::new(
            &mut identity,
            &mut slots,
            &mut names,
            content,
            walk::Kind::Directory,
            walk::Limits {
                max_depth: options.max_depth,
                max_entries: options.max_entries,
                max_total_bytes: options.max_total_bytes,
                max_queued: capacity,
                shared: walk::SharedPolicy::VisitAgain,
                cycles: walk::CyclePolicy::Reject,
            },
        )
        .map_err(Error::from)?;
        let mut paths = Paths {
            jobs: Vec::new(),
            names: BTreeSet::new(),
            path_bytes: 0,
            inline_bytes: 0,
        };
        paths.jobs.try_reserve(1).map_err(|_| Error::Limit)?;
        paths.jobs.push(Job {
            path: Arc::new(PathBuf::new()),
            target: options.transfer.target,
            inline: None,
            id: root_id(content),
            parent: None,
            kind: walk::Kind::Directory,
        });
        let mut last = None;
        checkpoint(
            &source,
            options.transfer.deadline,
            &mut last,
            progress,
            &mut control,
        )?;
        progress.root_created = target.begin()?;
        progress.directories_created = usize::from(progress.root_created);
        let job_result: std::result::Result<(), T::Failure> = async {
            while let Some(work) = owner.begin().map_err(Error::from)? {
                let index = owner.ordinal(work.id.task()).map_err(Error::from)?;
                let path = paths.jobs.get(index).ok_or(Error::Corrupt)?.path.clone();
                failed_path = relative.join(path.as_ref());
                checkpoint(
                    &source,
                    options.transfer.deadline,
                    &mut last,
                    progress,
                    &mut control,
                )?;
                let content = match work.request {
                    walk::Request::Content(content) => content,
                    walk::Request::Namespace(key) => {
                        let identifier =
                            owner.namespace_identifier(work.id).map_err(Error::from)?;
                        let (content, peer) = target
                            .namespace(
                                &paths.jobs[index],
                                &source,
                                Namespace::new(key, identifier).map_err(Error::from)?,
                                options,
                                progress,
                                &mut last,
                                &mut control,
                                &mut cleanup,
                            )
                            .await?;
                        owner
                            .resolve_namespace(work.id, content)
                            .map_err(Error::from)?;
                        paths.jobs[index].target = peer;
                        continue;
                    }
                };
                let mut guard_error = None;
                let inline = {
                    let mut guarded = |_| match checkpoint(
                        &source,
                        options.transfer.deadline,
                        &mut last,
                        progress,
                        &mut control,
                    ) {
                        Ok(()) => Control::Continue,
                        Err(error) => {
                            guard_error = Some(error);
                            Control::Cancel
                        }
                    };
                    inline_blocks(
                        buffers,
                        content,
                        paths.jobs[index].inline.take(),
                        options.transfer.limits,
                        &mut guarded,
                    )
                };
                let mut inline = retain_interruption(inline, &mut guard_error, &mut interruption)?;
                let mut transfer = options.transfer;
                transfer.target = paths.jobs[index].target;
                if work.kind == walk::Kind::Directory {
                    if index != 0 && target.directory(&paths.jobs[index], content)? {
                        progress.directories_created += 1;
                    }
                    let mut visit = |entry: VerifiedEntry<'_>| {
                        paths.admit(&mut owner, work.id, path.as_ref(), entry, options)
                    };
                    // The inline encoder may have used guard_error; create a
                    // fresh borrowing control for this actual read.
                    let mut guarded = |_| match checkpoint(
                        &source,
                        options.transfer.deadline,
                        &mut last,
                        progress,
                        &mut control,
                    ) {
                        Ok(()) => Control::Continue,
                        Err(error) => {
                            guard_error = Some(error);
                            Control::Cancel
                        }
                    };
                    let read = match inline.as_mut() {
                        Some(blocks) => buffers.visit_directory_controlled(
                            blocks,
                            content,
                            transfer.limits,
                            options.directory,
                            &mut guarded,
                            &mut visit,
                        ),
                        None => buffers
                            .download_directory(
                                source
                                    .duplicate()
                                    .map_err(super::super::Error::from)
                                    .map_err(Error::from)?,
                                content,
                                cache.as_deref_mut(),
                                transfer,
                                options.directory,
                                &mut guarded,
                                &mut visit,
                            )
                            .await
                            .map_err(Error::from),
                    };
                    let receipt = retain_interruption(read, &mut guard_error, &mut interruption)
                        .map_err(T::Failure::from)?;
                    target.directory_verified(&paths.jobs[index], receipt)?;
                    owner
                        .finish_directory(work.id, receipt)
                        .map_err(Error::from)?;
                    progress.directories_verified += 1;
                } else {
                    let mut guarded = |_| match checkpoint(
                        &source,
                        options.transfer.deadline,
                        &mut last,
                        progress,
                        &mut control,
                    ) {
                        Ok(()) => Control::Continue,
                        Err(error) => {
                            guard_error = Some(error);
                            Control::Cancel
                        }
                    };
                    let read = target
                        .file(
                            &paths.jobs[index],
                            content,
                            &source,
                            buffers,
                            cache.as_deref_mut(),
                            transfer,
                            inline.as_mut(),
                            &mut guarded,
                        )
                        .await;
                    // A known commit remains known if temporary cleanup failed.
                    if read.is_ok() || read.as_ref().is_err_and(|error| T::known_commit(error)) {
                        progress.files_committed += 1;
                        progress.file_bytes += u128::from(content.size);
                    }
                    owner
                        .finish_file(
                            work.id,
                            retain_interruption(read, &mut guard_error, &mut interruption)?
                                .verified,
                        )
                        .map_err(Error::from)?;
                }
            }
            checkpoint(
                &source,
                options.transfer.deadline,
                &mut last,
                progress,
                &mut control,
            )?;
            target.finish()?;
            Ok(())
        }
        .await;
        summary = Some(owner.summary());
        job_result?;
        owner.completion().ok_or_else(|| Error::Corrupt.into())
    }
    .await;
    match result {
        Ok(walk) => Ok(DownloadedTree { progress, walk }),
        Err(cause) => Err(Box::new(Failure {
            path: failed_path,
            progress,
            walk: summary,
            cause,
            interruption,
            namespace_cleanup: cleanup,
        })),
    }
}
