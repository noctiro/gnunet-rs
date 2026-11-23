//! Independent file transfers admitted by the original verified tree walk.
use super::{
    TreeDownloadProgress, TreeFileFailure, inline::inline_blocks, namespace::checkpoint,
    paths::Paths,
};
use crate::{
    Buffers, Control, Error, IncompleteOutput, OutputDir, ReadFile, Result,
    network::{self, DownloadOptions},
    output::TemporaryNames,
};
use gnunet_client_host::EndpointSource;
use gnunet_fs::directory::walk::{AttemptId, FileWork, Walk};
use gnunet_types::AbsoluteTime;
use std::{
    future::{Future, poll_fn},
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
};

pub(super) struct Files<'a> {
    pub output: &'a OutputDir,
    pub parent: &'a OutputDir,
    pub source: &'a EndpointSource,
    pub relative: &'a Path,
    pub transfer: DownloadOptions,
    pub slots: NonZeroU32,
    pub next_temporary: &'a AtomicU64,
    pub incomplete: Option<IncompleteOutput>,
}

#[derive(Clone, Copy)]
enum FileOutput<'a> {
    Atomic(TemporaryNames<'a>),
    Reopen(IncompleteOutput),
}

pub(super) struct Status<'a> {
    pub progress: &'a mut TreeDownloadProgress,
    pub last: &'a mut Option<AbsoluteTime>,
    pub path: &'a mut PathBuf,
    pub interruption: &'a mut Option<Error>,
    pub file_failures: &'a mut Vec<TreeFileFailure>,
}

impl Files<'_> {
    pub(super) async fn run<'scope>(
        &self,
        owner: &mut Walk<'scope>,
        paths: &mut Paths,
        status: Status<'_>,
        control: &mut impl FnMut(TreeDownloadProgress) -> Control,
    ) -> Result<()> {
        let Some(first) = owner.begin_file()? else {
            return Ok(());
        };
        let mut first = Some(first);
        let mut stage = match self
            .incomplete
            .is_none()
            .then(|| self.parent.stage_next_to(self.relative))
            .transpose()
        {
            Ok(stage) => stage,
            Err(error) => {
                owner.cancel();
                if let Some(first) = first {
                    owner.cancelled(first.id)?;
                }
                *status.path = self.relative.to_owned();
                return Err(error);
            }
        };
        let stop = AtomicBool::new(false);
        let file_output = match (stage.as_ref(), self.incomplete) {
            (Some(stage), None) => FileOutput::Atomic(TemporaryNames::in_stage(
                &stage.directory,
                self.next_temporary,
            )),
            (None, Some(incomplete)) => FileOutput::Reopen(incomplete),
            _ => return Err(Error::Corrupt),
        };
        let mut active = Vec::new();
        let mut free = Vec::new();
        let mut primary = None;
        let mut more = true;
        // Partition the one global request cap across file workers. A lone
        // lookup and its optional reorder window both consume this same share.
        let per_file = NonZeroU32::new(self.transfer.request_parallelism.get() / self.slots.get())
            .ok_or(Error::Corrupt)?;
        loop {
            while primary.is_none() && more && active.len() < self.slots.get() as usize {
                let admitted = (|| {
                    let work = if first.is_some() {
                        first.take()
                    } else {
                        owner.begin_file()?
                    };
                    let Some(work) = work else {
                        return Ok(None);
                    };
                    let job = paths
                        .jobs
                        .get_mut(owner.ordinal(work.id.task())?)
                        .ok_or(Error::Corrupt)?;
                    Ok::<_, Error>(Some((
                        work,
                        job.path.clone(),
                        job.target,
                        job.inline.take(),
                    )))
                })();
                match admitted {
                    Ok(Some((work, path, target, inline))) => {
                        let mut transfer = self.transfer;
                        transfer.target = target;
                        transfer.request_parallelism = per_file;
                        let inputs = File {
                            original: work,
                            path,
                            transfer,
                            hint: inline,
                            last: *status.last,
                        };
                        active.push(Box::pin(inputs.receive(
                            self.output,
                            self.source,
                            file_output,
                            free.pop().unwrap_or_else(Buffers::new),
                            &stop,
                        )));
                    }
                    Ok(None) => more = false,
                    Err(error) => {
                        owner.cancel();
                        stop.store(true, Ordering::Relaxed);
                        primary = Some(error);
                    }
                }
            }
            if active.is_empty() {
                drop(active);
                if let Some(stage) = stage.as_mut()
                    && let Err(error) = stage.cleanup()
                {
                    let cause = Error::from(error);
                    if primary.is_none() {
                        *status.path = self.relative.to_owned();
                        primary = Some(cause);
                    } else {
                        status.file_failures.push(TreeFileFailure {
                            path: self.relative.to_owned(),
                            cause,
                        });
                    }
                }
                return primary.map_or(Ok(()), Err);
            }

            let (index, done) = poll_fn(|cx| {
                if primary.is_none()
                    && let Err(error) = checkpoint(
                        self.source,
                        &self.transfer,
                        status.last,
                        *status.progress,
                        control,
                    )
                {
                    *status.interruption = Some(error);
                    primary = Some(Error::Cancelled);
                    owner.cancel();
                    stop.store(true, Ordering::Relaxed);
                }
                for (index, file) in active.iter_mut().enumerate() {
                    if let Poll::Ready(done) = file.as_mut().poll(cx) {
                        return Poll::Ready((index, done));
                    }
                }
                Poll::Pending
            })
            .await;
            drop(active.swap_remove(index));
            free.push(done.buffers);
            if done.result.is_ok() || matches!(&done.result, Err(Error::CleanupAfterCommit { .. }))
            {
                status.progress.files_committed += 1;
                status.progress.file_bytes += u128::from(done.size);
            }
            let read = if let Some(interruption) = done.interruption
                && primary.is_none()
            {
                *status.interruption = Some(interruption);
                done.result.and(Err(Error::Cancelled))
            } else {
                done.result
            };
            let result = read.and_then(|read| {
                owner
                    .finish_file(done.id, read.verified)
                    .map_err(Error::from)
            });
            if let Err(error) = result {
                if primary.is_none() {
                    *status.path = self.relative.join(done.path.as_ref());
                    primary = Some(error);
                    owner.cancel();
                    stop.store(true, Ordering::Relaxed);
                } else if !cancelled(&error) {
                    status.file_failures.push(TreeFileFailure {
                        path: self.relative.join(done.path.as_ref()),
                        cause: error,
                    });
                }
                if let Err(error) = owner.cancelled(done.id) {
                    status.file_failures.push(TreeFileFailure {
                        path: self.relative.join(done.path.as_ref()),
                        cause: error.into(),
                    });
                }
            }
        }
    }
}

fn cancelled(error: &Error) -> bool {
    matches!(error, Error::Cancelled)
        || matches!(error, Error::Transfer(error) if matches!(error.as_ref(), network::Error::Cancelled(_)))
}

struct File<'scope> {
    original: FileWork<'scope>,
    path: Arc<PathBuf>,
    transfer: DownloadOptions,
    hint: Option<Vec<u8>>,
    last: Option<AbsoluteTime>,
}

struct Completion<'scope> {
    id: AttemptId<'scope>,
    path: Arc<PathBuf>,
    size: u64,
    result: Result<ReadFile>,
    buffers: Buffers,
    interruption: Option<Error>,
}

impl<'scope> File<'scope> {
    async fn receive(
        self,
        output: &OutputDir,
        source: &EndpointSource,
        file_output: FileOutput<'_>,
        mut buffers: Buffers,
        stop: &AtomicBool,
    ) -> Completion<'scope> {
        let mut last = self.last;
        let mut interruption = None;
        let mut control = |_| {
            if stop.load(Ordering::Relaxed) || interruption.is_some() {
                return Control::Cancel;
            }
            match checkpoint(
                source,
                &self.transfer,
                &mut last,
                TreeDownloadProgress::default(),
                &mut |_| Control::Continue,
            ) {
                Ok(()) => Control::Continue,
                Err(error) => {
                    interruption = Some(error);
                    Control::Cancel
                }
            }
        };
        let content = self.original.content;
        let result = async {
            if stop.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let mut output = output.duplicate()?;
            let mut inline = inline_blocks(
                &mut buffers,
                content,
                self.hint,
                self.transfer.limits,
                &mut control,
            )?;
            match file_output {
                FileOutput::Atomic(temporary) => {
                    output
                        .download_tree_file(
                            self.path.as_ref(),
                            source,
                            content,
                            &mut buffers,
                            None,
                            self.transfer,
                            inline.as_mut(),
                            temporary,
                            &mut control,
                        )
                        .await
                }
                FileOutput::Reopen(incomplete) => {
                    output
                        .download_resumable_with(
                            self.path.as_ref(),
                            source.duplicate().map_err(network::Error::from)?,
                            content,
                            &mut buffers,
                            self.transfer,
                            incomplete,
                            inline.as_mut(),
                            &mut control,
                        )
                        .await
                }
            }
        }
        .await;
        Completion {
            id: self.original.id,
            path: self.path,
            size: content.size,
            result,
            buffers,
            interruption,
        }
    }
}
