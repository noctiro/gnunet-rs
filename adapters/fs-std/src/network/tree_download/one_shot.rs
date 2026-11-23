//! Existing immediate extraction policy over the shared tree traversal.
use super::{TreeDownloadOptions, TreeDownloadProgress, driver, inline::InlineBlocks, paths::Job};
use crate::output::TemporaryNames;
use crate::{Buffers, Control, Error, IncompleteOutput, OutputDir, ReadFile, Repository};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{Content, Namespace};
use gnunet_types::AbsoluteTime;
use std::path::Path;

pub(super) struct Target<'a> {
    parent: &'a mut OutputDir,
    relative: &'a Path,
    output: Option<OutputDir>,
    incomplete: Option<IncompleteOutput>,
}
impl<'a> Target<'a> {
    pub(super) fn new(
        parent: &'a mut OutputDir,
        relative: &'a Path,
        incomplete: Option<IncompleteOutput>,
    ) -> Self {
        Self {
            parent,
            relative,
            output: None,
            incomplete,
        }
    }
    fn output(&mut self) -> Result<&mut OutputDir, Error> {
        self.output.as_mut().ok_or(Error::Corrupt)
    }
}
impl driver::Target for Target<'_> {
    type Failure = Error;
    fn begin(&mut self) -> Result<bool, Error> {
        let (output, created) = if self.incomplete.is_some() {
            self.parent.reopen_tree_directory(self.relative)?
        } else {
            (self.parent.create_directory(self.relative)?, true)
        };
        self.output = Some(output);
        Ok(created)
    }
    fn directory(&mut self, job: &Job, _content: Content) -> Result<bool, Error> {
        if self.incomplete.is_some() {
            return Ok(self.output()?.reopen_tree_directory(job.path.as_ref())?.1);
        }
        self.output()?.create_directory(job.path.as_ref())?;
        Ok(true)
    }
    fn independent_output(&self) -> Option<(&OutputDir, &OutputDir)> {
        self.output.as_ref().map(|output| (output, &*self.parent))
    }
    fn incomplete_output(&self) -> Option<IncompleteOutput> {
        self.incomplete
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
        temporary: TemporaryNames<'_>,
        control: &mut impl FnMut(crate::Progress) -> Control,
    ) -> Result<ReadFile, Error> {
        if let Some(incomplete) = self.incomplete {
            return self
                .output()?
                .download_resumable_with(
                    job.path.as_ref(),
                    source.duplicate().map_err(super::super::Error::from)?,
                    content,
                    buffers,
                    options,
                    incomplete,
                    inline,
                    control,
                )
                .await;
        }
        self.output()?
            .download_tree_file(
                job.path.as_ref(),
                source,
                content,
                buffers,
                cache,
                options,
                inline,
                temporary,
                control,
            )
            .await
    }
    async fn namespace(
        &mut self,
        _job: &Job,
        source: &EndpointSource,
        namespace: Namespace<'_>,
        options: TreeDownloadOptions,
        progress: TreeDownloadProgress,
        last: &mut Option<AbsoluteTime>,
        control: &mut impl FnMut(TreeDownloadProgress) -> Control,
        cleanup: &mut Option<crate::search::Error>,
    ) -> Result<(Content, [u8; 32]), Error> {
        super::namespace::resolve_namespace(
            source, namespace, options, progress, last, control, cleanup,
        )
        .await
    }
    fn known_commit(error: &Error) -> bool {
        matches!(error, Error::CleanupAfterCommit { .. })
    }
    fn finish(&mut self) -> Result<(), Error> {
        self.output()?.sync_directory().map(|_| ())
    }
}
