//! Existing immediate extraction policy over the shared tree traversal.
use super::{TreeDownloadOptions, TreeDownloadProgress, driver, inline::InlineBlocks, paths::Job};
use crate::{Buffers, Control, Error, OutputDir, ReadFile, Repository};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{Content, Namespace};
use gnunet_types::AbsoluteTime;
use std::path::Path;

pub(super) struct Target<'a> {
    parent: &'a mut OutputDir,
    relative: &'a Path,
    output: Option<OutputDir>,
}
impl<'a> Target<'a> {
    pub(super) fn new(parent: &'a mut OutputDir, relative: &'a Path) -> Self {
        Self {
            parent,
            relative,
            output: None,
        }
    }
    fn output(&mut self) -> Result<&mut OutputDir, Error> {
        self.output.as_mut().ok_or(Error::Corrupt)
    }
}
impl driver::Target for Target<'_> {
    type Failure = Error;
    fn begin(&mut self) -> Result<bool, Error> {
        self.output = Some(self.parent.create_directory(self.relative)?);
        Ok(true)
    }
    fn directory(&mut self, job: &Job, _content: Content) -> Result<bool, Error> {
        self.output()?.create_directory(job.path.as_ref())?;
        Ok(true)
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
    ) -> Result<ReadFile, Error> {
        match inline {
            Some(blocks) => self.output()?.write_file(
                job.path.as_ref(),
                blocks,
                content,
                buffers,
                options.limits,
                control,
            ),
            None => {
                self.output()?
                    .download_file(
                        job.path.as_ref(),
                        source.duplicate().map_err(super::super::Error::from)?,
                        content,
                        buffers,
                        cache,
                        options,
                        control,
                    )
                    .await
            }
        }
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
        self.output()?.sync_directory()
    }
}
