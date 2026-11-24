//! Explicit GNUnet incomplete-file retention at the caller-selected output name.
use super::{OutputDir, components, existing::Stamp, invalid_name};
use crate::{
    Buffers, Control, Error, Progress, ReadFile, Result,
    network::{self, DownloadOptions},
};
use gnunet_client_host::EndpointSource;
use gnunet_fs::Content;
use gnunet_native::filesystem::{self, Directory};
use std::{ffi::OsStr, fs::File, io, path::Path};

/// Settlement of an incomplete, explicitly selected standalone download file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompleteOutput {
    /// Keep the authenticated blocks for a later invocation.
    Keep,
    /// Remove the original incomplete output on a settled failure or cancellation.
    Delete,
}

struct Output<'a> {
    parent: Directory,
    name: &'a OsStr,
    file: File,
    existing: Option<Stamp>,
}
impl<'a> Output<'a> {
    fn open(parent: Directory, name: &'a OsStr) -> Result<Self> {
        let (file, reopened) = match parent.create_private_file(name) {
            Ok(file) => (file, false),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let file = parent.open_file_for_update(name)?;
                (file, true)
            }
            Err(error) => return Err(error.into()),
        };
        file.try_lock().map_err(io::Error::from)?;
        let existing = reopened.then(|| Stamp::file(&file)).transpose()?;
        let output = Self {
            parent,
            name,
            file,
            existing,
        };
        output.check()?;
        Ok(output)
    }

    fn check(&self) -> io::Result<()> {
        if self.parent.same_file(self.name, &self.file)? && filesystem::file_links(&self.file)? == 1
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original single-link download output changed",
            ))
        }
    }

    fn finish(&self, content: Content, mut read: ReadFile) -> Result<ReadFile> {
        let commit = || {
            self.file.set_len(content.size)?;
            self.file.sync_all()?;
            self.check()?;
            let sync = self.parent.sync()?;
            self.check()?;
            Ok::<_, io::Error>(sync)
        };
        read.directory_sync = Some(commit().map_err(|source| Error::CommitUnknown {
            query: content.query,
            source,
        })?);
        Ok(read)
    }

    fn interrupted(&self, policy: IncompleteOutput, admitted: bool, cause: Error) -> Error {
        if !admitted {
            return cause;
        }
        let settlement = match policy {
            IncompleteOutput::Keep => self.check().and_then(|()| self.file.sync_all()),
            IncompleteOutput::Delete => self
                .check()
                .and_then(|()| self.parent.remove_file(self.name, &self.file)),
        }
        .and_then(|()| self.parent.sync().map(|_| ()));
        match settlement {
            Ok(()) => cause,
            Err(source) => Error::CleanupFailed {
                cause: Box::new(cause),
                source,
            },
        }
    }
}

impl OutputDir {
    pub(crate) fn reopen_tree_directory(&mut self, relative: &Path) -> Result<(Self, bool)> {
        match self.create_directory(relative) {
            Ok(directory) => Ok((directory, true)),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                let parts = components(relative)?;
                let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
                let parent = self.parent_existing(ancestors)?;
                let root = parent.open_directory(name)?;
                root.validate_namespace()?;
                if !parent.same_directory(name, &root)? {
                    return Err(Error::SourceChanged);
                }
                Ok((Self { root, nonce: 0 }, false))
            }
            Err(error) => Err(error),
        }
    }
    /// Download into the explicit GNUnet output name and retain verified blocks
    /// in the standard partial-file layout. Reused bytes are authenticated
    /// against their original CHK before use. Successful output is truncated to
    /// the verified plaintext extent and synced. Existing files must be ordinary
    /// single-link entries. A nonempty existing file must contain matching
    /// authenticated data before it is updated. This route writes into the
    /// selected name while active. Callers exclude concurrent writers that
    /// cannot observe the native file lock.
    #[expect(
        clippy::too_many_arguments,
        reason = "The selected name, source, content, buffers, retention and control have independent ownership"
    )]
    pub async fn download_resumable(
        &mut self,
        relative: impl AsRef<Path>,
        source: EndpointSource,
        content: Content,
        buffers: &mut Buffers,
        options: DownloadOptions,
        incomplete: IncompleteOutput,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile> {
        self.download_resumable_with(
            relative.as_ref(),
            source,
            content,
            buffers,
            options,
            incomplete,
            None,
            control,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Tree file admission includes a verified inline source when available"
    )]
    pub(crate) async fn download_resumable_with(
        &mut self,
        relative: &Path,
        source: EndpointSource,
        content: Content,
        buffers: &mut Buffers,
        options: DownloadOptions,
        incomplete: IncompleteOutput,
        inline: Option<&mut network::tree_download::inline::InlineBlocks>,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile> {
        let mut transfer = network::retained::Transfer::prepare(buffers, source, content, options)?;
        let parts = components(relative)?;
        let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
        let parent = self.parent_existing(ancestors)?;
        if control(Progress::default()) == Control::Cancel {
            return Err(Error::Cancelled);
        }
        transfer.check()?;
        let output = Output::open(parent, name)?;
        let file = match output.file.try_clone() {
            Ok(file) => tokio::fs::File::from_std(file),
            Err(error) => {
                return Err(output.interrupted(
                    incomplete,
                    output.existing.is_none(),
                    error.into(),
                ));
            }
        };
        let mut blocks =
            network::retained::Blocks::new(file, output.existing.map(|stamp| stamp.bytes), inline);
        let mut stamp = output.existing;
        let read = transfer
            .run(buffers, &mut blocks, &mut control, || {
                use network::retained::ExistingFence;
                let expected = stamp.ok_or(Error::Corrupt)?;
                let observed = Stamp::file(&output.file)?;
                if observed == expected {
                    return Ok(ExistingFence::Stable);
                }
                if cfg!(target_os = "freebsd") && expected.only_ctime_changed(observed) {
                    // A deferred unlink of the staging link may advance ctime.
                    // Reauthenticate the original plaintext in the same budget.
                    stamp = Some(observed);
                    return Ok(ExistingFence::Recheck);
                }
                Err(Error::SourceChanged)
            })
            .await;
        let admitted = blocks.may_delete();
        // Retire original Tokio file work before any final truncation or unlink.
        drop(blocks.file.into_std().await);
        match read {
            Ok(mut completed) => {
                output.check()?;
                if control(completed.read.progress) == Control::Cancel {
                    return Err(output.interrupted(incomplete, admitted, Error::Cancelled));
                }
                if let Err(error) = completed.time.check() {
                    return Err(output.interrupted(incomplete, admitted, error.into()));
                }
                output.finish(content, completed.read)
            }
            Err(error) => Err(output.interrupted(incomplete, admitted, error)),
        }
    }
}
