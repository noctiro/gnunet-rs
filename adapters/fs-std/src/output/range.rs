//! Absolute-coordinate selected output and cache-backed selected revalidation.
use super::{
    FileIdentity, ObservedFailure, OutputDir, RevalidateFailure, RevalidateStage, components,
    existing::{REGULAR, Stamp},
    invalid_name,
    observed::{FinalName, OutputObservation, finish},
};
use crate::network::range::{Completion, Destination, Options, RangeSink, ReadRange};
use crate::{BlockSource, Buffers, Control, Error, Limits, Progress, Repository, Result};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content,
    content::{RangeReader, VerifiedChunk},
};
use nix::{fcntl::openat, sys::stat::Mode};
use std::{fs::File, io, ops::Range, os::unix::fs::FileExt, path::Path};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

/// Actual selected authentication and output barriers, never a VerifiedFile.
#[derive(Clone, Debug)]
pub struct RevalidatedRange {
    /// Selected cache bytes were authenticated and compared at absolute offsets.
    pub read: ReadRange,
    /// Exact held final inode.
    pub identity: FileIdentity,
    /// Actual final parent whose naming barrier was refreshed.
    pub parent: FileIdentity,
}
/// Original refusal, actual phase and independently obtained selected receipt.
pub type RevalidateRangeFailure = RevalidateFailure<ReadRange>;

struct SparseWriter {
    file: tokio::fs::File,
}
impl RangeSink for SparseWriter {
    async fn chunk(
        &mut self,
        chunk: VerifiedChunk<'_>,
    ) -> std::result::Result<(), crate::network::Error> {
        self.file
            .seek(io::SeekFrom::Start(chunk.range().start))
            .await?;
        self.file.write_all(chunk.bytes()).await?;
        Ok(())
    }
    async fn finish(&mut self) -> std::result::Result<(), crate::network::Error> {
        self.file.flush().await?;
        Ok(())
    }
}
impl OutputDir {
    /// Download an exact range at its absolute file coordinates into a private
    /// marked staging directory. The final sparse extent is the CHK file size;
    /// unselected bytes receive no authentication claim. Both directories remain
    /// held by descriptors. The same physical finalizer serves whole-file output.
    #[expect(
        clippy::too_many_arguments,
        reason = "Staging ownership, final name, original selection and transfer policy remain explicit"
    )]
    pub(crate) async fn download_range_observed<E>(
        &mut self,
        relative: impl AsRef<Path>,
        staging: &mut OutputDir,
        source: EndpointSource,
        content: Content,
        selection: Range<u64>,
        buffers: &mut Buffers,
        cache: Option<&mut Repository>,
        options: Options,
        mut control: impl FnMut(Progress) -> Control,
        mut observer: impl for<'a> FnMut(OutputObservation<'a, ReadRange>) -> std::result::Result<(), E>,
    ) -> std::result::Result<ReadRange, Box<ObservedFailure<E, ReadRange>>> {
        if selection.start > selection.end || selection.end > content.size {
            return Err(ObservedFailure::operation(invalid_name()));
        }
        buffers
            .prepare(content, options.download.limits)
            .map_err(ObservedFailure::operation)?;
        let parts = components(relative.as_ref()).map_err(ObservedFailure::operation)?;
        let (name, ancestors) = parts
            .split_last()
            .ok_or_else(invalid_name)
            .map_err(ObservedFailure::operation)?;
        let parent = self
            .parent_existing(ancestors)
            .map_err(ObservedFailure::operation)?;
        super::ensure_absent(&parent, name).map_err(ObservedFailure::operation)?;
        let parent_id = FileIdentity::of(&parent)
            .map_err(Error::from)
            .map_err(ObservedFailure::operation)?;
        let staging_parent = staging
            .root
            .try_clone()
            .map_err(Error::from)
            .map_err(ObservedFailure::operation)?;
        let staging_id = FileIdentity::of(&staging_parent)
            .map_err(Error::from)
            .map_err(ObservedFailure::operation)?;
        if staging_id.device != parent_id.device {
            return Err(ObservedFailure::operation(invalid_name()));
        }
        let mut temporary = staging
            .temporary(&staging_parent, name)
            .map_err(ObservedFailure::operation)?;
        let observer_error = observer(OutputObservation::TempOwned(
            temporary.record(staging_id, content),
        ))
        .err();
        let result = if observer_error.is_none() {
            Some(
                async {
                    temporary.file.set_len(content.size)?;
                    let mut sink = SparseWriter {
                        file: tokio::fs::File::from_std(temporary.file.try_clone()?),
                    };
                    let transfer = buffers
                        .download_range_to(
                            source,
                            content,
                            selection,
                            &mut sink,
                            cache,
                            options,
                            &mut control,
                        )
                        .await;
                    // A cancelled/failed original chunk can still own native file
                    // work. Drain that owner before sync, link or exact cleanup.
                    drop(sink.file.into_std().await);
                    transfer.map_err(Error::from)
                }
                .await,
            )
        } else {
            None
        };
        finish(
            &mut temporary,
            FinalName {
                parent: &parent,
                identity: parent_id,
                name,
            },
            staging_id,
            content,
            result,
            observer_error,
            &mut control,
            &mut observer,
        )
    }

    /// Authenticate the original selection from actual cached encrypted blocks
    /// and compare each selected plaintext chunk with the held final file at its
    /// absolute offset. Never re-encode unselected sparse bytes or trust saved
    /// progress. Empty selection in a nonempty file retains EmptySelection and
    /// no authentication/flush receipt; physical barriers are separate facts.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original content, selection, inode, parent, bounded cache and control retain independent provenance"
    )]
    pub fn revalidate_range(
        &self,
        relative: impl AsRef<Path>,
        content: Content,
        selection: Range<u64>,
        expected_identity: FileIdentity,
        expected_parent: Option<FileIdentity>,
        buffers: &mut Buffers,
        cache: &mut Repository,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
    ) -> std::result::Result<RevalidatedRange, Box<RevalidateRangeFailure>> {
        let mut stage = RevalidateStage::Unopened;
        let mut identity = None;
        let mut receipt = None;
        let result = (|| -> Result<RevalidatedRange> {
            if selection.start > selection.end || selection.end > content.size {
                return Err(invalid_name());
            }
            buffers.prepare(content, limits)?;
            if control(Progress::default()) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            let parts = components(relative.as_ref())?;
            let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
            let parent = self.parent_existing(ancestors)?;
            let parent_id = FileIdentity::of(&parent)?;
            if expected_parent.is_some_and(|expected| expected != parent_id) {
                return Err(Error::SourceChanged);
            }
            let file = File::from(openat(&parent, *name, REGULAR, Mode::empty())?);
            // Settle pending filesystem metadata before anchoring the read fence.
            #[cfg(target_os = "freebsd")]
            file.sync_all().map_err(|source| Error::CommitUnknown {
                query: content.query,
                source,
            })?;
            let original = Stamp::file(&file)?;
            identity = Some(original.identity);
            if original.identity != expected_identity || original.bytes != content.size {
                return Err(Error::SourceChanged);
            }
            stage = RevalidateStage::Opened;
            let read = compare_selection(
                &file,
                buffers,
                cache,
                content,
                selection.clone(),
                &mut control,
            )?;
            receipt = Some(read.clone());
            // EmptySelection establishes no authenticated content, even though
            // its actual held inode and physical naming barriers can be checked.
            if matches!(read.completion, Completion::Verified(_)) {
                stage = RevalidateStage::Verified;
            }
            let check = || -> Result<()> {
                if Stamp::file(&file)? != original {
                    return Err(Error::SourceChanged);
                }
                let current_parent = self.parent_existing(ancestors)?;
                if FileIdentity::of(&current_parent)? != parent_id {
                    return Err(Error::SourceChanged);
                }
                let current = File::from(openat(&current_parent, *name, REGULAR, Mode::empty())?);
                if Stamp::file(&current)? != original {
                    return Err(Error::SourceChanged);
                }
                Ok(())
            };
            check()?;
            if control(read.authenticated) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            file.sync_all().map_err(|source| Error::CommitUnknown {
                query: content.query,
                source,
            })?;
            parent.sync_all().map_err(|source| Error::CommitUnknown {
                query: content.query,
                source,
            })?;
            check()?;
            Ok(RevalidatedRange {
                read,
                identity: original.identity,
                parent: parent_id,
            })
        })();
        result.map_err(|operation| {
            Box::new(RevalidateFailure {
                stage,
                identity,
                receipt,
                operation,
            })
        })
    }
}

fn compare_selection(
    file: &File,
    buffers: &mut Buffers,
    cache: &mut Repository,
    content: Content,
    selection: Range<u64>,
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<ReadRange> {
    let mut progress = Progress::default();
    let mut delivered_bytes = 0;
    let mut delivered_chunks = 0;
    let completion = if content.size != 0 && selection.is_empty() {
        Completion::EmptySelection
    } else {
        let mut reader = RangeReader::new(content, selection.clone(), &mut buffers.keys)?;
        while let Some(request) = reader.next() {
            if control(progress) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            let length = cache.read_block(request, &mut buffers.encoded)?;
            let ciphertext = buffers.encoded.get(..length).ok_or(Error::Corrupt)?;
            let chunk = reader.open_next(ciphertext, &mut buffers.plain)?;
            progress.blocks += 1;
            progress.encoded_bytes += length as u128;
            if let Some(chunk) = chunk {
                progress.plaintext_bytes += chunk.bytes().len() as u64;
                let actual = buffers
                    .index
                    .get_mut(..chunk.bytes().len())
                    .ok_or(Error::Corrupt)?;
                file.read_exact_at(actual, chunk.range().start)?;
                if actual != chunk.bytes() {
                    return Err(Error::SourceChanged);
                }
                delivered_bytes += chunk.bytes().len() as u64;
                delivered_chunks += 1;
            }
        }
        Completion::Verified(reader.completion().ok_or(Error::Corrupt)?)
    };
    Ok(ReadRange {
        content,
        selection,
        completion,
        destination: match completion {
            Completion::Verified(_) => Destination::ExistingFileCompared,
            Completion::EmptySelection => Destination::Untouched,
        },
        authenticated: progress,
        delivered_bytes,
        delivered_chunks,
    })
}
