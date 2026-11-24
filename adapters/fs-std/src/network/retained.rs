//! Verified reuse of the official sparse download-file layout.
use super::{
    Buffers, Control, Download, DownloadOptions, DownloadSink, Error, LocalNode, Lookup, Progress,
    ReadFile, controlled, tree_download::inline::InlineBlocks,
};
use crate::BlockSource;
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content,
    content::{
        self, BLOCK_BYTES, CHK_BYTES, FileEncoder, MAX_CHILDREN, Node, NodeRef, VerifiedChunk,
    },
};
use gnunet_types::Error as ProtocolError;
use std::io::{self, SeekFrom};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

// The official downloader places plaintext index levels after the rounded
// data extent. Keep the C level-size recurrence and bound every coordinate.
fn offset(node: Node) -> Result<u64, ProtocolError> {
    if node.level() == 0 {
        return Ok(node.range().start);
    }
    let leaves = u128::from(node.layout().leaf_count());
    let mut start = leaves * BLOCK_BYTES as u128;
    let mut level_bytes = leaves * CHK_BYTES as u128;
    let mut ordinal = u128::from(node.first_leaf());
    for _ in 1..node.level() {
        start += level_bytes;
        level_bytes = level_bytes.div_ceil(MAX_CHILDREN as u128);
        ordinal /= MAX_CHILDREN as u128;
    }
    let start = start + ordinal * CHK_BYTES as u128;
    u64::try_from(start + node.plaintext_bytes() as u128).map_err(|_| ProtocolError::Overflow)?;
    u64::try_from(start).map_err(|_| ProtocolError::Overflow)
}

pub(crate) struct Blocks<'hint> {
    pub file: File,
    original_size: Option<u64>,
    inline: Option<&'hint mut InlineBlocks>,
    // An untouched existing input never becomes eligible for cancellation deletion.
    retained: bool,
}
impl<'hint> Blocks<'hint> {
    pub(crate) fn new(
        file: File,
        original_size: Option<u64>,
        inline: Option<&'hint mut InlineBlocks>,
    ) -> Self {
        Self {
            file,
            original_size,
            inline,
            retained: original_size.is_none(),
        }
    }
    pub(crate) fn may_delete(&self) -> bool {
        self.retained
    }
    fn can_write(&self) -> bool {
        self.retained || self.original_size == Some(0)
    }
    async fn write(&mut self, start: u64, bytes: &[u8]) -> Result<(), Error> {
        self.file.seek(SeekFrom::Start(start)).await?;
        self.retained = true;
        self.file.write_all(bytes).await?;
        Ok(())
    }
    async fn original_node(
        &mut self,
        node: NodeRef,
        plaintext: &mut [u8],
        encoded: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let Some(original_size) = self.original_size else {
            return Ok(None);
        };
        let size = node.node().plaintext_bytes();
        let start = offset(node.node())?;
        if original_size
            < start
                .checked_add(size as u64)
                .ok_or(ProtocolError::Overflow)?
        {
            return Ok(None);
        }
        let plaintext = plaintext.get_mut(..size).ok_or(ProtocolError::Capacity)?;
        self.file.seek(SeekFrom::Start(start)).await?;
        match self.file.read_exact(plaintext).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if gnunet_crypto::hash512(plaintext) != node.key().key {
            return Ok(None);
        }
        let value = content::encode_data(plaintext, encoded)?;
        if value.key() != node.key() {
            return Ok(None);
        }
        self.retained = true;
        Ok(Some(value.bytes().len()))
    }
}
impl DownloadSink for Blocks<'_> {
    fn retains_nodes(&self) -> bool {
        true
    }
    async fn local_node(
        &mut self,
        node: NodeRef,
        plaintext: &mut [u8],
        encoded: &mut [u8],
    ) -> Result<Option<LocalNode>, Error> {
        if let Some(length) = self.original_node(node, plaintext, encoded).await? {
            return Ok(Some(LocalNode {
                length,
                already_written: true,
            }));
        }
        self.inline
            .as_deref_mut()
            .map(|blocks| {
                Ok(LocalNode {
                    length: blocks.read_block(node, encoded)?,
                    already_written: false,
                })
            })
            .transpose()
    }
    async fn index(&mut self, node: NodeRef, plaintext: &[u8]) -> Result<(), Error> {
        if self.can_write() {
            self.write(offset(node.node())?, plaintext).await?;
        }
        Ok(())
    }
    async fn chunk(&mut self, chunk: VerifiedChunk<'_>, reused: bool) -> Result<(), Error> {
        if !reused {
            if !self.can_write() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "existing output has no authenticated download data",
                )
                .into());
            }
            self.write(chunk.range().start, chunk.bytes()).await?;
        }
        Ok(())
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.file.flush().await?;
        Ok(())
    }
}

pub(crate) struct Transfer {
    lookup: Lookup,
    content: Content,
}
pub(crate) struct Completed {
    pub read: ReadFile,
    pub time: super::TimeLimit,
}
pub(crate) enum ExistingFence {
    Stable,
    Recheck,
}
impl Transfer {
    pub(crate) fn prepare(
        buffers: &mut Buffers,
        source: EndpointSource,
        content: Content,
        options: DownloadOptions,
    ) -> Result<Self, Error> {
        buffers.prepare(content, options.limits)?;
        Ok(Self {
            lookup: Lookup::new(source, options)?,
            content,
        })
    }
    pub(crate) fn check(&mut self) -> Result<(), Error> {
        self.lookup.time.check()
    }
    pub(crate) async fn run(
        mut self,
        buffers: &mut Buffers,
        output: &mut Blocks<'_>,
        mut control: impl FnMut(Progress) -> Control,
        mut confirm: impl FnMut() -> crate::Result<ExistingFence>,
    ) -> crate::Result<Completed> {
        if output.original_size == Some(self.content.size)
            && let Some(mut read) = buffers
                .existing_content(
                    self.content,
                    &mut output.file,
                    &mut self.lookup,
                    &mut control,
                )
                .await?
        {
            if matches!(confirm()?, ExistingFence::Recheck) {
                read = buffers
                    .existing_content(
                        self.content,
                        &mut output.file,
                        &mut self.lookup,
                        &mut control,
                    )
                    .await?
                    .ok_or(crate::Error::SourceChanged)?;
                if !matches!(confirm()?, ExistingFence::Stable) {
                    return Err(crate::Error::SourceChanged);
                }
            }
            return Ok(Completed {
                read,
                time: self.lookup.time,
            });
        }
        let mut transfer = Download::with_lookup(
            self.lookup,
            self.content,
            None,
            &mut buffers.keys,
            &mut buffers.plain,
            &mut buffers.encoded,
        )?;
        let read = transfer.run(output, &mut control).await?;
        Ok(Completed {
            read,
            time: transfer.lookup.time,
        })
    }
}

impl Buffers {
    async fn existing_content(
        &mut self,
        content: Content,
        file: &mut File,
        lookup: &mut Lookup,
        control: &mut impl FnMut(Progress) -> Control,
    ) -> Result<Option<ReadFile>, Error> {
        let mut encoder = FileEncoder::new(content.size, &mut self.keys)?;
        let mut progress = Progress::default();
        controlled(
            lookup.during(file.seek(SeekFrom::Start(0))),
            progress,
            control,
        )
        .await??;
        while let Some(node) = encoder.next() {
            lookup.during(std::future::ready(())).await?;
            if control(progress) == Control::Cancel {
                return Err(Error::Cancelled(progress));
            }
            let encoded = if node.level() == 0 {
                let plain = &mut self.plain[..node.plaintext_bytes()];
                match controlled(lookup.during(file.read_exact(plain)), progress, control).await? {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(error) => return Err(error.into()),
                }
                progress.plaintext_bytes += plain.len() as u64;
                encoder.push_data(plain, &mut self.encoded)?
            } else {
                encoder.emit_index(&mut self.index, &mut self.encoded)?
            };
            progress.blocks += 1;
            progress.encoded_bytes += encoded.block().bytes().len() as u128;
        }
        Ok(encoder.verified(content).map(|verified| ReadFile {
            verified,
            progress,
            directory_sync: None,
        }))
    }
}
