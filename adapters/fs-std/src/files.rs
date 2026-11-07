use crate::{BlockSink, BlockSource, Error, Insert, Result};
use gnunet_fs::{
    Content,
    content::{BLOCK_BYTES, BlockKey, FileEncoder, FileReader, Layout, TAG_BYTES, VerifiedFile},
};
use std::io::{Read, Write};

/// Open a caller-selected regular input through its actual descriptor. The
/// nonblocking open permits type refusal of FIFOs without waiting for a writer.
pub fn open_input(path: impl AsRef<std::path::Path>) -> Result<std::fs::File> {
    let file = std::fs::File::from(nix::fcntl::open(
        path.as_ref(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FS input must be a regular file",
        )
        .into());
    }
    Ok(file)
}

/// File operation limits, checked before growing frontier storage or reading.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual file length accepted by this host operation.
    pub max_file_bytes: u64,
    /// Maximum ciphertext bytes across all data/index blocks of this file.
    pub max_encoded_bytes: u128,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 256 * 1024 * 1024 * 1024,
            max_encoded_bytes: 512 * 1024 * 1024 * 1024,
        }
    }
}
/// Caller interruption decision, sampled between real block operations and
/// during quiet native lookup waits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Continue the same operation.
    Continue,
    /// Return a cancelled outcome, without a completed-file receipt.
    Cancel,
}
/// Actual work performed so far; output may contain an authenticated prefix.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    /// Actual plaintext file bytes processed.
    pub plaintext_bytes: u64,
    /// Actual data/index blocks processed.
    pub blocks: u64,
    /// Actual complete ciphertext bytes processed.
    pub encoded_bytes: u128,
}
/// Completed local import. This does not assert external network publication.
#[derive(Clone, Copy, Debug)]
pub struct Published {
    /// Actual encoded root and file length.
    pub content: Content,
    /// Completed encoding/storage work.
    pub progress: Progress,
    /// Newly stored immutable blocks.
    pub created_blocks: u64,
}
/// Completed authenticated read, independently of a caller writer's durability.
#[derive(Clone, Copy, Debug)]
pub struct ReadFile {
    /// Complete actual tree authentication receipt.
    pub verified: VerifiedFile,
    /// Completed retrieval/decryption/output work.
    pub progress: Progress,
}
/// Reusable bounded host buffers. There is no per-block allocation or whole-file
/// copy. Directory record carry grows only when its actual parser requests it.
pub struct Buffers {
    pub(crate) keys: Vec<BlockKey>,
    pub(crate) plain: Vec<u8>,
    pub(crate) encoded: Vec<u8>,
    pub(crate) index: Vec<u8>,
    pub(crate) record: Vec<u8>,
    pub(crate) metadata_plain: Vec<u8>,
}
impl Default for Buffers {
    fn default() -> Self {
        Self::new()
    }
}
impl Buffers {
    /// Allocate reusable protocol-sized block buffers, with a small record arena.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            plain: vec![0; BLOCK_BYTES],
            encoded: vec![0; BLOCK_BYTES + TAG_BYTES],
            index: vec![0; BLOCK_BYTES],
            record: vec![0; 4096],
            metadata_plain: Vec::new(),
        }
    }
    pub(crate) fn prepare(&mut self, content: Content, limits: Limits) -> Result<()> {
        let layout = Layout::new(content.size);
        if content.size > limits.max_file_bytes
            || layout.encoded_tree_bytes() > limits.max_encoded_bytes
        {
            return Err(Error::Limit);
        }
        crate::resize(&mut self.keys, layout.required_keys(), BlockKey::default())?;
        Ok(())
    }
    /// Stream exactly size bytes into real data/index blocks and retain each in
    /// the selected backend. A failure may leave independently useful blocks;
    /// a completed file root is returned only after all blocks and exact EOF.
    pub fn publish(
        &mut self,
        input: &mut impl Read,
        size: u64,
        sink: &mut impl BlockSink,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<Published> {
        self.prepare(
            Content {
                key: [0; 64],
                query: [0; 64],
                size,
            },
            limits,
        )?;
        let mut encoder = FileEncoder::new(size, &mut self.keys)?;
        let mut progress = Progress::default();
        let mut created_blocks = 0;
        while let Some(node) = encoder.next() {
            if control(progress) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            let encoded = if node.level() == 0 {
                let length = node.plaintext_bytes();
                input.read_exact(&mut self.plain[..length])?;
                encoder.push_data(&self.plain[..length], &mut self.encoded)?
            } else {
                encoder.emit_index(&mut self.index, &mut self.encoded)?
            };
            let length = encoded.block().bytes().len();
            if sink.insert_block(encoded)? == Insert::Created {
                created_blocks += 1;
            }
            progress.blocks += 1;
            progress.encoded_bytes += length as u128;
            if node.level() == 0 {
                progress.plaintext_bytes += node.plaintext_bytes() as u64;
            }
        }
        if control(progress) == Control::Cancel {
            return Err(Error::Cancelled);
        }
        let mut extra = [0];
        loop {
            match input.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err(Error::SourceChanged),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Published {
            content: encoder.content().ok_or(Error::Corrupt)?,
            progress,
            created_blocks,
        })
    }
    /// Retrieve/authenticate each real block and write only authenticated file
    /// bytes. On failure/cancellation the writer owns its partial prefix; use an
    /// atomic output owner when incomplete files must remain unpublished.
    pub fn copy_to(
        &mut self,
        source: &mut impl BlockSource,
        content: Content,
        output: &mut impl Write,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile> {
        self.prepare(content, limits)?;
        let mut reader = FileReader::new(content, &mut self.keys)?;
        let mut progress = Progress::default();
        while let Some(request) = reader.next() {
            if control(progress) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            let length = source.read_block(request, &mut self.encoded)?;
            let ciphertext = self.encoded.get(..length).ok_or(Error::Corrupt)?;
            if let Some(chunk) = reader.open_next(ciphertext, &mut self.plain)? {
                output.write_all(chunk.bytes())?;
                progress.plaintext_bytes += chunk.bytes().len() as u64;
            }
            progress.blocks += 1;
            progress.encoded_bytes += length as u128;
        }
        Ok(ReadFile {
            verified: reader.completion().ok_or(Error::Corrupt)?,
            progress,
        })
    }
}
