//! Shared immutable-object verification, publication and bounded block I/O.
use super::{Insert, Retention, native::Directory};
use crate::{BlockSink, BlockSource, Error, Result};
use gnunet_fs::content::{BLOCK_BYTES, EncodedNode, NodeRef, TAG_BYTES};
use gnunet_native::DirectorySync;
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

/// Anchored repository of raw official ciphertext and tag bytes. The complete
/// query hash selects a two-character shard and a 126-character object name.
/// Data synchronization and directory-barrier availability are independent;
/// local insertion does not certify network publication or remote retention.
/// Callers serialize stored-object mutation and administrative shard replacement
/// or removal. Concurrent immutable insertions use exclusive temporaries and
/// no-replace publication. Renaming the selected root cannot redirect this owner.
#[derive(Debug)]
pub struct Repository {
    root: Directory,
    nonce: u64,
    prepared_shards: [u64; 4],
    root_sync: DirectorySync,
    cleanup_pending: bool,
}
enum Access {
    Read,
    Prepare,
}
impl Repository {
    fn anchored(root: Directory) -> Result<Self> {
        let root_sync = root.sync()?;
        Ok(Self {
            root,
            nonce: 0,
            prepared_shards: [0; 4],
            root_sync,
            cleanup_pending: false,
        })
    }
    /// Create/open a selected root beneath its actual existing parent. Final
    /// root/shard/object symlinks and Windows name surrogates are refused.
    /// Native ancestor selection is not a sandbox against ancestor replacement.
    ///
    /// # Errors
    /// Preserves actual open, identity, sharing and synchronization failures.
    /// A newly created directory can remain after a later error.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::anchored(Directory::open(path.as_ref())?)
    }
    #[cfg(feature = "network")]
    pub(crate) fn from_directory(root: File) -> Result<Self> {
        Self::anchored(Directory::from_file(root)?)
    }
    #[cfg(feature = "network")]
    pub(crate) fn open_child(parent: &File, name: &OsStr) -> Result<Self> {
        Self::anchored(Directory::private_child(parent, name)?)
    }
    /// Whether exact-temporary cleanup failed independently of publication.
    #[must_use]
    pub const fn cleanup_pending(&self) -> bool {
        self.cleanup_pending
    }
    fn names(query: &[u8; 64]) -> ([u8; 2], [u8; 126]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0; 128];
        for (pair, byte) in encoded.as_chunks_mut::<2>().0.iter_mut().zip(query) {
            pair[0] = HEX[usize::from(byte >> 4)];
            pair[1] = HEX[usize::from(byte & 15)];
        }
        let mut shard = [0; 2];
        let mut name = [0; 126];
        shard.copy_from_slice(&encoded[..2]);
        name.copy_from_slice(&encoded[2..]);
        (shard, name)
    }
    fn object(&mut self, query: &[u8; 64], access: Access) -> Result<(Directory, [u8; 126])> {
        let (shard, name) = Self::names(query);
        let word = usize::from(query[0] / 64);
        let bit = 1_u64 << (query[0] % 64);
        let shard = OsStr::new(text(&shard)?);
        let parent = if matches!(access, Access::Prepare) && self.prepared_shards[word] & bit == 0 {
            let parent = self.root.ensure_directory(shard)?;
            self.root_sync = self.root_sync.combine(self.root.sync()?);
            self.prepared_shards[word] |= bit;
            parent
        } else {
            self.root.open_directory(shard)?
        };
        Ok((parent, name))
    }
    pub(super) fn existing(
        parent: &Directory,
        name: &str,
        expected: &[u8],
    ) -> Result<DirectorySync> {
        let mut file = parent.open_for_sync(name)?;
        Self::existing_open(parent, name, &mut file, expected)
    }
    pub(super) fn existing_open(
        parent: &Directory,
        name: &str,
        file: &mut File,
        expected: &[u8],
    ) -> Result<DirectorySync> {
        if file.metadata()?.len() != expected.len() as u64 {
            return Err(Error::Corrupt);
        }
        parent.same_file(name, file)?;
        let mut scratch = [0; 1024];
        for chunk in expected.chunks(scratch.len()) {
            file.read_exact(&mut scratch[..chunk.len()])?;
            if scratch[..chunk.len()] != *chunk {
                return Err(Error::Corrupt);
            }
        }
        exact_end(file)?;
        file.sync_all()?;
        parent.same_file(name, file)?;
        let receipt = parent.sync()?;
        parent.same_file(name, file)?;
        Ok(receipt)
    }
    fn put(&mut self, query: [u8; 64], bytes: &[u8]) -> Result<Insert> {
        if !(TAG_BYTES..=BLOCK_BYTES + TAG_BYTES).contains(&bytes.len()) {
            return Err(Error::Corrupt);
        }
        self.put_payload(query, bytes)
    }
    fn put_payload(&mut self, query: [u8; 64], bytes: &[u8]) -> Result<Insert> {
        let (parent, name) = self.object(&query, Access::Prepare)?;
        let name = text(&name)?;
        match Self::existing(&parent, name, bytes) {
            Ok(receipt) => {
                return Ok(Insert::Existing(Retention::FileSynchronized(
                    self.root_sync.combine(receipt),
                )));
            }
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut reserved = None;
        for _ in 0..1024 {
            let nonce = self.nonce;
            self.nonce = nonce.checked_add(1).ok_or(Error::Limit)?;
            let mut bytes = [0; 64];
            let used = {
                let mut output = &mut bytes[..];
                write!(&mut output, ".tmp-{}-{nonce}", std::process::id())?;
                64 - output.len()
            };
            match parent.create_file(text(&bytes[..used])?) {
                Ok(file) => {
                    reserved = Some((bytes, used, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let (temporary, used, mut file) = reserved.ok_or(Error::Limit)?;
        let temporary = text(&temporary[..used])?;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            parent.same_file(temporary, &file)?;
            match parent.publish(temporary, &file, name) {
                Ok(()) => {
                    parent
                        .same_file(name, &file)
                        .map_err(|source| Error::CommitUnknown { query, source })?;
                    let receipt = parent
                        .sync()
                        .map_err(|source| Error::CommitUnknown { query, source })?;
                    parent
                        .same_file(name, &file)
                        .map_err(|source| Error::CommitUnknown { query, source })?;
                    Ok(Insert::Created(Retention::FileSynchronized(
                        self.root_sync.combine(receipt),
                    )))
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let receipt = Self::existing(&parent, name, bytes)?;
                    Ok(Insert::Existing(Retention::FileSynchronized(
                        self.root_sync.combine(receipt),
                    )))
                }
                // Filesystems can report a failed publication after the native
                // request reached the backing provider. Preserve reconciliation.
                Err(source) => Err(Error::CommitUnknown { query, source }),
            }
        })();
        match parent.remove(temporary, &file) {
            Ok(()) => result,
            Err(source) => {
                self.cleanup_pending = true;
                match result {
                    Ok(insert) => Err(Error::CleanupAfterCommit {
                        query,
                        retention: insert.retention(),
                        source,
                    }),
                    Err(cause) => Err(Error::CleanupFailed {
                        cause: Box::new(cause),
                        source,
                    }),
                }
            }
        }
    }
    #[cfg(feature = "network")]
    pub(crate) fn insert_payload(&mut self, bytes: &[u8]) -> Result<([u8; 64], Insert)> {
        if bytes.is_empty() || bytes.len() > u16::MAX as usize {
            return Err(Error::Limit);
        }
        let hash = gnunet_crypto::hash512(bytes);
        self.put_payload(hash, bytes).map(|insert| (hash, insert))
    }
    #[cfg(feature = "network")]
    pub(crate) fn read_payload(&mut self, hash: &[u8; 64], output: &mut [u8]) -> Result<usize> {
        let (parent, name) = self.object(hash, Access::Read)?;
        let mut file = parent.open_file(text(&name)?)?;
        let length = file.metadata()?.len();
        if length == 0 || length > u16::MAX as u64 {
            return Err(Error::Corrupt);
        }
        let length = usize::try_from(length).map_err(|_| Error::Limit)?;
        if output.len() < length {
            return Err(gnunet_types::Error::Capacity.into());
        }
        file.read_exact(&mut output[..length])?;
        exact_end(&mut file)?;
        if gnunet_crypto::hash512(&output[..length]) != *hash {
            return Err(Error::Corrupt);
        }
        Ok(length)
    }
    /// Cache only bytes whose actual hash equals the supplied ciphertext query.
    /// Full content authentication remains the reader's responsibility.
    ///
    /// # Errors
    /// Rejects invalid size/hash and preserves I/O, uncertain publication and
    /// independent exact-temporary cleanup failures.
    pub fn cache(&mut self, query: [u8; 64], ciphertext: &[u8]) -> Result<Insert> {
        if !(TAG_BYTES..=BLOCK_BYTES + TAG_BYTES).contains(&ciphertext.len())
            || gnunet_crypto::hash512(ciphertext) != query
        {
            return Err(Error::Corrupt);
        }
        self.put(query, ciphertext)
    }
}
impl BlockSource for Repository {
    fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> Result<usize> {
        let expected = request.node().plaintext_bytes() + TAG_BYTES;
        if output.len() < expected {
            return Err(gnunet_types::Error::Capacity.into());
        }
        let (parent, name) = self.object(&request.key().query, Access::Read)?;
        let mut file = parent.open_file(text(&name)?)?;
        if file.metadata()?.len() != expected as u64 {
            return Err(Error::Corrupt);
        }
        file.read_exact(&mut output[..expected])?;
        exact_end(&mut file)?;
        Ok(expected)
    }
}
impl BlockSink for Repository {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> Result<Insert> {
        self.put(encoded.block().key().query, encoded.block().bytes())
    }
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error::Corrupt)
}
fn exact_end(file: &mut File) -> Result<()> {
    loop {
        match file.read(&mut [0]) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(Error::Corrupt),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}
