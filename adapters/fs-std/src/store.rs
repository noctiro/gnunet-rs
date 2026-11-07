use crate::{BlockSink, BlockSource, Error, Result};
use gnunet_fs::content::{BLOCK_BYTES, EncodedNode, NodeRef, TAG_BYTES};
use nix::{
    errno::Errno,
    fcntl::{AtFlags, OFlag, open, openat},
    sys::stat::{Mode, SFlag, fstat, fstatat, mkdirat},
    unistd::{UnlinkatFlags, linkat, unlinkat},
};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

/// Result for an immutable, data-and-directory-synced content-addressed block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Insert {
    /// A new object became durable at its standard query hash.
    Created,
    /// The exact existing bytes were checked and their durability refreshed.
    Existing,
}
/// Anchored local repository storing raw official ciphertext+tag bytes. Two
/// hexadecimal characters select a shard; filenames are internal query hashes.
/// It does not imply GNUnet network publication or implement datastore IPC.
pub struct Repository {
    root: File,
    nonce: u64,
    durable_shards: [u64; 4],
    cleanup_pending: bool,
}
impl Repository {
    #[cfg(feature = "network")]
    pub(crate) fn from_directory(root: File) -> Result<Self> {
        if !root.metadata()?.is_dir() {
            return Err(gnunet_types::Error::InvalidInput.into());
        }
        Ok(Self {
            root,
            nonce: 0,
            durable_shards: [0; 4],
            cleanup_pending: false,
        })
    }
    /// Create/open a selected repository beneath an existing parent, anchoring
    /// its actual directory descriptor. The parent/root naming barrier is synced;
    /// final root/shard/object symlinks are never followed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let root = if let Some(name) = path.file_name() {
            let parent_path = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let parent = File::from(open(&fs::canonicalize(parent_path)?, flags, Mode::empty())?);
            match mkdirat(&parent, name, Mode::S_IRWXU) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(e.into()),
            }
            let root = File::from(openat(&parent, name, flags, Mode::empty())?);
            root.sync_all()?;
            parent.sync_all()?;
            root
        } else {
            File::from(open(path, flags, Mode::empty())?)
        };
        Ok(Self {
            root,
            nonce: 0,
            durable_shards: [0; 4],
            cleanup_pending: false,
        })
    }
    /// Whether an owned temporary could not be removed. Already confirmed final
    /// objects retain their actual successful durability disposition.
    #[must_use]
    pub const fn cleanup_pending(&self) -> bool {
        self.cleanup_pending
    }
    #[cfg(feature = "network")]
    pub(crate) fn open_child(parent: &File, name: &std::ffi::OsStr) -> Result<Self> {
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        let raw = name.as_bytes();
        if raw.is_empty() || raw.contains(&b'/') || raw.contains(&0) || matches!(raw, b"." | b"..")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository child requires one ordinary name",
            )
            .into());
        }
        match mkdirat(parent, name, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(error.into()),
        }
        let root = File::from(openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let meta = root.metadata()?;
        if !meta.is_dir()
            || meta.mode() & 0o7777 != 0o700
            || meta.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(Error::Corrupt);
        }
        root.sync_all()?;
        parent.sync_all()?;
        Self::same_name(parent, raw, &root, true)?;
        Ok(Self {
            root,
            nonce: 0,
            durable_shards: [0; 4],
            cleanup_pending: false,
        })
    }
    fn same_name(parent: &File, name: &[u8], file: &File, directory: bool) -> io::Result<()> {
        let original = fstat(file).map_err(io::Error::from)?;
        let named = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        let kind = if directory {
            SFlag::S_IFDIR
        } else {
            SFlag::S_IFREG
        };
        if original.st_dev != named.st_dev
            || original.st_ino != named.st_ino
            || SFlag::from_bits_truncate(original.st_mode) != kind
            || SFlag::from_bits_truncate(named.st_mode) != kind
        {
            return Err(io::Error::other(
                "original FS object name no longer matches its descriptor",
            ));
        }
        Ok(())
    }
    fn remove_owned_temp(parent: &File, name: &[u8], file: &File) -> io::Result<()> {
        Self::same_name(parent, name, file, false)?;
        unlinkat(parent, name, UnlinkatFlags::NoRemoveDir).map_err(io::Error::from)?;
        parent.sync_all()
    }
    fn names(query: &[u8; 64]) -> ([u8; 2], [u8; 126]) {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0; 128];
        for (out, byte) in encoded.as_chunks_mut::<2>().0.iter_mut().zip(query) {
            out[0] = DIGITS[usize::from(byte >> 4)];
            out[1] = DIGITS[usize::from(byte & 15)];
        }
        let mut shard = [0; 2];
        let mut name = [0; 126];
        shard.copy_from_slice(&encoded[..2]);
        name.copy_from_slice(&encoded[2..]);
        (shard, name)
    }
    fn object(&mut self, query: &[u8; 64], create: bool) -> Result<(File, [u8; 126])> {
        let (shard, name) = Self::names(query);
        let word = usize::from(query[0] / 64);
        let bit = 1_u64 << (query[0] % 64);
        let needs_sync = create && self.durable_shards[word] & bit == 0;
        if needs_sync {
            match mkdirat(&self.root, shard.as_slice(), Mode::S_IRWXU) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(e.into()),
            }
            self.root.sync_all()?;
        }
        let parent = File::from(openat(
            &self.root,
            shard.as_slice(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        if needs_sync {
            self.durable_shards[word] |= bit;
        }
        Ok((parent, name))
    }
    fn existing(parent: &File, name: &[u8], expected: &[u8]) -> Result<()> {
        let mut file = File::from(openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        Self::existing_open(parent, name, &mut file, expected)
    }
    fn existing_open(parent: &File, name: &[u8], file: &mut File, expected: &[u8]) -> Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != expected.len() as u64 {
            return Err(Error::Corrupt);
        }
        Self::same_name(parent, name, file, false)?;
        let mut scratch = [0; 1024];
        for chunk in expected.chunks(scratch.len()) {
            file.read_exact(&mut scratch[..chunk.len()])?;
            if scratch[..chunk.len()] != *chunk {
                return Err(Error::Corrupt);
            }
        }
        let mut extra = [0];
        if file.read(&mut extra)? != 0 {
            return Err(Error::Corrupt);
        }
        file.sync_all()?;
        Self::same_name(parent, name, file, false)?;
        parent.sync_all()?;
        Self::same_name(parent, name, file, false)?;
        Ok(())
    }
    fn put(&mut self, query: [u8; 64], bytes: &[u8]) -> Result<Insert> {
        if !(TAG_BYTES..=BLOCK_BYTES + TAG_BYTES).contains(&bytes.len()) {
            return Err(Error::Corrupt);
        }
        self.put_payload(query, bytes)
    }
    fn put_payload(&mut self, query: [u8; 64], bytes: &[u8]) -> Result<Insert> {
        let (parent, name) = self.object(&query, true)?;
        match Self::existing(&parent, &name, bytes) {
            Ok(()) => return Ok(Insert::Existing),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut reserved = None;
        for _ in 0..1024 {
            let nonce = self.nonce;
            self.nonce = nonce.checked_add(1).ok_or(Error::Limit)?;
            let mut temp = [0; 64];
            let used = {
                let mut out = &mut temp[..];
                write!(&mut out, ".tmp-{}-{nonce}", std::process::id())?;
                64 - out.len()
            };
            match openat(
                &parent,
                &temp[..used],
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            ) {
                Ok(fd) => {
                    reserved = Some((temp, used, File::from(fd)));
                    break;
                }
                Err(Errno::EEXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let (temp, used, mut file) = reserved.ok_or(Error::Limit)?;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            Self::same_name(&parent, &temp[..used], &file, false)?;
            match linkat(
                &parent,
                &temp[..used],
                &parent,
                name.as_slice(),
                AtFlags::empty(),
            ) {
                Ok(()) => {
                    Self::same_name(&parent, &name, &file, false)
                        .map_err(|source| Error::CommitUnknown { query, source })?;
                    parent
                        .sync_all()
                        .map_err(|source| Error::CommitUnknown { query, source })?;
                    Self::same_name(&parent, &name, &file, false)
                        .map_err(|source| Error::CommitUnknown { query, source })?;
                    Ok(Insert::Created)
                }
                Err(Errno::EEXIST) => {
                    Self::existing(&parent, &name, bytes)?;
                    Ok(Insert::Existing)
                }
                Err(e) => Err(e.into()),
            }
        })();
        // A foreign replacement never becomes cleanup authority. Known final
        // durability and independent exact-temporary cleanup remain distinct.
        match Self::remove_owned_temp(&parent, &temp[..used], &file) {
            Ok(()) => result,
            Err(source) => {
                self.cleanup_pending = true;
                match result {
                    Ok(_) => Err(Error::CleanupAfterCommit { query, source }),
                    Err(cause) => Err(Error::CleanupFailed {
                        cause: Box::new(cause),
                        source,
                    }),
                }
            }
        }
    }
    // Publication-task payloads are immutable raw artifacts indexed by their
    // body hash; a UBLOCK's network lookup key is a different public value.
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
        let (parent, name) = self.object(hash, false)?;
        let mut file = File::from(openat(
            &parent,
            name.as_slice(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > u16::MAX as u64 {
            return Err(Error::Corrupt);
        }
        let length = usize::try_from(metadata.len()).map_err(|_| Error::Limit)?;
        if output.len() < length {
            return Err(gnunet_types::Error::Capacity.into());
        }
        file.read_exact(&mut output[..length])?;
        let mut extra = [0];
        loop {
            match file.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err(Error::Corrupt),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        if gnunet_crypto::hash512(&output[..length]) != *hash {
            return Err(Error::Corrupt);
        }
        Ok(length)
    }
    /// Cache an externally supplied block only at its actual ciphertext query.
    /// Full source authentication remains the reader's responsibility.
    pub fn cache(&mut self, query: [u8; 64], ciphertext: &[u8]) -> Result<Insert> {
        if !(TAG_BYTES..=BLOCK_BYTES + TAG_BYTES).contains(&ciphertext.len()) {
            return Err(Error::Corrupt);
        }
        if gnunet_crypto::hash512(ciphertext) != query {
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
        let (parent, name) = self.object(&request.key().query, false)?;
        let mut file = File::from(openat(
            &parent,
            name.as_slice(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != expected as u64 {
            return Err(Error::Corrupt);
        }
        file.read_exact(&mut output[..expected])?;
        Ok(expected)
    }
}
impl BlockSink for Repository {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> Result<Insert> {
        self.put(encoded.block().key().query, encoded.block().bytes())
    }
}

#[cfg(test)]
mod tests;
