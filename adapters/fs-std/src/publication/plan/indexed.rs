//! Real indexed-source preparation and FileReader verification of type6 plans.
use super::{Error, Limits, Payload, Position, Put};
use crate::{BlockSink, BlockSource, Buffers, Control, Insert, Progress, ReadFile, Repository};
use gnunet_crypto::Hash512State;
use gnunet_fs::{
    Content,
    content::{self, EncodedNode, Layout, NodeRef, TAG_BYTES},
};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    mem::size_of,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

/// Exact native identity/change observations. Atime is excluded because our own
/// actual source reads can update it. This is not an atomic filesystem snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStamp {
    /// Original native device.
    pub device: u64,
    /// Original native inode.
    pub inode: u64,
    /// Complete original plaintext length.
    pub bytes: u64,
    /// Native modification seconds.
    pub modified: i64,
    /// Native modification nanoseconds.
    pub modified_nanos: i64,
    /// Native change seconds.
    pub changed: i64,
    /// Native change nanoseconds.
    pub changed_nanos: i64,
}
impl SourceStamp {
    fn capture(metadata: &std::fs::Metadata) -> Result<Self, Error> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "indexed source must be a regular file",
            )
            .into());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        })
    }
}
/// Original indexed source binding. The plaintext remains in this actual file;
/// a task's immutable type6 objects cannot replace a missing/changed source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    /// Canonical absolute native filename, preserving raw Unix bytes.
    pub path: Vec<u8>,
    /// Complete actual source SHA-512, carried in every type6 descriptor.
    pub file_id: [u8; 64],
    /// Original file identity and change observations.
    pub stamp: SourceStamp,
}
impl Source {
    fn validate_path(&self) -> Result<(), Error> {
        let raw = &self.path;
        if raw.len() > 4096
            || raw.first() != Some(&b'/')
            || raw.contains(&0)
            || raw.len() < 2
            || raw[1..]
                .split(|b| *b == b'/')
                .any(|p| p.is_empty() || matches!(p, b"." | b".."))
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    /// Validate only structural source bounds; no source availability is implied.
    pub fn validate(&self, limits: Limits) -> Result<(), Error> {
        self.validate_path()?;
        if self.path.len() > limits.max_plan_bytes || self.stamp.bytes > limits.file.max_file_bytes
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
    /// Borrow the exact native path without lossy decoding.
    #[must_use]
    pub fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(&self.path))
    }
}
/// One active source descriptor. A runner holds only the current indexed file,
/// verifies its binding around every original mutation, then releases it.
pub struct SourceGuard {
    file: File,
    source: Source,
}
impl SourceGuard {
    pub(crate) fn matches(&self, source: &Source) -> bool {
        self.source == *source
    }
    /// Open the exact original source, never following a final symlink. This
    /// refuses missing sources; source metadata alone cannot prove authenticity.
    pub fn open(source: &Source) -> Result<Self, Error> {
        source.validate_path()?;
        let file = crate::open_input(source.path())?;
        let result = Self {
            file,
            source: source.clone(),
        };
        result.stable()?;
        Ok(result)
    }
    /// Check both held FD and original canonical path. A matching stamp is a
    /// change observation, not a replacement for the complete content check.
    pub fn stable(&self) -> Result<(), Error> {
        let held = SourceStamp::capture(&self.file.metadata()?)?;
        let named = SourceStamp::capture(&std::fs::symlink_metadata(self.source.path())?)?;
        if held != self.source.stamp || named != self.source.stamp {
            return Err(crate::Error::SourceChanged.into());
        }
        Ok(())
    }
}
/// A genuinely prepared indexed object; no service registration has run yet.
#[derive(Debug)]
pub struct Prepared {
    /// Original canonical source authority and complete actual file hash.
    pub source: Source,
    /// Genuine computed CHK of this actual file.
    pub content: Content,
    /// Every exact ordered type6/full-IBLOCK PUT, including duplicate positions.
    pub puts: Vec<Put>,
}
/// Check indexed geometry and actual stored-payload work without opening a source.
/// This is a bound, not a claim that any source or payload was verified.
pub fn budget(size: u64, limits: Limits) -> Result<(usize, u128), Error> {
    let layout = Layout::new(size);
    let count = (0..layout.levels()).try_fold(0u64, |n, level| {
        n.checked_add(layout.node_count(level)?)
            .ok_or(gnunet_types::Error::Overflow)
    })?;
    let count = usize::try_from(count).map_err(|_| Error::Limit)?;
    let leaves = u128::from(layout.leaf_count());
    let stored = layout
        .encoded_tree_bytes()
        .checked_sub(u128::from(size) + leaves * TAG_BYTES as u128)
        .and_then(|n| n.checked_add(leaves * 72))
        .ok_or(Error::Limit)?;
    if count > limits.max_puts
        || size > limits.file.max_file_bytes
        || layout.encoded_tree_bytes() > limits.file.max_encoded_bytes
        || stored > limits.max_stored_bytes
        || size_of::<Source>()
            .checked_add(size_of::<Prepared>())
            .and_then(|n| {
                count
                    .checked_mul(size_of::<Put>())
                    .and_then(|rows| n.checked_add(rows))
            })
            .is_none_or(|n| n > limits.max_plan_bytes)
    {
        return Err(Error::Limit);
    }
    for level in 0..layout.levels() {
        let bytes = if level == 0 {
            72
        } else {
            layout.node(level, 0)?.plaintext_bytes() + TAG_BYTES
        };
        if bytes > limits.max_payload_bytes
            || bytes > gnunet_wire::official::datastore::MAX_VALUE_BYTES
        {
            return Err(Error::Limit);
        }
    }
    Ok((count, stored))
}
fn descriptor(file_id: [u8; 64], offset: u64) -> [u8; 72] {
    let mut value = [0; 72];
    value[..64].copy_from_slice(&file_id);
    value[64..].copy_from_slice(&offset.to_be_bytes());
    value
}
struct Sink<'a> {
    repo: &'a mut Repository,
    file_id: [u8; 64],
    rows: Vec<Put>,
}
impl BlockSink for Sink<'_> {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> crate::Result<Insert> {
        let node = encoded.node();
        let block = encoded.block();
        let descriptor = descriptor(self.file_id, node.range().start);
        let (kind, bytes) = if node.level() == 0 {
            (6, descriptor.as_slice())
        } else {
            (2, block.bytes())
        };
        let (hash, insert) = self.repo.insert_payload(bytes)?;
        self.rows.push(Put {
            kind,
            key: block.key().query,
            payload: Payload {
                hash,
                bytes: bytes.len(),
            },
            position: Some(Position {
                level: node.level(),
                index: node.ordinal(),
            }),
        });
        Ok(insert)
    }
}
struct HashReader<'a> {
    file: &'a mut File,
    hash: Hash512State,
}
impl Read for HashReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let used = self.file.read(output)?;
        self.hash.update(&output[..used]);
        Ok(used)
    }
}
fn hash_file(
    input: &mut File,
    size: u64,
    scratch: &mut [u8],
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<[u8; 64], Error> {
    input.rewind()?;
    let mut done = 0;
    let mut hash = Hash512State::new();
    while done < size {
        if control(Progress::default()) == Control::Cancel {
            return Err(crate::Error::Cancelled.into());
        }
        let n = (size - done).min(scratch.len() as u64) as usize;
        match input.read(&mut scratch[..n]) {
            Ok(0) => return Err(crate::Error::SourceChanged.into()),
            Ok(n) => {
                hash.update(&scratch[..n]);
                done += n as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut extra = [0];
    loop {
        match input.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err(crate::Error::SourceChanged.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(hash.finish())
}
/// Hash the original source and stream real encodings into immutable type6/full
/// index objects. Both complete source passes, exact EOF and stamps must match.
/// No registration or DATASTORE mutation is performed.
pub fn prepare(
    repo: &mut Repository,
    input: &mut File,
    filename: &Path,
    buffers: &mut Buffers,
    limits: Limits,
    mut control: impl FnMut(Progress) -> Control,
) -> Result<Prepared, Error> {
    let stamp = SourceStamp::capture(&input.metadata()?)?;
    let (count, _) = budget(stamp.bytes, limits)?;
    let path = std::fs::canonicalize(filename)?;
    let raw = path.as_os_str().as_bytes();
    if raw.len() > 4096
        || raw
            .len()
            .checked_add(size_of::<Prepared>())
            .and_then(|n| {
                count
                    .checked_mul(size_of::<Put>())
                    .and_then(|m| n.checked_add(m))
            })
            .is_none_or(|n| n > limits.max_plan_bytes)
    {
        return Err(Error::Limit);
    }
    if SourceStamp::capture(&std::fs::symlink_metadata(&path)?)? != stamp {
        return Err(crate::Error::SourceChanged.into());
    }
    let file_id = hash_file(input, stamp.bytes, &mut buffers.plain, &mut control)?;
    let source = Source {
        path: super::owned(raw)?,
        file_id,
        stamp,
    };
    source.validate(limits)?;
    if SourceStamp::capture(&input.metadata()?)? != stamp {
        return Err(crate::Error::SourceChanged.into());
    }
    input.rewind()?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    let mut sink = Sink {
        repo,
        file_id,
        rows,
    };
    let mut reading = HashReader {
        file: input,
        hash: Hash512State::new(),
    };
    let published = buffers.publish(
        &mut reading,
        stamp.bytes,
        &mut sink,
        limits.file,
        &mut control,
    )?;
    if reading.hash.finish() != file_id
        || SourceStamp::capture(&reading.file.metadata()?)? != stamp
        || SourceStamp::capture(&std::fs::symlink_metadata(&path)?)? != stamp
    {
        return Err(crate::Error::SourceChanged.into());
    }
    let prepared = Prepared {
        source,
        content: published.content,
        puts: sink.rows,
    };
    validate(&prepared.source, prepared.content, &prepared.puts, limits)?;
    Ok(prepared)
}
fn positions(
    source: &Source,
    content: Content,
    puts: &[Put],
    limits: Limits,
) -> Result<HashMap<Position, usize>, Error> {
    source.validate(limits)?;
    let layout = Layout::new(content.size);
    let (count, stored) = budget(content.size, limits)?;
    if source.stamp.bytes != content.size || puts.len() != count || stored > limits.max_stored_bytes
    {
        return Err(Error::Binding);
    }
    let mut map = HashMap::new();
    map.try_reserve(count).map_err(|_| Error::Limit)?;
    for (index, put) in puts.iter().enumerate() {
        let position = put.position.ok_or(Error::Binding)?;
        let node = layout.node(position.level, position.index)?;
        let expected = if node.level() == 0 {
            72
        } else {
            node.plaintext_bytes() + TAG_BYTES
        };
        if put.kind != if node.level() == 0 { 6 } else { 2 }
            || put.payload.bytes != expected
            || put.payload.bytes > limits.max_payload_bytes
            || put.payload.bytes > gnunet_wire::official::datastore::MAX_VALUE_BYTES
            || (node.level() > 0 && put.payload.hash != put.key)
            || map.insert(position, index).is_some()
        {
            return Err(Error::Binding);
        }
        for child in 0..node.child_count() {
            let child = node.child(child)?;
            if !map.contains_key(&Position {
                level: child.level(),
                index: child.ordinal(),
            }) {
                return Err(Error::Binding);
            }
        }
    }
    let root = layout.root();
    let last = puts.last().ok_or(Error::Binding)?;
    if last.position
        != Some(Position {
            level: root.level(),
            index: 0,
        })
        || last.key != content.query
    {
        return Err(Error::Binding);
    }
    Ok(map)
}
/// Validate exact indexed shape/order/resource bounds without opening the source
/// or claiming a genuine authenticated file receipt.
pub fn validate(
    source: &Source,
    content: Content,
    puts: &[Put],
    limits: Limits,
) -> Result<(), Error> {
    positions(source, content, puts, limits).map(|_| ())
}
struct Reader<'a> {
    repo: &'a mut Repository,
    source: &'a mut SourceGuard,
    puts: &'a [Put],
    map: HashMap<Position, usize>,
    seen: Vec<bool>,
    plain: Vec<u8>,
    descriptor: [u8; 72],
    hash: Hash512State,
    hashed: u64,
    failure: Option<Error>,
}
impl BlockSource for Reader<'_> {
    fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> crate::Result<usize> {
        let position = Position {
            level: request.node().level(),
            index: request.node().ordinal(),
        };
        let index = *self.map.get(&position).ok_or(crate::Error::Corrupt)?;
        let put = self.puts.get(index).ok_or(crate::Error::Corrupt)?;
        if put.key != request.key().query || self.seen[index] {
            self.failure = Some(Error::Binding);
            return Err(crate::Error::Corrupt);
        }
        self.source.stable().map_err(|error| {
            self.failure = Some(error);
            crate::Error::SourceChanged
        })?;
        let used = if position.level == 0 {
            let n = self
                .repo
                .read_payload(&put.payload.hash, &mut self.descriptor)?;
            if n != 72
                || self.descriptor
                    != descriptor(self.source.source.file_id, request.node().range().start)
                || self.hashed != request.node().range().start
            {
                self.failure = Some(Error::Binding);
                return Err(crate::Error::Corrupt);
            }
            self.source
                .file
                .seek(SeekFrom::Start(request.node().range().start))?;
            let bytes = request.node().plaintext_bytes();
            self.source.file.read_exact(&mut self.plain[..bytes])?;
            self.hash.update(&self.plain[..bytes]);
            self.hashed = self
                .hashed
                .checked_add(bytes as u64)
                .ok_or(crate::Error::Limit)?;
            let encoded = content::encode_data(&self.plain[..bytes], output)?;
            if encoded.key().query != put.key {
                self.failure = Some(Error::Binding);
                return Err(crate::Error::Corrupt);
            }
            encoded.bytes().len()
        } else {
            let n = self.repo.read_payload(&put.payload.hash, output)?;
            if n != put.payload.bytes || put.payload.hash != put.key {
                self.failure = Some(Error::Binding);
                return Err(crate::Error::Corrupt);
            }
            n
        };
        self.source.stable().map_err(|error| {
            self.failure = Some(error);
            crate::Error::SourceChanged
        })?;
        self.seen[index] = true;
        Ok(used)
    }
}
/// Reopen the original source and obtain a genuine complete FileReader receipt.
/// Every leaf reconstructs actual ciphertext from the held source and checks
/// its exact immutable type6 descriptor; index payloads are authenticated by the
/// same core reader. The source must remain stable and its complete hash match.
pub fn verify(
    source: &Source,
    content: Content,
    puts: &[Put],
    repo: &mut Repository,
    buffers: &mut Buffers,
    limits: Limits,
    mut control: impl FnMut(Progress) -> Control,
) -> Result<ReadFile, Error> {
    let map = positions(source, content, puts, limits)?;
    let mut guard = SourceGuard::open(source)?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(puts.len())
        .map_err(|_| Error::Limit)?;
    seen.resize(puts.len(), false);
    let mut reader = Reader {
        repo,
        source: &mut guard,
        puts,
        map,
        seen,
        plain: super::owned(&[0; content::BLOCK_BYTES])?,
        descriptor: [0; 72],
        hash: Hash512State::new(),
        hashed: 0,
        failure: None,
    };
    let read = buffers.copy_to(
        &mut reader,
        content,
        &mut io::sink(),
        limits.file,
        &mut control,
    );
    if let Some(error) = reader.failure {
        return Err(error);
    }
    let read = read?;
    if reader.seen.iter().any(|seen| !*seen)
        || reader.hashed != content.size
        || reader.hash.finish() != source.file_id
    {
        return Err(Error::Binding);
    }
    reader.source.stable()?;
    Ok(read)
}

#[cfg(test)]
mod tests;
