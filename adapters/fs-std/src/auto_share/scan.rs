//! Descriptor-anchored sorted stat trees. No file plaintext is read by a scan.
use super::{Error, Stop};
use crate::input_tree::{FrameSource, InputDir, Kind, SourceError, Stamp, stamp};
use gnunet_crypto::Hash512State;
use std::{fs::File, path::Path};
/// Finite source-enumeration bounds. Symlinks/special files are refused rather
/// than followed; this prevents cycles and publishing outside the selected root.
#[derive(Clone, Copy, Debug)]
pub struct ScanLimits {
    /// Maximum original source objects across the scan.
    pub objects: u64,
    /// Maximum entries in one directory listing.
    pub children: usize,
    /// Maximum raw basename bytes.
    pub name_bytes: usize,
    /// Maximum retained directory-name bytes along the DFS frontier.
    pub names_bytes: usize,
    /// Maximum component depth.
    pub depth: usize,
    /// Maximum logical regular-file bytes across a complete scan.
    pub file_bytes: u64,
}
impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            objects: 65536,
            children: 4096,
            name_bytes: 255,
            names_bytes: 8 * 1024 * 1024,
            depth: 64,
            file_bytes: 256 * 1024 * 1024,
        }
    }
}
impl ScanLimits {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.objects == 0
            || self.children == 0
            || self.children > 65536
            || self.name_bytes == 0
            || self.name_bytes > 4096
            || self.names_bytes == 0
            || self.names_bytes > 64 * 1024 * 1024
            || self.depth == 0
            || self.depth > 256
        {
            return Err(Error::Binding("invalid auto-share scan limits"));
        }
        Ok(())
    }
}
/// Exact native source condition; no failed/incomplete scan marks an item deleted.
#[derive(Debug)]
pub enum ScanError {
    /// Original source IO/identity/mapping error.
    Source(SourceError),
    /// Root/path changed around the scan.
    Changed,
    /// Caller stopped between bounded native operations.
    Stopped,
    /// An explicit source/work/storage limit refused the scan.
    Limit,
}
impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(e) => e.fmt(f),
            Self::Changed => f.write_str("auto-share source changed during scan"),
            Self::Stopped => f.write_str("auto-share scan stopped"),
            Self::Limit => f.write_str("auto-share scan limit exceeded"),
        }
    }
}
impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(e) => Some(e),
            _ => None,
        }
    }
}
impl From<SourceError> for ScanError {
    fn from(e: SourceError) -> Self {
        Self::Source(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    File,
    Directory,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub name: Vec<u8>,
    pub fingerprint: [u8; 64],
    pub kind: EntryKind,
    pub bytes: u64,
    pub objects: u64,
}
pub(crate) struct Snapshot {
    pub entries: Vec<Entry>,
    pub objects: u64,
    pub bytes: u64,
}
struct Frame {
    source: FrameSource,
    next: usize,
}
fn cancelled(stop: &Stop) -> Result<(), ScanError> {
    if stop.requested() {
        Err(ScanError::Stopped)
    } else {
        Ok(())
    }
}
fn identity(a: Stamp, b: Stamp) -> bool {
    a.kind == b.kind && a.device == b.device && a.inode == b.inode
}
fn item(hash: &mut Hash512State, name: &[u8], stamp: Stamp) {
    hash.update(&(name.len() as u64).to_be_bytes());
    hash.update(name);
    stamp.hash(hash)
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, ScanError> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| ScanError::Limit)?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn tree(
    file: File,
    original: Stamp,
    limits: ScanLimits,
    stop: &Stop,
) -> Result<([u8; 64], u64, u64), ScanError> {
    cancelled(stop)?;
    let mut hash = Hash512State::new();
    hash.update(b"gnunet-rs auto-share stat tree v1\0");
    original.hash(&mut hash);
    let mut objects = 1u64;
    if objects > limits.objects {
        return Err(ScanError::Limit);
    }
    let mut bytes = if original.kind == Kind::File {
        original.bytes
    } else {
        0
    };
    if bytes > limits.file_bytes {
        return Err(ScanError::Limit);
    }
    if original.kind == Kind::File {
        if stamp(&file)? != original {
            return Err(ScanError::Changed);
        }
        return Ok((hash.finish(), objects, bytes));
    }
    let first = FrameSource::scan(file, limits.children, limits.name_bytes, limits.names_bytes)?;
    let mut charged = first.names_bytes;
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(limits.depth)
        .map_err(|_| ScanError::Limit)?;
    stack.push(Frame {
        source: first,
        next: 0,
    });
    while !stack.is_empty() {
        cancelled(stop)?;
        let last = stack.len() - 1;
        if stack[last].next == stack[last].source.names.len() {
            stack[last].source.verify()?;
            charged = charged
                .checked_sub(stack[last].source.names_bytes)
                .ok_or(ScanError::Limit)?;
            hash.update(&[0xff]);
            stack.pop();
            continue;
        }
        let index = stack[last].next;
        stack[last].next += 1;
        let child = stack[last].source.open(index)?;
        let observed = stamp(&child)?;
        let name = &stack[last].source.names[index];
        if observed != name.stamp {
            return Err(ScanError::Changed);
        }
        item(&mut hash, &name.bytes, observed);
        objects = objects
            .checked_add(1)
            .filter(|n| *n <= limits.objects)
            .ok_or(ScanError::Limit)?;
        if observed.kind == Kind::File {
            bytes = bytes
                .checked_add(observed.bytes)
                .filter(|n| *n <= limits.file_bytes)
                .ok_or(ScanError::Limit)?;
            if stamp(&child)? != observed {
                return Err(ScanError::Changed);
            }
        } else {
            if stack.len() == limits.depth {
                return Err(ScanError::Limit);
            }
            let remaining = limits
                .names_bytes
                .checked_sub(charged)
                .ok_or(ScanError::Limit)?;
            let source = FrameSource::scan(child, limits.children, limits.name_bytes, remaining)?;
            charged = charged
                .checked_add(source.names_bytes)
                .ok_or(ScanError::Limit)?;
            stack.push(Frame { source, next: 0 });
        }
    }
    Ok((hash.finish(), objects, bytes))
}
pub(crate) fn observe(
    root: &Path,
    expected: (u64, u64),
    limits: ScanLimits,
    stop: &Stop,
) -> Result<Snapshot, ScanError> {
    cancelled(stop)?;
    let input = InputDir::open(root)?;
    let original = stamp(input.descriptor())?;
    if (original.device, original.inode) != expected {
        return Err(ScanError::Changed);
    }
    let frame = FrameSource::scan(
        input.descriptor().try_clone().map_err(SourceError::from)?,
        limits.children,
        limits.name_bytes,
        limits.names_bytes,
    )?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(frame.names.len())
        .map_err(|_| ScanError::Limit)?;
    let mut objects = 0u64;
    let mut bytes = 0u64;
    let mut output_names = 0usize;
    for (index, name) in frame.names.iter().enumerate() {
        cancelled(stop)?;
        // C's private state and this independently marked Rust state are never part
        // of published content. No C state body is opened/read/adopted.
        if name.bytes.starts_with(b".auto-share") {
            continue;
        }
        let child = frame.open(index)?;
        output_names = output_names
            .checked_add(name.bytes.len())
            .ok_or(ScanError::Limit)?;
        let mut available = limits;
        available.names_bytes = limits
            .names_bytes
            .checked_sub(frame.names_bytes)
            .and_then(|n| n.checked_sub(output_names))
            .ok_or(ScanError::Limit)?;
        available.objects = limits
            .objects
            .checked_sub(objects)
            .ok_or(ScanError::Limit)?;
        available.file_bytes = limits
            .file_bytes
            .checked_sub(bytes)
            .ok_or(ScanError::Limit)?;
        let (fingerprint, count, size) = tree(child, name.stamp, available, stop)?;
        objects = objects.checked_add(count).ok_or(ScanError::Limit)?;
        bytes = bytes.checked_add(size).ok_or(ScanError::Limit)?;
        entries.push(Entry {
            name: copy(&name.bytes)?,
            fingerprint,
            kind: if name.kind == Kind::File {
                EntryKind::File
            } else {
                EntryKind::Directory
            },
            bytes: size,
            objects: count,
        });
    }
    frame.verify()?;
    let named = InputDir::open(root)?;
    if !identity(original, stamp(named.descriptor())?) || stamp(input.descriptor())? != original {
        return Err(ScanError::Changed);
    }
    Ok(Snapshot {
        entries,
        objects,
        bytes,
    })
}

/// Recheck one original top-level path without scanning all other subtrees.
pub(super) fn single(
    root: &Path,
    expected: (u64, u64),
    name: &[u8],
    limits: ScanLimits,
    stop: &Stop,
) -> Result<Entry, ScanError> {
    use nix::{
        fcntl::{AtFlags, OFlag, openat},
        sys::stat::{Mode, fstatat},
    };
    use std::os::unix::ffi::OsStrExt;
    cancelled(stop)?;
    let directory = InputDir::open(root)?;
    let parent = stamp(directory.descriptor())?;
    if (parent.device, parent.inode) != expected {
        return Err(ScanError::Changed);
    }
    let component = std::ffi::OsStr::from_bytes(name);
    let before = fstatat(
        directory.descriptor(),
        component,
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(SourceError::from)?;
    let fd = openat(
        directory.descriptor(),
        component,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(SourceError::from)?;
    let file = File::from(fd);
    let observed = stamp(&file)?;
    if observed.device != before.st_dev as u64 || observed.inode != before.st_ino as u64 {
        return Err(ScanError::Changed);
    }
    let (fingerprint, objects, bytes) = tree(file, observed, limits, stop)?;
    let after = fstatat(
        directory.descriptor(),
        component,
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(SourceError::from)?;
    let named = InputDir::open(root)?;
    let end = stamp(named.descriptor())?;
    if observed.device != after.st_dev as u64
        || observed.inode != after.st_ino as u64
        || (end.device, end.inode) != expected
    {
        return Err(ScanError::Changed);
    }
    Ok(Entry {
        name: copy(name)?,
        fingerprint,
        kind: if observed.kind == Kind::File {
            EntryKind::File
        } else {
            EntryKind::Directory
        },
        bytes,
        objects,
    })
}
/// Logical bytes of regular files in an owned prepared group; no payload body
/// is read. This is not physical block/RSS accounting or a storage ACK.
pub(super) fn owned_bytes(
    path: &Path,
    expected: (u64, u64),
    limits: ScanLimits,
    stop: &Stop,
) -> Result<u64, ScanError> {
    let input = InputDir::open(path)?;
    let original = stamp(input.descriptor())?;
    if (original.device, original.inode) != expected {
        return Err(ScanError::Changed);
    }
    let (_, _, bytes) = tree(
        input.descriptor().try_clone().map_err(SourceError::from)?,
        original,
        limits,
        stop,
    )?;
    let named = InputDir::open(path)?;
    if !identity(original, stamp(named.descriptor())?) {
        return Err(ScanError::Changed);
    }
    Ok(bytes)
}
