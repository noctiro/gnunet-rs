//! Descriptor-anchored, bounded native input enumeration shared by local
//! metadata inspection, publication preparation and change detection.
#[cfg(feature = "network")]
use gnunet_crypto::Hash512State;
use gnunet_types::Error as ProtocolError;
use nix::{
    fcntl::{AtFlags, OFlag, open, openat},
    sys::stat::{Mode, SFlag, fstatat},
};
use std::{
    ffi::OsStr,
    fmt,
    fs::File,
    io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC);
const REGULAR: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC);

/// Bounds actually consumed by a live descriptor-root walk.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum relative component depth; the root has depth zero.
    pub max_depth: usize,
    /// Total file/directory entries excluding the selected root.
    pub max_entries: u64,
    /// Maximum immediate children retained in one sorted listing.
    pub max_children: usize,
    /// Maximum raw Unix basename bytes.
    pub max_name_bytes: usize,
    /// Maximum complete root-relative path bytes.
    pub max_path_bytes: usize,
    /// Name bytes retained across the entire live DFS stack.
    pub max_retained_name_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_entries: 65_536,
            max_children: 4096,
            max_name_bytes: 8192,
            max_path_bytes: 4096,
            max_retained_name_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Open one actual regular source without following its final symlink or
/// waiting on a concurrently substituted FIFO/special file.
pub fn open_regular(path: impl AsRef<Path>) -> Result<File, SourceError> {
    let file = File::from(open(path.as_ref(), REGULAR, Mode::empty())?);
    if stamp(&file)?.kind != Kind::File {
        return Err(SourceError::Unsupported);
    }
    Ok(file)
}

/// Actual native source refusal, with the original I/O failure retained.
#[derive(Debug)]
pub enum SourceError {
    /// Original filesystem failure, including the native errno when available.
    Io(io::Error),
    /// A source entry is a symlink or a special file rather than a file/directory.
    Unsupported,
    /// An observed descriptor, directory listing or entry mapping changed.
    Changed,
    /// A caller-selected enumeration or name-storage bound was exceeded.
    Limit,
    /// Invalid caller-provided index or component.
    Protocol(ProtocolError),
    /// Original scan failure at this exact raw child name. The caller can append
    /// this component to its retained parent-relative path without decoding it.
    Entry {
        /// Exact basename bytes, without a final NUL.
        name: Vec<u8>,
        /// Original failure, including its native I/O cause when present.
        cause: Box<SourceError>,
    },
}
impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "FS input tree I/O: {error}"),
            Self::Unsupported => f.write_str("FS input tree contains a symlink or special file"),
            Self::Changed => f.write_str("FS input tree changed during inspection or transfer"),
            Self::Limit => f.write_str("FS input tree exceeds its resource limits"),
            Self::Protocol(error) => write!(f, "FS input tree: {error}"),
            Self::Entry { name, cause } => {
                write!(f, "FS tree entry {:?}: {cause}", OsStr::from_bytes(name))
            }
        }
    }
}
impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Entry { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for SourceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<nix::errno::Errno> for SourceError {
    fn from(error: nix::errno::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error as i32))
    }
}

/// A caller-selected existing directory, held by its actual descriptor. Renaming
/// the original pathname cannot redirect any later child open. No source path,
/// symlink target or special-file contents are followed during enumeration.
pub struct InputDir {
    root: File,
}
impl InputDir {
    /// Open the selected root without following its final symlink component.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SourceError> {
        Self::from_file(File::from(open(path.as_ref(), DIRECTORY, Mode::empty())?))
    }
    /// Take an already-owned root descriptor and verify its actual file type.
    pub fn from_file(root: File) -> Result<Self, SourceError> {
        if stamp(&root)?.kind != Kind::Directory {
            return Err(SourceError::Unsupported);
        }
        Ok(Self { root })
    }
    /// Borrow the actual selected root, independently of its original pathname.
    #[must_use]
    pub fn descriptor(&self) -> &File {
        &self.root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    File,
    Directory,
}

/// Source identity and change observations. Atime is deliberately excluded:
/// reading a regular source or enumerating a directory may update it normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Stamp {
    pub kind: Kind,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub modified: i64,
    pub modified_nanos: i64,
    pub changed: i64,
    pub changed_nanos: i64,
}
impl Stamp {
    /// Fixed-width portable encoding for the caller's ordered-tree fingerprint.
    #[cfg(feature = "network")]
    pub fn hash(self, state: &mut Hash512State) {
        state.update(&[match self.kind {
            Kind::File => 1,
            Kind::Directory => 2,
        }]);
        state.update(&self.device.to_be_bytes());
        state.update(&self.inode.to_be_bytes());
        state.update(&self.bytes.to_be_bytes());
        state.update(&self.modified.to_be_bytes());
        state.update(&self.modified_nanos.to_be_bytes());
        state.update(&self.changed.to_be_bytes());
        state.update(&self.changed_nanos.to_be_bytes());
    }
}
pub(crate) fn stamp(file: &File) -> Result<Stamp, SourceError> {
    let metadata = file.metadata()?;
    let kind = if metadata.is_file() {
        Kind::File
    } else if metadata.is_dir() {
        Kind::Directory
    } else {
        return Err(SourceError::Unsupported);
    };
    Ok(Stamp {
        kind,
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    })
}

#[derive(Debug)]
pub(crate) struct Name {
    pub bytes: Vec<u8>,
    pub kind: Kind,
    pub stamp: Stamp,
}

fn component(bytes: &[u8]) -> Result<&OsStr, SourceError> {
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&0)
        || bytes.contains(&b'/')
    {
        return Err(SourceError::Protocol(ProtocolError::InvalidInput));
    }
    Ok(OsStr::from_bytes(bytes))
}
fn at_entry(name: &[u8], cause: SourceError) -> SourceError {
    let mut bytes = Vec::new();
    // Diagnostic allocation exhaustion must not erase the original failure.
    if bytes.try_reserve_exact(name.len()).is_err() {
        return cause;
    }
    bytes.extend_from_slice(name);
    SourceError::Entry {
        name: bytes,
        cause: Box::new(cause),
    }
}
fn kind(mode: nix::libc::mode_t) -> Result<Kind, SourceError> {
    let flags = SFlag::from_bits_truncate(mode) & SFlag::S_IFMT;
    if flags == SFlag::S_IFDIR {
        Ok(Kind::Directory)
    } else if flags == SFlag::S_IFREG {
        Ok(Kind::File)
    } else {
        Err(SourceError::Unsupported)
    }
}
fn observe(parent: &File, name: &OsStr) -> Result<(File, Stamp), SourceError> {
    // Refuse an observed special file before opening. NONBLOCK also prevents a
    // concurrent substitution with a FIFO from waiting for an external writer.
    let before = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    let expected = kind(before.st_mode)?;
    let flags = match expected {
        Kind::File => REGULAR,
        Kind::Directory => DIRECTORY,
    };
    let file = File::from(openat(parent, name, flags, Mode::empty())?);
    let actual = stamp(&file)?;
    if actual.kind != expected
        || actual.device != before.st_dev as u64
        || actual.inode != before.st_ino as u64
    {
        return Err(SourceError::Changed);
    }
    let after = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    if kind(after.st_mode)? != actual.kind
        || actual.device != after.st_dev as u64
        || actual.inode != after.st_ino as u64
    {
        return Err(SourceError::Changed);
    }
    Ok((file, actual))
}

/// One bounded sorted directory listing. Only this directory descriptor stays
/// open; child descriptors used for metadata capture are closed immediately.
pub(crate) struct FrameSource {
    pub file: File,
    pub stamp: Stamp,
    pub names: Vec<Name>,
    pub names_bytes: usize,
}
impl FrameSource {
    pub fn scan(
        file: File,
        max_children: usize,
        max_name_bytes: usize,
        max_names_bytes: usize,
    ) -> Result<Self, SourceError> {
        let original = stamp(&file)?;
        if original.kind != Kind::Directory {
            return Err(SourceError::Unsupported);
        }
        // A new open description starts at offset zero without altering a
        // caller descriptor's readdir cursor, unlike dup/try_clone alone.
        let enumeration = openat(&file, c".", DIRECTORY, Mode::empty())?;
        let mut directory = nix::dir::Dir::from_fd(enumeration)?;
        let mut names = Vec::new();
        let mut names_bytes = 0_usize;
        for entry in directory.iter() {
            let entry = entry?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            let name = component(raw).map_err(|cause| at_entry(raw, cause))?;
            if names.len() == max_children || raw.len() > max_name_bytes {
                return Err(SourceError::Limit);
            }
            names_bytes = names_bytes
                .checked_add(raw.len())
                .filter(|total| *total <= max_names_bytes)
                .ok_or(SourceError::Limit)?;
            let (_, observed) = observe(&file, name).map_err(|cause| at_entry(raw, cause))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(raw.len())
                .map_err(|_| SourceError::Limit)?;
            bytes.extend_from_slice(raw);
            names.try_reserve(1).map_err(|_| SourceError::Limit)?;
            names.push(Name {
                bytes,
                kind: observed.kind,
                stamp: observed,
            });
        }
        names.sort_unstable_by(|left, right| left.bytes.cmp(&right.bytes));
        if names.windows(2).any(|pair| pair[0].bytes == pair[1].bytes) || stamp(&file)? != original
        {
            return Err(SourceError::Changed);
        }
        Ok(Self {
            file,
            stamp: original,
            names,
            names_bytes,
        })
    }
    /// Verify this directory's captured stamp. Descendant file changes are
    /// checked separately through open() and the caller's final tree pass.
    pub fn verify(&self) -> Result<(), SourceError> {
        if stamp(&self.file)? != self.stamp {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
    /// Open the same observed child through the original parent descriptor.
    pub fn open(&self, index: usize) -> Result<File, SourceError> {
        let name = self
            .names
            .get(index)
            .ok_or(SourceError::Protocol(ProtocolError::InvalidInput))?;
        self.verify()?;
        let (file, observed) = observe(&self.file, component(&name.bytes)?)?;
        if observed != name.stamp {
            return Err(SourceError::Changed);
        }
        self.verify()?;
        Ok(file)
    }
}
