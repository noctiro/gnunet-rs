//! Original-handle input roots and bounded native source enumeration.
//! Local names remain native strings. Protocol text encoding belongs to the
//! publication/metadata boundary, never the directory cursor.
#[cfg(feature = "extraction")]
mod frame;
#[cfg(feature = "network")]
pub(crate) use frame::Stamp;
#[cfg(feature = "extraction")]
pub(crate) use frame::{FrameSource, Kind, Name, stamp};
use gnunet_native::filesystem::{Directory, EntryInfo};
use gnunet_types::Error as ProtocolError;
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io,
    path::Path,
};

/// Bounds actually consumed by a live descriptor-root walk.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum relative component depth; the root has depth zero.
    pub max_depth: usize,
    /// Total file/directory entries excluding the selected root.
    pub max_entries: u64,
    /// Maximum immediate children retained in one sorted listing.
    pub max_children: usize,
    /// Maximum bytes in one native basename representation.
    pub max_name_bytes: usize,
    /// Maximum bytes in the native root-relative path representation.
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

/// Open one actual regular source without following its final name surrogate
/// or waiting for a concurrently substituted FIFO. Ancestors select the parent
/// once; subsequent checks and opens use that original directory handle.
pub fn open_regular(path: impl AsRef<Path>) -> Result<File, SourceError> {
    let file = open_source(path.as_ref())?;
    if !matches!(
        gnunet_native::filesystem::file_info(&file)?,
        EntryInfo::File(_)
    ) {
        return Err(SourceError::Unsupported);
    }
    Ok(file)
}
/// Open one file/directory through a held original parent. The name must map to
/// the opened identity both before and after the native open.
pub(crate) fn open_source(path: &Path) -> Result<File, SourceError> {
    let name = path
        .file_name()
        .ok_or(SourceError::Protocol(ProtocolError::InvalidInput))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = Directory::open(&std::fs::canonicalize(parent)?)?;
    observe(&parent, name).map(|(file, _)| file)
}
fn observe(parent: &Directory, name: &OsStr) -> Result<(File, EntryInfo), SourceError> {
    let before = parent.entry_info(name)?;
    let file = match before {
        EntryInfo::File(_) => parent.open_file(name)?,
        EntryInfo::Directory(_) => parent.open_source_directory(name)?.into_file(),
        EntryInfo::Other => return Err(SourceError::Unsupported),
    };
    let actual = gnunet_native::filesystem::file_info(&file)?;
    fn identity(info: EntryInfo) -> Result<(bool, crate::FileIdentity), SourceError> {
        match info {
            EntryInfo::File(info) => Ok((false, info.identity)),
            EntryInfo::Directory(info) => Ok((true, info.identity)),
            EntryInfo::Other => Err(SourceError::Unsupported),
        }
    }
    if identity(before)? != identity(actual)?
        || identity(parent.entry_info(name)?)? != identity(actual)?
    {
        return Err(SourceError::Changed);
    }
    Ok((file, actual))
}

/// A selected directory held by its original native handle. Renaming its old
/// pathname cannot redirect later child opens. Symlinks and name surrogates
/// are refused; special-file data is never read.
#[derive(Debug)]
pub struct InputDir {
    root: Directory,
}
impl InputDir {
    /// Open the selected root without following its final symlink component.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SourceError> {
        Ok(Self {
            root: Directory::open_source(path.as_ref())?,
        })
    }
    /// Take an owned directory file and retain an original-object directory owner.
    pub fn from_file(root: File) -> Result<Self, SourceError> {
        Ok(Self {
            root: Directory::from_source_file(&root)?,
        })
    }
    /// Borrow the actual selected root independently of its original pathname.
    #[must_use]
    pub fn descriptor(&self) -> &File {
        self.root.as_file()
    }
    /// Open an ordinary file/directory child while checking the original mapping.
    /// The native leaf validator rejects separators, NUL, dot and parent names.
    pub fn open_child(&self, name: &OsStr) -> Result<File, SourceError> {
        observe(&self.root, name).map(|(file, _)| file)
    }
}
/// Actual native source refusal, with the original I/O failure retained.
#[derive(Debug)]
pub enum SourceError {
    /// Original filesystem failure, including the native errno when available.
    Io(io::Error),
    /// A source entry is a symlink, name surrogate or special file.
    Unsupported,
    /// An observed descriptor, directory listing or entry mapping changed.
    Changed,
    /// A caller-selected enumeration or name-storage bound was exceeded.
    Limit,
    /// Invalid caller-provided index or component.
    Protocol(ProtocolError),
    /// Original scan failure at this exact native child name. The caller can append
    /// this component to its retained parent-relative path without decoding it.
    Entry {
        /// Exact native basename, without a final NUL.
        name: OsString,
        /// Original failure, including its native I/O cause when present.
        cause: Box<SourceError>,
    },
}
impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "FS input tree I/O: {error}"),
            Self::Unsupported => {
                f.write_str("FS input tree contains a symlink, name surrogate or special file")
            }
            Self::Changed => f.write_str("FS input tree changed during inspection or transfer"),
            Self::Limit => f.write_str("FS input tree exceeds its resource limits"),
            Self::Protocol(error) => write!(f, "FS input tree: {error}"),
            Self::Entry { name, cause } => {
                write!(f, "FS tree entry {:?}: {cause}", name)
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

/// Encode a source basename only at the protocol metadata boundary. Windows
/// requires Unicode; internal WTF-8/local path bytes must never enter metadata.
#[cfg(feature = "extraction")]
pub(crate) fn protocol_name(name: &OsStr) -> Result<&[u8], SourceError> {
    #[cfg(unix)]
    {
        Ok(name.as_encoded_bytes())
    }
    #[cfg(windows)]
    {
        name.to_str()
            .map(str::as_bytes)
            .ok_or(SourceError::Protocol(ProtocolError::InvalidInput))
    }
}

/// Encode a native relative source coordinate using protocol basenames and
/// slash separators. The descriptor walk itself keeps native paths.
#[cfg(feature = "network")]
pub(crate) fn protocol_path(path: &Path) -> Result<Vec<u8>, SourceError> {
    let mut bytes = Vec::new();
    // Separators are one byte with either spelling; Windows rejects names
    // that cannot be represented in protocol text.
    bytes
        .try_reserve_exact(path.as_os_str().as_encoded_bytes().len())
        .map_err(|_| SourceError::Protocol(ProtocolError::Capacity))?;
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(SourceError::Protocol(ProtocolError::InvalidInput));
        };
        let name = protocol_name(name)?;
        if !bytes.is_empty() {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(name);
    }
    Ok(bytes)
}
