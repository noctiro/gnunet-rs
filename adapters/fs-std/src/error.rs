use std::{fmt, io};

/// Native FS refusal, preserving uncertain storage outcomes.
#[derive(Debug)]
pub enum Error {
    /// Original filesystem or byte-stream failure.
    Io(io::Error),
    /// Official content/URI cryptography or framing refusal.
    Protocol(gnunet_types::Error),
    /// Directory artifact or construction refusal.
    Directory(gnunet_fs::directory::Error),
    /// Directory source-coordinate or authenticated-source refusal.
    Source(gnunet_fs::directory::SourceError),
    /// Original bounded recursive directory ownership refusal.
    Walk(gnunet_fs::directory::walk::Error),
    /// Original authenticated native namespace lookup failure.
    #[cfg(feature = "service")]
    Search(Box<crate::search::Error>),
    /// Original native transfer cause and outcome, retained without relabeling.
    #[cfg(feature = "service")]
    Transfer(Box<crate::network::Error>),
    /// Original selected transfer cause and its actual authenticated/delivered
    /// prefix, without converting a range receipt into whole-file success.
    #[cfg(feature = "service")]
    Range(Box<crate::network::range::Failure>),
    /// A caller file/work/storage bound was exceeded.
    Limit,
    /// Caller stopped between actual block operations.
    Cancelled,
    /// Stored bytes have a wrong length, shape or content-addressed identity.
    Corrupt,
    /// Source identity, length, contents or metadata changed during verification,
    /// or input contains bytes beyond its declared file length.
    SourceChanged,
    /// The final file is known durable, but temporary cleanup needs attention.
    CleanupAfterCommit {
        /// Original file query; the destination belongs to the caller.
        query: [u8; 64],
        /// Actual temporary cleanup failure after confirmed final durability.
        source: io::Error,
    },
    /// Original failure plus inability to remove its owned temporary.
    CleanupFailed {
        /// Preserve the original cancellation, integrity or I/O cause.
        cause: Box<Error>,
        /// Actual cleanup failure, independently of that original cause.
        source: io::Error,
    },
    /// The immutable object may be present, but durability is uncertain.
    CommitUnknown {
        /// Original file/block query; named outputs also require their destination.
        query: [u8; 64],
        /// Actual failure after the object link was created.
        source: io::Error,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "FS I/O: {e}"),
            Self::Protocol(e) => write!(f, "FS protocol: {e}"),
            Self::Directory(e) => e.fmt(f),
            Self::Source(e) => e.fmt(f),
            Self::Walk(e) => e.fmt(f),
            #[cfg(feature = "service")]
            Self::Search(e) => e.fmt(f),
            #[cfg(feature = "service")]
            Self::Transfer(e) => e.fmt(f),
            #[cfg(feature = "service")]
            Self::Range(e) => e.fmt(f),
            Self::Limit => f.write_str("FS resource limit exceeded"),
            Self::Cancelled => f.write_str("FS operation cancelled"),
            Self::Corrupt => f.write_str("FS stored block is corrupt"),
            Self::SourceChanged => f.write_str("FS source changed or exceeds its declared size"),
            Self::CleanupAfterCommit { source, .. } => {
                write!(f, "FS file committed; temporary cleanup failed: {source}")
            }
            Self::CleanupFailed { cause, source } => {
                write!(f, "{cause}; FS temporary cleanup also failed: {source}")
            }
            Self::CommitUnknown { source, .. } => {
                write!(f, "FS object durability is uncertain: {source}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e)
            | Self::CommitUnknown { source: e, .. }
            | Self::CleanupAfterCommit { source: e, .. } => Some(e),
            Self::CleanupFailed { cause, .. } => Some(cause.as_ref()),
            Self::Protocol(e) => Some(e),
            #[cfg(feature = "service")]
            Self::Transfer(e) => Some(e.as_ref()),
            #[cfg(feature = "service")]
            Self::Range(e) => Some(e.as_ref()),
            Self::Directory(e) => Some(e),
            Self::Source(e) => Some(e),
            Self::Walk(e) => Some(e),
            #[cfg(feature = "service")]
            Self::Search(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<nix::errno::Errno> for Error {
    fn from(e: nix::errno::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(e as i32))
    }
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_fs::directory::Error> for Error {
    fn from(e: gnunet_fs::directory::Error) -> Self {
        Self::Directory(e)
    }
}
impl From<gnunet_fs::directory::SourceError> for Error {
    fn from(e: gnunet_fs::directory::SourceError) -> Self {
        Self::Source(e)
    }
}
impl From<gnunet_fs::directory::walk::Error> for Error {
    fn from(e: gnunet_fs::directory::walk::Error) -> Self {
        Self::Walk(e)
    }
}
#[cfg(feature = "service")]
impl From<crate::search::Error> for Error {
    fn from(e: crate::search::Error) -> Self {
        Self::Search(Box::new(e))
    }
}
#[cfg(feature = "service")]
impl From<crate::network::Error> for Error {
    fn from(e: crate::network::Error) -> Self {
        Self::Transfer(Box::new(e))
    }
}
#[cfg(feature = "service")]
impl From<crate::network::range::Failure> for Error {
    fn from(e: crate::network::range::Failure) -> Self {
        Self::Range(Box::new(e))
    }
}
/// Result from a local FS host operation.
pub type Result<T> = std::result::Result<T, Error>;
