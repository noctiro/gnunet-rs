//! Extraction-local causes without a service or publication error dependency.
use std::{fmt, io};
/// Original local source, metadata, provider or caller refusal.
#[derive(Debug)]
pub enum Error {
    /// Invalid explicit metadata or workspace policy.
    Policy,
    /// Original local filesystem failure.
    Io(io::Error),
    /// Checked representation or official text/metadata coordinate refusal.
    Protocol(gnunet_types::Error),
    /// Original standard metadata framing/serialization refusal.
    Metadata(gnunet_fs::metadata::Error),
    /// Original descriptor-root enumeration or source-identity refusal.
    Source(crate::input_tree::SourceError),
    /// An explicit metadata, term or allocation bound was exceeded.
    Limit,
    /// Caller stopped between original extraction boundaries.
    Cancelled,
    /// The original held descriptor changed during extraction or delivery.
    SourceChanged,
    /// Metadata or explicit selection does not match the required shape.
    Binding,
    /// Original native provider/caller refusal and descriptor restore facts.
    Extractor(Box<gnunet_extractor_host::Failure<Error>>),
    /// Original invalid native provider selection.
    MetadataSettings(gnunet_extractor_host::NativeError),
    /// Independent actual provider close refusal, retaining any earlier cause.
    ExtractorCleanup {
        /// Earlier original refusal, if present.
        original: Option<Box<Error>>,
        /// Independent physical provider close refusal.
        cleanup: gnunet_extractor_host::NativeError,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy => f.write_str("invalid metadata extraction policy"),
            Self::Io(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
            Self::Metadata(error) => error.fmt(f),
            Self::Source(error) => error.fmt(f),
            Self::Limit => f.write_str("metadata extraction limit exceeded"),
            Self::Cancelled => f.write_str("metadata extraction cancelled"),
            Self::SourceChanged => f.write_str("metadata input changed"),
            Self::Binding => f.write_str("metadata extraction binding mismatch"),
            Self::Extractor(error) => error.fmt(f),
            Self::MetadataSettings(error) => error.fmt(f),
            Self::ExtractorCleanup { original, cleanup } => {
                if let Some(original) = original {
                    write!(f, "{original}; ")?;
                }
                write!(f, "independent metadata provider cleanup: {cleanup}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Metadata(error) => Some(error),
            Self::Source(error) => Some(error),
            Self::Extractor(error) => Some(error.as_ref()),
            Self::MetadataSettings(error) => Some(error),
            Self::ExtractorCleanup {
                original: Some(error),
                ..
            } => Some(error.as_ref()),
            Self::ExtractorCleanup { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<gnunet_types::Error> for Error {
    fn from(error: gnunet_types::Error) -> Self {
        Self::Protocol(error)
    }
}
impl From<gnunet_fs::metadata::Error> for Error {
    fn from(error: gnunet_fs::metadata::Error) -> Self {
        Self::Metadata(error)
    }
}
impl From<crate::input_tree::SourceError> for Error {
    fn from(error: crate::input_tree::SourceError) -> Self {
        Self::Source(error)
    }
}
impl From<gnunet_extractor_host::Failure<Error>> for Error {
    fn from(error: gnunet_extractor_host::Failure<Error>) -> Self {
        Self::Extractor(Box::new(error))
    }
}
