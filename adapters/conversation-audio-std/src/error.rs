use std::{fmt, io};
/// Actual framing/codec/device/loader/I/O refusal. Audio bytes are never logged.
#[derive(Debug)]
pub enum Error {
    /// Original finite resource or malformed input classification.
    Protocol(gnunet_types::Error),
    /// Actual partial pipe read/write with its independent native error.
    Io {
        /// Original boundary.
        operation: &'static str,
        /// Bytes completed at that original boundary.
        completed: usize,
        /// Original native error.
        source: io::Error,
    },
    /// A pipe ended partway through an original header/body.
    Truncated {
        /// Original boundary.
        operation: &'static str,
        /// Actual prefix bytes.
        actual: usize,
        /// Required whole extent.
        expected: usize,
    },
    /// Actual standard provider return code; no errno is invented.
    Provider {
        /// Actual standard library family.
        provider: &'static str,
        /// Original requested operation.
        operation: &'static str,
        /// Actual returned native code.
        code: i32,
    },
    /// Actual POSIX loader diagnostic. Bounded text is retained directly because
    /// dlerror supplies text, not a Rust error object or reliable errno.
    Loader {
        /// Exact selected candidate/symbol context.
        operation: &'static str,
        /// Original diagnostic prefix.
        detail: String,
        /// Whether the configured diagnostic cap truncated it.
        truncated: bool,
    },
    /// A known Ogg checksum did not match its actual protected page bytes.
    Checksum,
    /// Ogg stream/sequence/continuation/granule semantics were invalid.
    Ogg(&'static str),
    /// Independent error while flushing/draining an already failed operation.
    Cleanup {
        /// Original source/protocol error.
        original: Box<Error>,
        /// Independent actual cleanup failure.
        cleanup: Box<Error>,
    },
    /// Actual OS entropy failure before creating a stream serial.
    Entropy(getrandom::Error),
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Io {
                operation,
                completed,
                source,
            } => write!(f, "{operation} after {completed} bytes: {source}"),
            Self::Truncated {
                operation,
                actual,
                expected,
            } => write!(f, "{operation}: truncated {actual}/{expected}"),
            Self::Provider {
                provider,
                operation,
                code,
            } => write!(f, "{provider} {operation}: native code {code}"),
            Self::Loader {
                operation,
                detail,
                truncated,
            } => write!(
                f,
                "loader {operation}: {detail} (diagnostic-truncated={truncated})"
            ),
            Self::Checksum => f.write_str("Ogg CRC mismatch"),
            Self::Ogg(reason) => write!(f, "Ogg: {reason}"),
            Self::Cleanup { original, cleanup } => write!(f, "{original}; cleanup: {cleanup}"),
            Self::Entropy(e) => write!(f, "audio stream serial entropy: {e}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Io { source, .. } => Some(source),
            Self::Cleanup { original, .. } => Some(original.as_ref()),
            _ => None,
        }
    }
}
