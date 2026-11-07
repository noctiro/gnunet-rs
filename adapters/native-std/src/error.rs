//! Native hostname and resolution errors shared across operating systems.
use std::{ffi::OsString, fmt, io};
/// Native FQDN lookup failure; no hostname is fabricated on resolution failure.
#[derive(Debug)]
pub enum NativeError {
    /// A system call, allocation or native-result validation failed.
    System(io::Error),
    /// The native `getaddrinfo` error, separate from `errno`.
    NameResolution {
        /// Exact native EAI error code.
        code: i32,
        /// Native diagnostic bytes, retained without a UTF-8 requirement.
        message: OsString,
    },
}
impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System(error) => error.fmt(formatter),
            Self::NameResolution { code, message } => {
                write!(
                    formatter,
                    "getaddrinfo ({code}): {}",
                    message.to_string_lossy()
                )
            }
        }
    }
}
impl std::error::Error for NativeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::System(error) => Some(error),
            Self::NameResolution { .. } => None,
        }
    }
}
impl From<io::Error> for NativeError {
    fn from(error: io::Error) -> Self {
        Self::System(error)
    }
}
