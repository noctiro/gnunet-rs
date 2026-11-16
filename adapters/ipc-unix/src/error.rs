//! Original configuration, native I/O, protocol, deadline and retirement errors.
use gnunet_types::Error;
use std::{fmt, io};
/// Boundary failures from the OS, original deadline or official message validation.
#[derive(Debug)]
pub enum IpcError {
    /// Official service configuration/path validation failed.
    Configuration(gnunet_config::Error),
    /// An OS/socket failure.
    Io(io::Error),
    /// Invalid/unsupported official message or exhausted caller capacity.
    Protocol(Error),
    /// The original operation deadline elapsed.
    Deadline,
    /// A failed/cancelled operation has retired this connection.
    Closed,
}
impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "IPC configuration: {error}"),
            Self::Io(error) => write!(f, "IPC I/O: {error}"),
            Self::Protocol(error) => write!(f, "IPC protocol: {error:?}"),
            Self::Deadline => f.write_str("IPC deadline elapsed"),
            Self::Closed => f.write_str("IPC connection closed"),
        }
    }
}
impl std::error::Error for IpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Protocol(_) | Self::Deadline | Self::Closed => None,
        }
    }
}
impl From<gnunet_client_host::ConnectError> for IpcError {
    fn from(error: gnunet_client_host::ConnectError) -> Self {
        match error {
            gnunet_client_host::ConnectError::Configuration(e) => Self::Configuration(e),
            gnunet_client_host::ConnectError::Io(e) => Self::Io(e),
            gnunet_client_host::ConnectError::Protocol(e) => Self::Protocol(e),
        }
    }
}
impl From<gnunet_config::Error> for IpcError {
    fn from(value: gnunet_config::Error) -> Self {
        Self::Configuration(value)
    }
}
impl From<io::Error> for IpcError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<Error> for IpcError {
    fn from(value: Error) -> Self {
        Self::Protocol(value)
    }
}
