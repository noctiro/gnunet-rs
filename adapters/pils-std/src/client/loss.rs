//! Original stream-loss causes and allocation-free diagnostic narrowing.
use super::Error;
use gnunet_types::Error as ProtocolError;
use std::io;

/// Why an established original MQ was retired. Port refusals are not IO loss.
#[derive(Debug)]
pub enum LossCause {
    /// Clean physical EOF between complete frames.
    Eof,
    /// Actual native error, including truncated-frame EOF.
    Io(io::Error),
    /// A known PILS frame/announcement failed validation.
    Protocol(ProtocolError),
    /// Bounded setup or received-frame storage resources were refused.
    Resource(ProtocolError),
    /// Native output setup/admission failed; original MQ is explicitly retired.
    Setup(Error),
    /// Caller explicitly retired the original MQ to reconnect.
    Requested,
}
impl LossCause {
    /// EOF or a kernel stream-connection failure, excluding malformed framing,
    /// protocol, resource, setup and requested retirement. This classification
    /// does not authorize replay or attest to a replacement identity.
    #[must_use]
    pub fn is_connection_loss(&self) -> bool {
        match self {
            Self::Eof => true,
            Self::Io(error) => connection_error(error),
            _ => false,
        }
    }
    /// Narrow an actual connection loss without copying or boxing its cause.
    /// Other failures are returned unchanged; this grants no retry authority.
    pub fn into_connection_loss(self) -> Result<ConnectionLoss, Self> {
        match self {
            Self::Eof => Ok(ConnectionLoss::Eof),
            Self::Io(error) if connection_error(&error) => Ok(ConnectionLoss::Io(error)),
            other => Err(other),
        }
    }
}
fn connection_error(error: &io::Error) -> bool {
    use io::ErrorKind;
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
            | ErrorKind::TimedOut
            | ErrorKind::NetworkDown
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
    )
}
/// Owned connection-only diagnostic. It supplies no source or operation authority.
#[derive(Debug)]
pub enum ConnectionLoss {
    /// Clean stream EOF.
    Eof,
    /// Original kernel stream-connection error.
    Io(io::Error),
}
impl std::fmt::Display for ConnectionLoss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => f.write_str("PILS connection EOF"),
            Self::Io(error) => std::fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ConnectionLoss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Eof => None,
            Self::Io(error) => Some(error),
        }
    }
}
