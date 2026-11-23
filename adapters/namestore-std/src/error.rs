//! Original NAMESTORE host failure and its underlying source.
use crate::backend;
use gnunet_types::Error as Fault;
use std::{io, sync::Arc};

/// Original failure from inventory, persistence, clock or native I/O.
#[derive(Debug)]
pub enum Error {
    /// Pure inventory, protocol or resource failure.
    Protocol(Fault),
    /// Original native I/O failure.
    Io(io::Error),
    /// Original canonical clock read or subscription failure.
    Clock(Fault),
    /// Original native persistence and cleanup cause.
    Storage(Arc<backend::Failure>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "NAMESTORE protocol: {error}"),
            Self::Io(error) => error.fmt(f),
            Self::Clock(error) => write!(f, "NAMESTORE clock: {error}"),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) | Self::Clock(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Storage(error) => Some(error.as_ref()),
        }
    }
}

impl From<Fault> for Error {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
