//! Actual Rust NAT host adapters over shared Resolver/clock/SERVICE owners.
#![deny(unsafe_code)]
#[cfg(feature = "providers")]
pub mod auto;
/// Shared original absolute and native bounds for all network/provider work.
pub mod deadline;
/// Shared PROGRAM/activation/credentials/Resolver foreground.
#[cfg(feature = "program")]
pub mod foreground;
#[cfg(feature = "providers")]
pub mod helpers;
/// Bounded actual local-IGD HTTP transport.
#[cfg(feature = "providers")]
pub mod http;
/// Actual bounded interface snapshot/monitor.
pub mod interfaces;
#[cfg(feature = "providers")]
pub mod manager;
#[cfg(feature = "providers")]
pub mod probe;
/// Actual shared-Resolver DNS and original callback lifetime.
pub mod resolve;
/// Actual NAT SERVICE, original jobs/mappings and helper lifecycle.
#[cfg(feature = "providers")]
pub mod server;
#[cfg(feature = "providers")]
pub mod settings;
/// Actual bound-socket STUN request and received-result owner.
pub mod stun;
/// Actual Rust SSDP/HTTP/SOAP IGD port mapping, with bounded mature XML parsing.
#[cfg(feature = "providers")]
pub mod upnp;

/// Original fault with no fabricated IO/provider success.
#[derive(Debug)]
pub enum Error {
    /// Protocol, state, resource or original deadline failure.
    Protocol(gnunet_types::Error),
    /// Original shared process-clock failure.
    Clock(gnunet_types::Error),
    /// Exact shared mature HTTP/TLS/proxy transport failure.
    #[cfg(feature = "providers")]
    Http(gnunet_http_host::Error),
    /// Actual operating-system entropy refusal; no transaction id invented.
    Entropy(getrandom::Error),
    /// Original native socket/resolver/helper IO error.
    Io(std::io::Error),
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
#[cfg(feature = "providers")]
impl From<gnunet_http_host::Error> for Error {
    fn from(e: gnunet_http_host::Error) -> Self {
        match e {
            gnunet_http_host::Error::Fault(e) => Self::Protocol(e),
            gnunet_http_host::Error::Clock(e) => Self::Clock(e),
            gnunet_http_host::Error::Io(e) => Self::Io(e),
            other => Self::Http(other),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "NAT protocol: {e}"),
            Self::Clock(e) => write!(f, "NAT clock: {e}"),
            Self::Io(e) => e.fmt(f),
            Self::Entropy(e) => e.fmt(f),
            #[cfg(feature = "providers")]
            Self::Http(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) | Self::Clock(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Entropy(e) => Some(e),
            #[cfg(feature = "providers")]
            Self::Http(e) => Some(e),
        }
    }
}

#[cfg(feature = "providers")]
impl From<gnunet_nat_helper_host::supervisor::Error> for Error {
    fn from(error: gnunet_nat_helper_host::supervisor::Error) -> Self {
        match error {
            gnunet_nat_helper_host::supervisor::Error::Protocol(error) => Self::Protocol(error),
            gnunet_nat_helper_host::supervisor::Error::Clock(error) => Self::Clock(error),
            gnunet_nat_helper_host::supervisor::Error::Io(error) => Self::Io(error),
        }
    }
}

impl From<gnunet_service_runtime::clock::BoundsError> for Error {
    fn from(error: gnunet_service_runtime::clock::BoundsError) -> Self {
        use gnunet_service_runtime::clock::BoundsError;
        match error {
            BoundsError::Deadline => Self::Protocol(gnunet_types::Error::Deadline),
            BoundsError::Overflow => Self::Protocol(gnunet_types::Error::Overflow),
            BoundsError::Clock(error) => Self::Clock(error),
        }
    }
}
