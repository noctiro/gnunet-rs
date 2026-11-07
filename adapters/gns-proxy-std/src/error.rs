//! Original proxy failures; no private HTTP payload or private key is echoed.
use std::{fmt, io};
/// An actual original protocol, native source or security failure.
#[derive(Debug)]
pub enum Error {
    /// Bounded protocol/resource rejection.
    Protocol(gnunet_types::Error),
    /// Actual operating-system cause.
    Io(io::Error),
    /// Actual GNS routing or service cause, never DNS fallback.
    Gns(gnunet_gns_host::tld::Cause),
    /// Actual endpoint snapshot/source construction cause.
    Connect(gnunet_client_host::ConnectError),
    /// Actual configuration copy/parse cause.
    Configuration(gnunet_config::Error),
    /// All actual native bind attempts failed.
    Binding(Vec<io::Error>),
    /// Independent original bind errors plus another construction failure.
    Construction {
        /// Actual primary cause, not a formatted message.
        cause: Box<Error>,
        /// Actual prior alternative binding causes.
        bind_failures: Vec<io::Error>,
    },
    /// Actual shared Resolver cause.
    Resolver(gnunet_resolver_broker::BrokerError),
    /// Actual canonical clock cause.
    Clock(gnunet_types::Error),
    /// Actual CA/TLS authentication cause.
    Tls(crate::tls::TlsError),
    /// Actual VPN consumer outcome; cleanup remains in its independent report.
    Vpn(crate::vpn::Failure),
    /// Actual mature HTTP parser/stream cause.
    Http(hyper::Error),
    /// Actual explicit allocation refusal.
    Allocation(std::collections::TryReserveError),
    /// Actual bounded IDNA conversion category.
    Idna(gnunet_idna::Error),
    /// Original parent/local stop fenced fresh work.
    Stopped,
    /// Original whole-session native or logical target elapsed.
    Deadline,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "GNS proxy protocol/resource: {e}"),
            Self::Io(e) => write!(f, "GNS proxy IO: {e}"),
            Self::Gns(e) => write!(f, "GNS proxy lookup: {e}"),
            Self::Connect(e) => write!(f, "GNS proxy endpoint: {e}"),
            Self::Configuration(e) => write!(f, "GNS proxy configuration: {e}"),
            Self::Binding(errors) => write!(f, "GNS proxy bindings failed: {errors:?}"),
            Self::Construction {
                cause,
                bind_failures,
            } => write!(
                f,
                "GNS proxy construction: {cause}; independent bind failures={bind_failures:?}"
            ),
            Self::Resolver(e) => write!(f, "GNS proxy Resolver: {e}"),
            Self::Clock(e) => write!(f, "GNS proxy clock: {e}"),
            Self::Tls(e) => write!(f, "GNS proxy TLS: {e}"),
            Self::Vpn(e) => write!(f, "GNS proxy VPN: {e}"),
            Self::Http(e) => write!(f, "GNS proxy HTTP: {e}"),
            Self::Allocation(e) => write!(f, "GNS proxy allocation: {e}"),
            Self::Idna(e) => write!(f, "GNS proxy IDNA: {e:?}"),
            Self::Stopped => f.write_str("GNS proxy original session stopped"),
            Self::Deadline => f.write_str("GNS proxy original session deadline"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) | Self::Clock(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Gns(e) => Some(e),
            Self::Connect(e) => Some(e),
            Self::Configuration(e) => Some(e),
            Self::Binding(errors) => errors.first().map(|e| e as &dyn std::error::Error),
            Self::Construction { cause, .. } => Some(cause.as_ref()),
            Self::Resolver(e) => Some(e),
            Self::Tls(e) => Some(e),
            Self::Http(e) => Some(e),
            Self::Vpn(e) => Some(e),
            Self::Allocation(e) => Some(e),
            Self::Idna(_) | Self::Stopped | Self::Deadline => None,
        }
    }
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self::Http(e)
    }
}
impl From<crate::tls::TlsError> for Error {
    fn from(e: crate::tls::TlsError) -> Self {
        Self::Tls(e)
    }
}
