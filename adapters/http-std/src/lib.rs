//! Bounded caller-driven HTTP/HTTPS GET/HEAD and SOAP POST. Explicit shared
//! Resolver, clock, original deadlines and owned TLS; no pools or hidden tasks.
#![forbid(unsafe_code)]
/// Explicit bounded native-byte/expiry guard for a caller's accepted HTTP server.
/// These guards report IO only and do not construct transport response receipts.
pub mod bounded_io;
mod exchange;
mod owner;
mod progress;
mod request;
mod transport;
pub use bounded_io::WireReport;
pub(crate) use bounded_io::{Counters, IoLease};
pub use gnunet_types::Error as Fault;
pub use owner::{Client, Head, ObservedResponse, Response};
pub(crate) use progress::State;
pub use progress::{Progress, Snapshot};
pub use request::{Instance, Job, Method, Redirects, Request};
pub use transport::{HttpLimits, Proxy, ProxyKind, SocketDiagnostic, Tls, validate_uri};

/// Original transport/provider error; no URL/authentication payload is printed.
#[derive(Debug)]
pub enum Error {
    /// Protocol/resource/original native deadline refusal.
    Fault(Fault),
    /// Actual shared clock/subscription failure.
    Clock(Fault),
    /// Actual socket/Resolver/TLS IO error.
    Io(std::io::Error),
    /// Mature HTTP parser or actual connection driver error.
    Http(hyper::Error),
    /// Local HTTP request/header construction failure.
    HttpBuild(hyper::http::Error),
    /// URL grammar failure, with no input URL retained in the error.
    Url(url::ParseError),
    /// Actual explicit TLS configuration error.
    Tls(rustls::Error),
    /// Original fatal native stream initialization plus earlier diagnostics.
    Initialization(gnunet_native::network::InitializationError),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Fault(e)
    }
}
impl From<gnunet_service_runtime::clock::BoundsError> for Error {
    fn from(error: gnunet_service_runtime::clock::BoundsError) -> Self {
        use gnunet_service_runtime::clock::BoundsError;
        match error {
            BoundsError::Deadline => Self::Fault(Fault::Deadline),
            BoundsError::Overflow => Self::Fault(Fault::Overflow),
            BoundsError::Clock(cause) => Self::Clock(cause),
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self::Http(e)
    }
}
impl From<hyper::http::Error> for Error {
    fn from(e: hyper::http::Error) -> Self {
        Self::HttpBuild(e)
    }
}
impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Self::Url(e)
    }
}
impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP transport: {self:?}")
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Fault(error) | Self::Clock(error) => error,
            Self::Io(error) => error,
            Self::Http(error) => error,
            Self::HttpBuild(error) => error,
            Self::Url(error) => error,
            Self::Tls(error) => error,
            Self::Initialization(error) => error,
        })
    }
}
