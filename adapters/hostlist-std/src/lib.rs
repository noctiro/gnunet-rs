//! Actual bounded HOSTLIST bootstrap, verified publication, CORE advertisements,
//! PEERSTORE hello-add and explicit qualified learned-metadata persistence.
#![forbid(unsafe_code)]
#![cfg(unix)]
pub use gnunet_hostlist::{
    Advertiser, Core, DownloadOutcome, Fetch, HelloFrame, Job, Learned, Modes, Uri,
};
pub use gnunet_types::Error as Fault;
mod durable;
mod gate;
pub mod http;
mod peerstore;
mod publication;
mod runtime;
mod server;
mod statistics;
pub use durable::{Durable, DurableEvent};
pub use http::{HttpLimits, Proxy, ProxyKind, Tls};
pub use peerstore::{AddCompletion, AddStatus, PeerstoreEvent};
pub use publication::PublicationLimits;
pub use runtime::*;
pub use server::{HttpEvent, HttpId};
pub use statistics::{Metric, StatisticsEvent};
/// Exact original provider/resource failure. URI and authentication bytes are not
/// retained in printable diagnostics. Real storage failures use their own receipts.
#[derive(Debug)]
pub enum Error {
    /// Protocol or finite bound failure.
    Fault(Fault),
    /// Original process clock/subscription refusal.
    Clock(Fault),
    /// Actual operating-system or Resolver callback error.
    Io(std::io::Error),
    /// Actual fixed native CLIENT source error.
    Native(gnunet_client_host::ConnectError),
    /// Original independent HTTP/TLS transport cause.
    Transport(gnunet_http_host::Error),
    /// Mature HTTP parser/driver failure; no fixed success status is fabricated.
    Http(hyper::Error),
    /// HTTP request/header construction failed.
    HttpBuild(hyper::http::Error),
    /// Actual URL grammar error (does not print the input URI).
    Url(url::ParseError),
    /// Exact shared accept/initialization failure, with original diagnostics.
    Accept(gnunet_service_runtime::accepted::AcceptError),
    /// Original qualified persistence cause and independent cleanup error.
    Store(std::sync::Arc<gnunet_snapshot_host::backend::Failure>),
    /// Fatal socket setup cause plus earlier actual nonfatal diagnostics.
    Initialization(gnunet_native::network::InitializationError),
}
impl From<gnunet_http_host::Error> for Error {
    fn from(e: gnunet_http_host::Error) -> Self {
        match e {
            gnunet_http_host::Error::Clock(e) => Self::Clock(e),
            gnunet_http_host::Error::Fault(e) => Self::Fault(e),
            other => Self::Transport(other),
        }
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Fault(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Native(e)
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
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HOSTLIST: {self:?}")
    }
}
impl std::error::Error for Error {}
