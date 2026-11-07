//! Ordinary SOCKS5 GNS web proxy with real TLS, GNS/native owners and streaming HTTP.
//!
//! Constructors create no private Resolver broker or detached task. The caller
//! supplies one original process Context/Driver/Clock and actual endpoint sources.
//! Local TLS signing and upstream PKIX/DANE are genuine mature provider calls;
//! no metadata or untrusted QUIC verifier substitutes for authentication.
#![forbid(unsafe_code)]
pub mod budget;
mod error;
mod http;
mod records;
mod runtime;
mod session;
mod socks;
pub mod tls;
mod types;
pub mod vpn;
mod wire;
pub use error::Error;
pub use http::{Limits as HttpLimits, Report as HttpReport};
pub use records::{Limits as RecordLimits, Summary as RecordSummary};
pub use runtime::{Event, Report, Runtime, SessionId};
pub use session::Report as SessionReport;
pub use types::{Limits, Options, Ports, Sources};
pub use wire::Snapshot as SocketReport;
