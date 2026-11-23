//! Actual bounded raw QUIC / HTTP3 communicator host building blocks.
//! Caller-owned drivers, fixed source clocks/selectors and external profile loans;
//! no detached Quinn tasks, hidden DNS, production GNUnet FFI or peer-auth claim.
#![forbid(unsafe_code)]
mod application;
#[cfg(feature = "embedded-config")]
mod configured;
pub mod credentials;
mod drivers;
/// Caller-driven raw QUIC and HTTP/3 foreground.
pub mod embedded;
mod endpoint;
mod frame_pool;
#[cfg(feature = "h3-profile")]
mod h3_link;
mod ipc;
mod local_keys;
/// Actual owned row inventory; independent of socket byte observations.
pub mod metrics;
mod network;
mod quic_tls;
mod raw;
mod runtime;
mod socket;
pub mod tls;
mod types;
pub use endpoint::{Closed as BackendClosed, Limits as BackendLimits};
pub use runtime::Runtime;
pub use socket::Statistics;
pub use types::{Buffers, Closed, Epoch, Event, Fault, Instance, Limits, Nat, Progress, Sources};

#[cfg(feature = "h3-profile")]
/// Actual H3 backend/profile cause, including unknown send exposure.
pub use h3_link::Failure as H3Failure;
/// Original typed local send identity; no wire-id constructor or peer authority.
pub use raw::SendId;

#[cfg(feature = "program")]
pub mod program;
#[cfg(feature = "program")]
/// Actual app-injected publisher contracts without IPC/statistics dependencies.
pub mod statistics;
