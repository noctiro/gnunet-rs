//! Bounded caller-driven official VPN allocation client.
//! An allocation response reserves an address; packet forwarding and kernel
//! configuration belong to the VPN service and explicit TUN/platform owners.
#![forbid(unsafe_code)]
mod scope;
pub use scope::{Epoch, Instance, Operation, WriteId};
mod types;
pub use types::{
    Cancel, Limits, LossCause, Outcome, Progress, Protocol, Reason, Service, Submission,
};
mod client;
pub use client::Client;
/// Original native or endpoint/configuration error.
pub use gnunet_client_host::ConnectError as Error;
/// Explicit caller-selected endpoint, configuration and Resolver ports.
pub use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution};
/// Canonical clock and absolute deadline ports.
pub use gnunet_service_runtime::clock;
/// Original official borrowed codecs, including opaque request IDs.
pub use gnunet_wire::official::vpn as ipc;
pub use ipc::{Address, AfProfile, Family};
