//! Caller-driven official NAMESTORE IPC, bounded original sources and streams.
//! Zone keys and complete retained frames are opaque, zeroizing and redacted.
#![forbid(unsafe_code)]
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_gnsrecord::ZoneKey;
pub use gnunet_identity::SecretKey;
pub use gnunet_service_runtime::clock;
pub use gnunet_wire::official::namestore as ipc;
mod client;
mod scope;
mod stream;
mod types;
pub use client::Client;
pub use scope::{Control, Epoch, Instance, Operation};
pub use stream::{Monitor, ZoneIterator};
pub use types::{
    Cancellation, Completion, ControlKind, ControlLoss, Kind, Limits, LocalReason, Loss, LossCause,
    Outcome, Progress, Reply, Stored, Submission,
};
