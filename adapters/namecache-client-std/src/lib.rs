//! Caller-driven official NAMECACHE IPC with bounded original operations.
//! Lookup ciphertext is validated by the actual carried-key signature and exact
//! original query before exposure. This client never decrypts naming records.
#![forbid(unsafe_code)]
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_service_runtime::clock;
use gnunet_types::AbsoluteTime;
pub use gnunet_wire::official::namecache as ipc;
mod client;
mod scope;
mod types;
pub use client::Client;
pub use scope::{Epoch, Instance, Operation};
pub use types::{
    Block, Cancellation, Completion, Kind, Limits, LocalReason, Loss, LossCause, Outcome, Progress,
    Submission,
};
