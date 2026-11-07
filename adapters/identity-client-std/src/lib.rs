//! Caller-driven official IDENTITY clients. Sensitive frames and keys are wiped
//! and have redacted formatting. No key file, Resolver, task or service is opened
//! by construction. IDENTITY has FIFO operation results and no wire cancellation.
#![forbid(unsafe_code)]
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_identity::SecretKey;
pub use gnunet_service_runtime::clock;
pub use gnunet_wire::official::identity::{self as ipc, KeyType};
mod client;
mod lookup;
mod scope;
mod types;
pub use client::Client;
pub use lookup::{Lookup, LookupOutcome, LookupProgress};
pub use scope::{Ego, Epoch, Instance, Operation};
pub use types::{
    Cancellation, Change, Completion, EgoView, Identity, InventoryProgress, Kind, Limits,
    LocalReason, Loss, LossCause, Outcome, Progress, Submission,
};
