//! Caller-driven official MESSENGER MQ, immutable original frames and actual
//! asynchronous notifications. No synthetic RID, ACK, room authority or crypto
//! verification is created. The higher room/message state owns those semantics.
#![forbid(unsafe_code)]
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_service_runtime::clock;
pub use gnunet_wire::official::messenger as ipc;
pub use ipc::profile::Profile;
mod client;
mod scope;
mod types;
pub use client::Client;
pub use scope::{Epoch, Instance, Operation};
pub use types::{Kind, Limits, Loss, LossCause, Notification, Progress, Report, Submission};
