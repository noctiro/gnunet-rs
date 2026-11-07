//! Caller-driven official RECLAIM IPC. Actual native writes, service replies,
//! original callback cancellation and original source retirement stay distinct.
#![forbid(unsafe_code)]
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_reclaim::{
    Attribute, AttributeList, AttributeType, Credential, CredentialList, CredentialType,
    Identifier, ListLimits, Name, Presentation, PresentationList, Sensitive, Ticket, Uri, ipc,
};
pub use gnunet_service_runtime::clock;
pub use gnunet_wire::official::{RelativeTime, identity::SecretKeyView};
mod client;
mod scope;
mod stream;
mod types;
pub use client::Client;
pub use scope::{Control, Epoch, Instance, Operation};
pub use stream::Iterator;
pub use types::{
    Cancellation, Completion, ControlKind, ControlLoss, Kind, Limits, LocalReason, Loss, LossCause,
    Outcome, Progress, Reply, Submission,
};
