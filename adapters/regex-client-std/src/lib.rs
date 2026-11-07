//! Caller-driven GNUnet v0.29.1 REGEX native IPC client.
//! Searches and announcement registrations survive actual source loss with one
//! original intent and fixed deadlines; physical epochs/writes are never reused.
//! No service, DHT backend, hidden task, acknowledgement or DONE is created.
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_service_runtime::clock;
pub use gnunet_wire::official::{RelativeTime, regex as ipc};
mod client;
mod scope;
mod types;
pub use client::{Announcement, AnnouncementRequest, Search};
pub use scope::{Epoch, Instance, Job, WriteId};
pub use types::{Deadlines, End, EndCause, Limits, OwnedResult, Progress, ResultView, Submission};
