//! Caller-driven official PEERSTORE client with bounded original MQs and credit.
//! Stores and iterators share a general MQ; monitors use an explicitly separate
//! MQ because official MONITOR_NEXT has no RID. Cache data is not peer authority.
#![forbid(unsafe_code)]
mod scope;
pub use scope::{Epoch, Instance, Operation, WriteId};
mod types;
pub use types::{
    Cancel, Command, Kind, Limits, LossCause, Observation, Outcome, Progress, Reason, RecordPhase,
    Submission,
};
mod client;
pub use client::Client;
/// Original native/configuration error, without a synthetic service result.
pub use gnunet_client_host::ConnectError as Error;
/// Caller-selected CLIENT endpoint and explicit live configuration/Resolver ports.
pub use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution};
/// Canonical absolute clock and original deadline/waiter traits.
pub use gnunet_service_runtime::clock;
/// Original official borrowed record/filter types and complete IPC codec.
pub use gnunet_wire::official::peerstore as ipc;
pub use ipc::{Filter, Record};

/// Actual original-source HELLO scan/newer/REPLACE composition.
pub mod hello;
