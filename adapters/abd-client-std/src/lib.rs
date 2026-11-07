//! Caller-driven original official ABD IPC. No background task, private RPC,
//! synthetic authorization, cancel ACK or implicit service/Resolver is created.
#![forbid(unsafe_code)]

mod budget;
mod client;
mod types;
pub use budget::Bounds;
pub use client::Client;
pub use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution};
pub use gnunet_service_runtime::clock;
pub use gnunet_wire::official::abd as ipc;
pub use types::{Cause, Epoch, Error, Kind, Limits, Loss, Observation, Progress, Receipt};
