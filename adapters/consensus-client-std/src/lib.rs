//! Original native CONSENSUS caller; official520/521/524 and523/525 only.
//! No service launch, private ACK, replacement MQ or mutation replay is implicit.
#![forbid(unsafe_code)]
mod client;
mod types;
pub use client::Client;
pub use gnunet_client_host::EndpointSource;
pub use gnunet_service_runtime::clock::Bounds;
pub use gnunet_wire::official::consensus::{ClientResponse, Join};
pub use types::{
    Cause, Epoch, Error, InsertId, Kind, Limits, Loss, Observation, Pending, Progress, Receipt,
};
