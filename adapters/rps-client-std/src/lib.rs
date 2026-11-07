//! Caller-driven official RPS client with independent stream-fed sampling.
//!
//! The standard IPC has neither request IDs nor acknowledgements nor END.
//! Raw stream batches are biased input; only the shared pure client sampler
//! produces public sampling results. No task, implicit replay or private RPC is
//! created. Each owner retains one original query, source and overall deadline.
mod budget;
mod client;
mod ports;
mod types;
pub use budget::Bounds;
pub use client::Client;
pub use gnunet_client_host::EndpointSource;
pub use gnunet_rps::{Peer, SampleInfo};
pub use gnunet_wire::official::rps::{ClientResponse, ReplyCountProfile};
pub use ports::subgroup_hash;
pub use types::{Cause, Epoch, Error, Limits, Loss, Observation, Progress, Query};
