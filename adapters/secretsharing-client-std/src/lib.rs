//! Original per-operation native SECRETSHARING MQ, without local crypto or tasks.
//! Private shares and plaintext results erase their owned storage on every drop.
#![forbid(unsafe_code)]
mod budget;
mod client;
mod types;
pub use budget::Bounds;
pub use client::Client;
pub use gnunet_client_host::{ConnectError, EndpointSource};
pub use gnunet_wire::official::secretsharing as ipc;
pub use types::{Cause, Decryption, Epoch, Error, Kind, Limits, Loss, Progress, Receipt, Share};
