//! Actual caller-driven DNS interception CLIENT, distinct from DNSSTUB.
//! Each callback and reply remains on its original physical MQ; reconnect only
//! resubscribes flags and never replays intercepted requests or replies.
#![forbid(unsafe_code)]
mod client;
pub use client::*;
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_wire::official::dns as ipc;
