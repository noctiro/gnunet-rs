//! Native original-MQ NSE subscription. No NSE algorithm, PoW, key or service.
#![forbid(unsafe_code)]
#![cfg(unix)]
pub use gnunet_client::nse::{Double, Epoch, Estimate, Instance, Observation};
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_service_runtime::clock;
mod subscription;
pub use subscription::{Bounds, Cause, Limits, Loss, Progress, Stop, Subscription};
#[cfg(feature = "program")]
pub mod cli;
