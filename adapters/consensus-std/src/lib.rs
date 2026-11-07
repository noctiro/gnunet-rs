//! Real generic SET bridge for one original CONSENSUS client session.
//! Public identity is supplied by the caller's actual verified PILS owner.
#![forbid(unsafe_code)]
mod bridge;
mod types;
pub use bridge::Bridge;
pub use gnunet_consensus as core;
pub use gnunet_pils::client::Identity;
pub use gnunet_set_client_host::{Bounds, Factory};
pub use types::{Error, Limits, Progress, SourceLossContext, SourceRefusal};

mod run;
mod server;
mod server_types;
pub use server::Server;
pub use server_types::{Event, Report, ServerLimits, ServerProgress, SessionReport, Sources};

/// Actual PILS HELLO and identity profiles used by native service configuration.
pub use gnunet_pils::{HelloLimits, Profile};
