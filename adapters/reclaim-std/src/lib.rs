//! Caller-driven official RECLAIM SERVICE and real original provider bridge.
//! No GNS resolver, persistent key store, task or worker is created here.
#![forbid(unsafe_code)]
#![cfg(unix)]
mod providers;
pub mod server;
pub use gnunet_client_host::EndpointSource;
pub use gnunet_gns_client_host as gns;
pub use gnunet_namestore_client_host as namestore;
pub use gnunet_reclaim as reclaim;
pub use providers::{SystemFailure, SystemProviders};

/// Bounded official persistent lookup-statistics publisher over actual shared CLIENT.
pub mod statistics;
