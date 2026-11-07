//! Official MESSENGER application SERVICE, shared CADET relay and purpose12 PILS
//! signer. All owners are caller driven; no resolver, task or worker is hidden.
#![forbid(unsafe_code)]
#![cfg(unix)]
mod carrier;
/// Actual bounded application daemon and original CADET/PILS ownership.
pub mod server;
pub use gnunet_cadet_host as cadet;
pub use gnunet_client_host::EndpointSource;
pub use gnunet_messenger_core as core;
pub use gnunet_pils_host as pils;

/// Explicit owned committed history and storage worker boundary.
pub mod history;

/// Explicit bounded original producer and relay profile policy.
pub mod layout;
