//! Name-based GNS queries composed from the original native IPC clients.
//!
//! The isolated GNS client remains in `gnunet-gns-client-host`; this layer owns
//! name routing, configuration and IDENTITY-to-GNS query composition.

pub mod tld;
