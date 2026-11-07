//! Allocation-free official GNUnet service protocols.
//!
//! These clients use GNUnet v0.29.1 IPC messages. They do not speak
//! private wire formats, start a C daemon, or implement the peer services themselves.
#![no_std]
#![forbid(unsafe_code)]

pub mod core;
pub mod gns;
pub mod nse;
pub mod resolver;
pub mod resolver_handle;
pub mod statistics;
pub mod statistics_handle;
pub mod transport;

mod statistics_owner;

/// Official DATASTORE service wire/client operations.
pub mod datastore;
