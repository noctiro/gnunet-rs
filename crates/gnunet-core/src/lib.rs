//! Official GNUnet CORE peer protocol with explicit time, entropy and storage.
//! Codec or cryptographic success does not certify a complete CORE service/node.
#![no_std]
#![forbid(unsafe_code)]

/// Single-peer CORE driving over an already validated direct transport.
pub mod direct_peer;
pub mod record;
pub mod session;
pub mod wire;
