//! Official GNUnet CORE peer protocol with explicit time, entropy and storage.
//! Codec or cryptographic success does not certify a complete CORE service/node.
#![no_std]
#![forbid(unsafe_code)]

pub mod record;
pub mod session;
pub mod wire;
