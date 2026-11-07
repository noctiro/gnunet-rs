//! Actual bounded official NAMECACHE service over shared original MQ owners.
//! The backend is explicit volatile ciphertext memory, with no disk receipt.
#![cfg(unix)]
#![forbid(unsafe_code)]
mod dispatch;
#[cfg(test)]
mod model;
/// Caller-driven accepted connections, bounded TX, expiry and source cleanup.
pub mod server;
