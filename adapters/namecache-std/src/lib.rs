//! Actual bounded official NAMECACHE service over shared original MQ owners.
//! Service instances can use volatile memory or a private persistent cache.
#![forbid(unsafe_code)]
mod dispatch;
mod files;
#[cfg(test)]
mod model;
/// Caller-driven accepted connections, bounded TX, expiry and source cleanup.
pub mod server;
