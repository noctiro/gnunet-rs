//! Official zonemaster record preparation, public/local block separation and
//! bounded publication scheduling. No listener, DHT client, storage or key file.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
pub mod material;
#[cfg(feature = "alloc")]
pub mod schedule;
pub use gnunet_types::Error;
