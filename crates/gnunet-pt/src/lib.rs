//! Official PT DNS transformation and DNS-over-CADET state ownership.
//! The VPN daemon owns actual IP forwarding and TUN/helper lifetimes. This crate
//! creates no resolver, service, task, private protocol, device or implicit DHT.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
pub mod core;
pub mod exit;
pub mod packet;
pub use gnunet_types::Error;
#[cfg(test)]
mod model;
