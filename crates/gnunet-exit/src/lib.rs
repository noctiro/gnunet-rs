//! Official EXIT raw-IP forwarding and bounded original VPN/CADET flow ownership.
//! Packet algorithms are shared with VPN. Native TUN/CADET IO stays an explicit
//! caller port: local write completion is never remote acceptance.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
/// Shared official address and family types.
pub use gnunet_wire::official::vpn::{Address, AfProfile, Family};
/// Bounded actual flow/table/packet/processing/retirement coordinator.
#[cfg(feature = "alloc")]
pub mod engine;
/// Explicit bounded caller-entropy NAT address/port selection.
pub mod nat;
/// Typed local transport/tuple and configured target policy.
pub mod policy;
