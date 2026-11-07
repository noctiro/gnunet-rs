//! Official VPN/EXIT packet primitives and bounded VPN lease/flow ownership.
//! Native TUN/route provisioning, discovery and CADET effects are explicit ports;
//! no network, OS route, thread, private protocol or default success is created.
#![no_std]
#![forbid(unsafe_code)]
/// Official REGEX exit-search byte string construction.
pub mod discovery;
mod engine;
/// Shared IP parsing, checksum, NAT rewrite and ICMP quote primitives for EXIT.
pub mod packet;
mod types;
pub use engine::Engine;
pub use gnunet_wire::official::vpn::{
    Address, AfProfile, Family, Helper, PeerMessage, Request as WireRequest, Response,
};
pub use types::*;
/// Actual service-name descriptor hash, without a terminating NUL or private tag.
#[must_use]
pub fn service_descriptor(name: &[u8]) -> [u8; 64] {
    gnunet_crypto::hash512(name)
}
/// Exact GNUNET_TUN_compute_service_cadet_port: override the descriptor's first
/// two bytes with the network-order destination port; do not hash concatenation.
#[must_use]
pub fn service_port(mut descriptor: [u8; 64], port: u16) -> [u8; 64] {
    descriptor[..2].copy_from_slice(&port.to_be_bytes());
    descriptor
}
/// Official named Internet gateway port.
#[must_use]
pub fn gateway_port(family: Family) -> [u8; 64] {
    gnunet_crypto::hash512(match family {
        Family::V4 => b"exit-ipv4",
        Family::V6 => b"exit-ipv6",
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod engine_tests;
