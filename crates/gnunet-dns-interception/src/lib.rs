//! Official DNS interception phases and raw helper packet envelope. This is
//! distinct from the DNS parser, DNSSTUB resolver and native interception client.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
use gnunet_types::Error;
pub use gnunet_vpn::packet::{Address, Family};
pub use gnunet_wire::official::dns::{self as wire, Decision};
/// One conservative common bound fitting complete IPv4/6+UDP+PI+official header.
pub const MAX_DNS_BYTES: usize = 65479;
/// Fixed official privileged helper message prefix: MQ4 and Linux TUN_PI4.
pub const HELPER_PREFIX: usize = 8;
/// Validate an actual original official helper frame and borrow raw IP bytes.
/// This grants no helper/process identity: native ownership must bind the source.
pub fn helper_packet(frame: &[u8]) -> Result<&[u8], Error> {
    let checked = gnunet_wire::official::Frame::decode(frame)?;
    if checked.header().message_type() != gnunet_wire::official::message_type::DNS_HELPER {
        return Err(Error::Unsupported);
    }
    let prefix = frame.get(4..8).ok_or(Error::Truncated)?;
    if prefix[..2] != [0; 2] {
        return Err(Error::Malformed);
    }
    let ip = &frame[8..];
    let packet = gnunet_vpn::packet::Packet::parse(ip)?;
    let protocol = u16::from_be_bytes([prefix[2], prefix[3]]);
    if protocol
        != match packet.source().family() {
            Family::V4 => 0x0800,
            Family::V6 => 0x86dd,
        }
    {
        return Err(Error::Malformed);
    }
    Ok(ip)
}
/// Encode actual raw IP packet into unchanged official DNS_HELPER/TUN_PI framing.
pub fn encode_helper(ip: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let p = gnunet_vpn::packet::Packet::parse(ip)?;
    let n = ip.len().checked_add(8).ok_or(Error::Overflow)?;
    let h = gnunet_wire::official::MessageHeader::from_total_size(
        gnunet_wire::official::message_type::DNS_HELPER,
        n,
    )?;
    if out.len() < n {
        return Err(Error::Capacity);
    }
    h.encode(out)?;
    out[4..6].fill(0);
    let protocol: u16 = match p.source().family() {
        Family::V4 => 0x0800,
        Family::V6 => 0x86dd,
    };
    out[6..8].copy_from_slice(&protocol.to_be_bytes());
    out[8..n].copy_from_slice(ip);
    Ok(n)
}
#[cfg(feature = "alloc")]
mod engine;
#[cfg(feature = "alloc")]
pub use engine::*;

#[cfg(all(test, feature = "alloc"))]
mod model;
