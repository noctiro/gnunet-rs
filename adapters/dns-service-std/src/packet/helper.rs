//! Unchanged DNS_HELPER/TUN_PI framing with preflight before output mutation.
use super::Family;
use gnunet_types::Error;
use gnunet_vpn::packet::Packet;
use gnunet_wire::official::{Frame, MessageHeader, message_type};

/// MQ4 plus Linux TUN_PI4; native interface zones are not carried in this header.
pub const HELPER_PREFIX: usize = 8;

fn parts(frame: &[u8]) -> Result<(&[u8], Family), Error> {
    let checked = Frame::decode(frame)?;
    if checked.header().message_type() != message_type::DNS_HELPER {
        return Err(Error::Unsupported);
    }
    let pi = frame.get(4..HELPER_PREFIX).ok_or(Error::Truncated)?;
    if pi[..2] != [0; 2] {
        return Err(Error::Malformed);
    }
    let family = match u16::from_be_bytes([pi[2], pi[3]]) {
        0x0800 => Family::V4,
        0x86dd => Family::V6,
        _ => return Err(Error::Malformed),
    };
    Ok((&frame[HELPER_PREFIX..], family))
}

pub(crate) fn decode_helper_packet(frame: &[u8]) -> Result<Packet<'_>, Error> {
    let (raw, family) = parts(frame)?;
    let packet = Packet::parse(raw)?;
    if packet.source().family() != family {
        return Err(Error::Malformed);
    }
    Ok(packet)
}

/// Borrow a structurally checked real IP packet from an official helper frame.
/// This validates framing/family, not checksums, DNS content or native ownership.
///
/// # Errors
/// Refuses invalid MQ lengths/types, TUN_PI flags/family and malformed raw IP.
pub fn helper_packet(frame: &[u8]) -> Result<&[u8], Error> {
    Ok(decode_helper_packet(frame)?.bytes())
}

/// Encode actual raw IP into the unchanged official DNS helper envelope.
/// No checksum, interface identity or device-delivery receipt is synthesized.
///
/// # Errors
/// Rejects malformed raw IP, an oversized complete helper frame or insufficient
/// output before modifying the destination.
pub fn encode_helper(raw: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    encode_checked_helper(Packet::parse(raw)?, out)
}

pub(crate) fn encode_checked_helper(packet: Packet<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let raw = packet.bytes();
    let total = raw
        .len()
        .checked_add(HELPER_PREFIX)
        .ok_or(Error::Overflow)?;
    let header = MessageHeader::from_total_size(message_type::DNS_HELPER, total)?;
    if out.len() < total {
        return Err(Error::Capacity);
    }
    header.encode(out)?;
    out[4..6].fill(0);
    out[6..HELPER_PREFIX].copy_from_slice(&protocol(packet.source().family()).to_be_bytes());
    out[HELPER_PREFIX..total].copy_from_slice(raw);
    Ok(total)
}

pub(super) const fn protocol(family: Family) -> u16 {
    match family {
        Family::V4 => 0x0800,
        Family::V6 => 0x86dd,
    }
}
