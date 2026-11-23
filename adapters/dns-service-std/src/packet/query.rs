//! Checked UDP query extraction; endpoint observations grant no native authority.
use super::{Address, address, helper};
use crate::core::Query;
use gnunet_types::Error;
use gnunet_vpn::packet::{Packet, UDP};

/// Original query endpoints retained outside the DNS engine for reply framing.
/// A tuple alone cannot select a native socket, interface or original request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyTuple {
    pub(super) source: Address,
    pub(super) destination: Address,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
}
impl ReplyTuple {
    /// Whether either endpoint needs a native IPv6 link-local or site-local zone.
    /// The tuple does not carry or establish that zone.
    pub fn requires_scope(self) -> bool {
        [self.source, self.destination]
            .into_iter()
            .any(|ip| address::scope(address::numeric(ip)) != address::Scope::Unscoped)
    }
    /// An original interface can supply link scope, but never a legacy site zone.
    pub(crate) fn raw_scope_supported(self, interface_scope: bool) -> bool {
        [self.source, self.destination].into_iter().all(|ip| {
            match address::scope(address::numeric(ip)) {
                address::Scope::Unscoped => true,
                address::Scope::LinkLocal => interface_scope,
                address::Scope::SiteLocal => false,
            }
        })
    }
}

/// Decode a real raw UDP port53 query once, borrowing its DNS datagram.
///
/// # Errors
/// Refuses unsupported/fragmented IP, bad checksums, non-UDP/other-port traffic
/// non-unicast or IPv4-mapped IPv6 endpoints and invalid DNS query bodies.
pub fn decode_query(raw: &[u8]) -> Result<(Query<'_>, ReplyTuple), Error> {
    decode_parsed_query(Packet::parse(raw)?)
}

/// Decode an official helper query without a second IP parser or payload copy.
///
/// # Errors
/// Preserves helper framing/family errors and the raw query validator's errors.
pub fn decode_helper_query(frame: &[u8]) -> Result<(Query<'_>, ReplyTuple), Error> {
    decode_parsed_query(helper::decode_helper_packet(frame)?)
}

pub(crate) fn decode_parsed_query(packet: Packet<'_>) -> Result<(Query<'_>, ReplyTuple), Error> {
    packet.validate_checksums()?;
    if packet.protocol() != UDP {
        return Err(Error::Unsupported);
    }
    let (source_port, destination_port) = packet.ports()?;
    if destination_port != 53 {
        return Err(Error::Unsupported);
    }
    // A raw reply reverses these endpoints. Group delivery and wildcard/broadcast
    // source selection require native owners this tuple cannot supply.
    if ![packet.source(), packet.destination()]
        .into_iter()
        .all(|ip| address::unicast(address::numeric(ip)))
    {
        return Err(Error::Unsupported);
    }
    let query = Query::decode(packet.segment().get(8..).ok_or(Error::Truncated)?)?;
    Ok((
        query,
        ReplyTuple {
            source: packet.source(),
            destination: packet.destination(),
            source_port,
            destination_port,
        },
    ))
}
