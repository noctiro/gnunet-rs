//! Raw helper/TUN/capture decoding and reply framing at the physical boundary.
use super::input::{InputRefusal, OriginalInput, ReplyOwner};
use crate::packet;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_tun_host::Received;
use gnunet_types::Error as Fault;

#[derive(Debug, Default)]
pub(super) enum Route {
    #[default]
    None,
    #[cfg(windows)]
    Captured(gnunet_native::windivert::ReplyAddress),
}
impl Route {
    fn has_interface_scope(&self) -> bool {
        match self {
            Self::None => false,
            #[cfg(windows)]
            Self::Captured(address) => address.has_interface_scope(),
        }
    }
}
/// A checked raw tuple retains its separate original native injection authority.
#[derive(Debug)]
pub(super) struct Reply {
    tuple: packet::ReplyTuple,
    pub route: Route,
}
impl Reply {
    pub fn helper(&self, dns: &[u8], capacity: usize) -> Result<OwnedFrame, Fault> {
        self.encode(dns, packet::Framing::Helper, capacity)
    }
    pub fn packet(&self, dns: &[u8], capacity: usize) -> Result<OwnedFrame, Fault> {
        self.encode(dns, packet::Framing::Raw, capacity)
    }
    fn encode(
        &self,
        dns: &[u8],
        framing: packet::Framing,
        capacity: usize,
    ) -> Result<OwnedFrame, Fault> {
        let size = self.tuple.encoded_len(dns.len(), framing)?;
        if size > capacity {
            return Err(Fault::TooLarge);
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
        bytes.resize(size, 0);
        self.tuple.encode(dns, framing, &mut bytes)?;
        Ok(OwnedFrame::new(std::mem::take(&mut *bytes)))
    }
}
enum Layout {
    Helper,
    Native { prefix: usize },
}
fn decode(
    storage: OwnedFrame,
    layout: Layout,
    route: Route,
) -> Result<OriginalInput, InputRefusal> {
    let parsed = match layout {
        Layout::Helper => packet::decode_helper_packet(storage.bytes()),
        Layout::Native { prefix } => storage
            .bytes()
            .get(prefix..)
            .ok_or(Fault::Malformed)
            .and_then(gnunet_vpn::packet::Packet::parse),
    }
    .map_err(InputRefusal::from)?;
    let (query, tuple) = packet::decode_parsed_query(parsed).map_err(|reason| InputRefusal {
        reason,
        non_dns_udp: parsed.protocol() == gnunet_vpn::packet::UDP
            && (parsed.ports().is_ok_and(|ports| ports.1 != 53) || parsed.segment().len() < 20),
    })?;
    if !tuple.raw_scope_supported(route.has_interface_scope()) {
        return Err(Fault::Unsupported.into());
    }
    let prefix = match layout {
        Layout::Helper => packet::HELPER_PREFIX,
        Layout::Native { prefix } => prefix,
    };
    let start = prefix
        .checked_add(parsed.transport_offset())
        .and_then(|offset| offset.checked_add(8))
        .ok_or(Fault::Overflow)?;
    let end = start
        .checked_add(query.bytes().len())
        .ok_or(Fault::Overflow)?;
    Ok(OriginalInput::checked(
        storage,
        start..end,
        ReplyOwner::Raw(Reply { tuple, route }),
    ))
}
pub(super) fn helper(frame: OwnedFrame) -> Result<OriginalInput, InputRefusal> {
    decode(frame, Layout::Helper, Route::None)
}
pub(super) fn device(packet: Received) -> Result<OriginalInput, InputRefusal> {
    let prefix = packet.native_bytes().len() - packet.bytes().len();
    decode(
        OwnedFrame::new(packet.into_native_bytes()),
        Layout::Native { prefix },
        Route::None,
    )
}
#[cfg(windows)]
pub(super) fn captured(
    packet: Vec<u8>,
    route: gnunet_native::windivert::ReplyAddress,
) -> Result<OriginalInput, InputRefusal> {
    decode(
        OwnedFrame::new(packet),
        Layout::Native { prefix: 0 },
        Route::Captured(route),
    )
}

#[cfg(test)]
pub(super) fn native(packet: OwnedFrame, prefix: usize) -> Result<OriginalInput, InputRefusal> {
    decode(packet, Layout::Native { prefix }, Route::None)
}
