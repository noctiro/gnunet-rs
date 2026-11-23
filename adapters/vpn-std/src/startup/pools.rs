//! Fixed shared VPN payload backing and VPN and CADET slot storage.
use super::ServiceSettings;
use gnunet_cadet_host::ChannelSlot;
use gnunet_vpn::{ClientSlot, FlowSlot, LeaseSlot, PacketSlot, RequestSlot, Storage};
use std::collections::TryReserveError;

/// Allocated fixed storage for one fresh VPN owner and its outbound CADET client.
pub struct Pools {
    clients: Vec<ClientSlot>,
    requests: Vec<RequestSlot>,
    leases: Vec<LeaseSlot>,
    flows: Vec<FlowSlot>,
    channels: Vec<ChannelSlot>,
    backing: Vec<u8>,
    small_count: usize,
    small_bytes: usize,
    large_count: usize,
    large_bytes: usize,
}

impl Pools {
    pub(super) fn new(settings: &ServiceSettings) -> Result<Self, TryReserveError> {
        Ok(Self {
            clients: filled(settings.clients, ClientSlot::new)?,
            requests: filled(settings.requests, RequestSlot::new)?,
            leases: filled(settings.leases, LeaseSlot::new)?,
            flows: filled(settings.flows, FlowSlot::new)?,
            channels: filled(settings.flows, ChannelSlot::new)?,
            backing: filled(settings.backing_bytes(), || 0)?,
            small_count: settings.small_count,
            small_bytes: settings.small_bytes,
            large_count: settings.large_count,
            large_bytes: settings.large_bytes,
        })
    }

    /// Borrow distinct VPN and CADET stores from the original pools.
    pub fn slots(&mut self) -> Result<Slots<'_>, TryReserveError> {
        let mut packets = Vec::new();
        packets.try_reserve_exact(self.small_count + self.large_count)?;
        let (small, large) = self
            .backing
            .split_at_mut(self.small_count * self.small_bytes);
        for bytes in small
            .chunks_exact_mut(self.small_bytes)
            .chain(large.chunks_exact_mut(self.large_bytes))
        {
            packets.push(PacketSlot::new(bytes));
        }
        Ok(Slots {
            clients: &mut self.clients,
            requests: &mut self.requests,
            leases: &mut self.leases,
            flows: &mut self.flows,
            channels: &mut self.channels,
            packets,
        })
    }
}

/// Prepared independent slot stores borrowing the original packet backing.
pub struct Slots<'bytes> {
    clients: &'bytes mut [ClientSlot],
    requests: &'bytes mut [RequestSlot],
    leases: &'bytes mut [LeaseSlot],
    flows: &'bytes mut [FlowSlot],
    channels: &'bytes mut [ChannelSlot],
    packets: Vec<PacketSlot<'bytes>>,
}

impl<'bytes> Slots<'bytes> {
    /// Lend the pure engine and outbound CADET channel owner their own slots.
    pub fn split(&mut self) -> (Storage<'_, 'bytes>, &mut [ChannelSlot]) {
        (
            Storage {
                clients: self.clients,
                requests: self.requests,
                leases: self.leases,
                flows: self.flows,
                packets: &mut self.packets,
            },
            self.channels,
        )
    }
}

fn filled<T>(count: usize, mut make: impl FnMut() -> T) -> Result<Vec<T>, TryReserveError> {
    let mut items = Vec::new();
    items.try_reserve_exact(count)?;
    items.resize_with(count, &mut make);
    Ok(items)
}
