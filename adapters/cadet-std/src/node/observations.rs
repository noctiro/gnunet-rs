//! Bounded first/last actual authenticated channel inputs; no payload or authority.
use gnunet_cadet::peer;
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::cadet_peer::ChannelMessage;

/// First and last observations only, with no traffic-sized history allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstLast<T> {
    /// Observed input count, saturated if `overflowed` becomes true.
    pub total: u64,
    /// The count exceeded its representable range; first/last remain actual.
    pub overflowed: bool,
    /// First actual observation for this original channel occupant.
    pub first: Option<T>,
    /// Latest actual observation for the same original occupant.
    pub last: Option<T>,
}
impl<T> Default for FirstLast<T> {
    fn default() -> Self {
        Self {
            total: 0,
            overflowed: false,
            first: None,
            last: None,
        }
    }
}
impl<T: Copy> FirstLast<T> {
    fn record(&mut self, value: T) {
        if let Some(total) = self.total.checked_add(1) {
            self.total = total;
        } else {
            self.overflowed = true;
        }
        if self.first.is_none() {
            self.first = Some(value);
        }
        self.last = Some(value);
    }
}
/// Actual stripped channel-owner result, without its private delivery/send tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelInputOutcome {
    /// A verified OPEN_ACK opened the original initiator.
    Opened,
    /// Duplicate OPEN scheduled its original port proof.
    DuplicateOpen,
    /// Payload was actually retained in the original bounded receive storage.
    Buffered,
    /// Already received or outside the original bounded window.
    Dropped,
    /// An actual ACK newly accepted this many original sends.
    Acknowledged {
        /// Actual new acceptance count; zero does not imply input loss.
        accepted: usize,
    },
    /// Actual remote channel teardown.
    Destroyed,
    /// Original owner requested a real DESTROY response.
    NeedDestroy,
    /// Actual unrelated/duplicate/invalid-direction control changed nothing.
    Ignored,
    /// Actual receive refusal, preserved without changing protocol handling.
    Refused(Error),
}
impl ChannelInputOutcome {
    fn actual(result: &Result<peer::Event<'_>, Error>) -> Self {
        match result {
            Ok(peer::Event::Opened) => Self::Opened,
            Ok(peer::Event::DuplicateOpen) => Self::DuplicateOpen,
            Ok(peer::Event::Buffered(_)) => Self::Buffered,
            Ok(peer::Event::Dropped) => Self::Dropped,
            Ok(peer::Event::Acknowledged { sends }) => Self::Acknowledged { accepted: *sends },
            Ok(peer::Event::Destroyed { .. }) => Self::Destroyed,
            Ok(peer::Event::NeedDestroy) => Self::NeedDestroy,
            Ok(peer::Event::Ignored) => Self::Ignored,
            Err(error) => Self::Refused(*error),
        }
    }
}
/// One actual authenticated DATA passed to its original channel owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataInput {
    /// Native elapsed timestamp from the shared Node epoch at the receive call.
    pub at: MonoInstant,
    /// Actual wrapping MID from the authenticated channel plaintext.
    pub mid: u32,
    /// Original expected receive base immediately before that call.
    pub expected_base: u32,
    /// Actual original channel phase before the receive call.
    pub phase_before: peer::Phase,
    /// Actual original channel phase after the same call.
    pub phase_after: peer::Phase,
    /// Actual owner result; not remote application processing.
    pub outcome: ChannelInputOutcome,
}
/// One actual authenticated DATA_ACK passed to its original channel owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckInput {
    /// Native elapsed timestamp from the shared Node epoch at the receive call.
    pub at: MonoInstant,
    /// Actual cumulative peer ACK base.
    pub mid: u32,
    /// Actual selective ACK bits; these observations grant no ACK authority.
    pub futures: u64,
    /// Actual free local send slots immediately before this ACK was applied.
    pub send_slots_before: usize,
    /// Actual free local send slots immediately after the same receive call.
    pub send_slots_after: usize,
    /// Actual original channel phase before the receive call.
    pub phase_before: peer::Phase,
    /// Actual original channel phase after the same call.
    pub phase_after: peer::Phase,
    /// Actual acceptance count or refusal from this original owner.
    pub outcome: ChannelInputOutcome,
}
/// Diagnostic facts for the last original channel occupying one fixed Node slot.
/// Retained after owner return; an actual later channel allocation replaces them.
/// No field can recreate a tunnel, channel, delivery token or send callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelObservations {
    /// Actual remote authenticated logical tunnel peer.
    pub peer: [u8; 32],
    /// Original local tunnel allocation serial, diagnostic only.
    pub tunnel: u64,
    /// Original wire channel number within that tunnel.
    pub channel: u32,
    /// Actual application port hash, not application payload.
    pub port: [u8; 64],
    /// The original closed owner actually returned its buffer package locally.
    /// False is not evidence that it remains remotely open.
    pub owner_returned: bool,
    /// Fixed first/last authenticated DATA inputs for this original occupant.
    pub data: FirstLast<DataInput>,
    /// Fixed first/last authenticated ACK inputs for the same occupant.
    pub ack: FirstLast<AckInput>,
}
impl ChannelObservations {
    pub(super) fn new(address: peer::Address, tunnel: u64) -> Self {
        Self {
            peer: address.remote_peer,
            tunnel,
            channel: address.channel,
            port: address.port,
            owner_returned: false,
            data: FirstLast::default(),
            ack: FirstLast::default(),
        }
    }
    pub(super) fn input(
        &mut self,
        message: ChannelMessage<'_>,
        expected: (u32, peer::Phase),
        send_slots: (usize, usize),
        phase_after: peer::Phase,
        result: &Result<peer::Event<'_>, Error>,
        now: MonoInstant,
    ) {
        match message {
            ChannelMessage::Data { mid, .. } => self.data.record(DataInput {
                at: now,
                mid,
                expected_base: expected.0,
                phase_before: expected.1,
                phase_after,
                outcome: ChannelInputOutcome::actual(result),
            }),
            ChannelMessage::DataAck { mid, futures, .. } => self.ack.record(AckInput {
                at: now,
                mid,
                futures,
                send_slots_before: send_slots.0,
                send_slots_after: send_slots.1,
                phase_before: expected.1,
                phase_after,
                outcome: ChannelInputOutcome::actual(result),
            }),
            _ => {}
        }
    }
}
