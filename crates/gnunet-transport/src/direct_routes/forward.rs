//! One original opaque DV BOX across egress backpressure and retirement.
use super::{NeighbourId, Router, first_hop, unique_hops};
use crate::dv::{self, BoxPacket};
use core::ptr;
use gnunet_types::{Duration, Error, MonoInstant, Rejected};

// GNUnet's DV_FORWARD_TIMEOUT, shortened by the original carrier leases.
const FORWARD_LIFETIME: Duration = Duration(60_000_000);

/// Routing decision for an original authenticated carrier's encrypted BOX.
#[derive(Debug)]
#[must_use]
pub enum BoxAction<'id, 'wire> {
    /// This node must still decrypt, authenticate and replay-check the contents.
    Destination(BoxPacket<'wire>),
    /// Forward the same original bytes across one exact live egress.
    Forward(ForwardBox<'id, 'wire>),
}

/// One immutable received BOX awaiting staging for local egress.
#[derive(Debug)]
#[must_use]
pub struct ForwardBox<'id, 'wire> {
    ingress: NeighbourId<'id>,
    egress: NeighbourId<'id>,
    serial: u64,
    packet: BoxPacket<'wire>,
    selected: usize,
    until: MonoInstant,
}

impl<'id> ForwardBox<'id, '_> {
    /// Exact original ingress.
    #[must_use]
    pub const fn ingress(&self) -> NeighbourId<'id> {
        self.ingress
    }

    /// Exact egress selected for this original, including its generation.
    #[must_use]
    pub const fn egress(&self) -> NeighbourId<'id> {
        self.egress
    }

    /// Last local admission deadline. Waiting and lease renewal do not extend it.
    #[must_use]
    pub const fn deadline(&self) -> MonoInstant {
        self.until
    }
}

/// Actual lower-layer settlement of one forwarded BOX.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct BoxCompletion<'id> {
    /// Original incoming carrier.
    pub ingress: NeighbourId<'id>,
    /// Original outgoing carrier.
    pub egress: NeighbourId<'id>,
    /// The observed ordered ciphertext buffer result. Successful native socket
    /// write and remote delivery remain separate events.
    pub ordered: Result<(), Error>,
}

/// The exact forwarding decision after encoding into an owned mailbox.
/// A staged reservation grants no native admission.
#[derive(Debug)]
#[must_use]
pub struct StagedBox<'id> {
    ingress: NeighbourId<'id>,
    egress: NeighbourId<'id>,
    serial: u64,
    until: MonoInstant,
}

impl<'id> StagedBox<'id> {
    /// Original authenticated receive carrier.
    pub const fn ingress(&self) -> NeighbourId<'id> {
        self.ingress
    }

    /// Original authenticated transmit carrier.
    pub const fn egress(&self) -> NeighbourId<'id> {
        self.egress
    }

    /// Original upper bound for its local admission.
    pub const fn deadline(&self) -> MonoInstant {
        self.until
    }
}

impl<'id> Router<'id, '_> {
    /// Inspect an opaque BOX received on one exact validated carrier.
    ///
    /// A forward selection is fixed for this input. A replacement link cannot
    /// take over retries or authenticate this original's egress completion.
    pub fn box_action<'wire>(
        &mut self,
        source: NeighbourId<'id>,
        bytes: &'wire [u8],
        now: MonoInstant,
    ) -> Result<BoxAction<'id, 'wire>, Error> {
        self.advance(now)?;
        let ingress = self.neighbour(source)?;
        let packet = BoxPacket::decode(bytes)?;
        unique_hops(packet.hop_count(), |index| {
            let hop = packet.hop(index)?;
            if hop == ingress.peer {
                return Err(Error::Malformed);
            }
            Ok(hop)
        })?;
        if usize::from(packet.traversed()) + packet.hop_count() > dv::MAX_HOPS {
            return Err(Error::TooLarge);
        }
        if packet.ciphertext().len() < dv::PAYLOAD_PREFIX + 4 {
            return Err(Error::Truncated);
        }
        if packet.hop_count() == 0 {
            return Ok(BoxAction::Destination(packet));
        }
        let selected = packet
            .shortcut(self.local, |peer| {
                first_hop(self.instance, self.neighbours, peer).is_some()
            })?
            .ok_or(Error::NotReady)?;
        let egress = first_hop(self.instance, self.neighbours, packet.hop(selected)?)
            .ok_or(Error::NotReady)?;
        let until = now
            .after(FORWARD_LIFETIME)?
            .min(ingress.until)
            .min(self.neighbour(egress)?.until);
        let serial = self.instance.next_forward.get();
        self.instance
            .next_forward
            .set(serial.checked_add(1).ok_or(Error::Overflow)?);
        Ok(BoxAction::Forward(ForwardBox {
            ingress: source,
            egress,
            serial,
            packet,
            selected,
            until,
        }))
    }

    /// Encode a BOX into an owned mailbox, reserving this staging generation.
    pub fn stage_box(
        &mut self,
        original: ForwardBox<'id, '_>,
        now: MonoInstant,
        mailbox: &mut [u8],
    ) -> Result<(StagedBox<'id>, usize), Error> {
        self.check_pair(original.ingress, original.egress, original.until, now)?;
        let index = self.index(original.egress)?;
        let carrier = self.neighbours[index]
            .0
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if carrier.forwarding.is_some() {
            return Err(Error::WouldBlock);
        }
        let len = original.packet.forward(original.selected, mailbox)?;
        carrier.forwarding = Some(original.serial);
        Ok((
            StagedBox {
                ingress: original.ingress,
                egress: original.egress,
                serial: original.serial,
                until: original.until,
            },
            len,
        ))
    }

    /// Revalidate the original staged frame before offering it to the carrier.
    pub fn check_staged_box(
        &mut self,
        staged: &StagedBox<'id>,
        now: MonoInstant,
    ) -> Result<(), Error> {
        self.check_pair(staged.ingress, staged.egress, staged.until, now)?;
        if self.neighbour(staged.egress)?.forwarding == Some(staged.serial) {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }

    /// Release this exact staged generation on actual admission or refusal.
    /// The owner can also record known cancellation of a never-offered mailbox.
    pub fn settle_staged_box(
        &mut self,
        original: StagedBox<'id>,
        actual_egress: NeighbourId<'id>,
        result: Result<(), Error>,
    ) -> Result<BoxCompletion<'id>, Rejected<StagedBox<'id>>> {
        if let Err(reason) = self.release_forward(original.egress, actual_egress, original.serial) {
            return Err(Rejected {
                value: original,
                reason,
            });
        }
        Ok(BoxCompletion {
            ingress: original.ingress,
            egress: original.egress,
            ordered: result,
        })
    }

    fn release_forward(
        &mut self,
        original: NeighbourId<'id>,
        actual: NeighbourId<'id>,
        expected: u64,
    ) -> Result<(), Error> {
        if !ptr::eq(original.instance, self.instance) || actual != original {
            return Err(Error::StaleGeneration);
        }
        if let Ok(index) = self.index(actual) {
            let egress = self.neighbours[index]
                .0
                .as_mut()
                .ok_or(Error::StaleGeneration)?;
            if egress.forwarding != Some(expected) {
                return Err(Error::StaleGeneration);
            }
            egress.forwarding = None;
        }
        Ok(())
    }
}
