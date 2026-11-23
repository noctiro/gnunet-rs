//! Authenticated reliable-carrier provenance for allocation-free DV routing.
use crate::{
    PeerId,
    dv::{self, Learn, VerifiedLearn, routes},
};
use core::{cell::Cell, fmt, num::NonZeroU64, ptr, slice};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, Entropy};
use gnunet_types::{Duration, Error, MonoInstant};

mod forward;
pub use forward::{BoxAction, BoxCompletion, ForwardBox, StagedBox};
mod origin;
pub use origin::OriginRoute;

// Official discovery allows sixteen forks and a separate return to the origin.
const MAX_FORWARDS: usize = 16;

/// Identity domain shared by route and physical neighbour admissions.
pub struct Instance {
    route_ids: routes::Instance,
    next_neighbour: Cell<u64>,
    next_forward: Cell<u64>,
}

impl Instance {
    /// Create an independent lifetime domain.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            route_ids: routes::Instance::new(),
            next_neighbour: Cell::new(1),
            next_forward: Cell::new(1),
        }
    }
}

impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

/// Identity of one original authenticated bidirectional carrier.
#[derive(Clone, Copy)]
pub struct NeighbourId<'id> {
    instance: &'id Instance,
    serial: u64,
}

impl PartialEq for NeighbourId<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.instance, other.instance) && self.serial == other.serial
    }
}

impl Eq for NeighbourId<'_> {}

impl fmt::Debug for NeighbourId<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NeighbourId")
            .field(&self.serial)
            .finish()
    }
}

#[derive(Clone, Copy)]
struct Neighbour {
    serial: u64,
    peer: PeerId,
    until: MonoInstant,
    forwarding: Option<u64>,
}

/// Caller-owned physical neighbour slot.
#[derive(Clone, Default)]
pub struct NeighbourSlot(Option<Neighbour>);

impl NeighbourSlot {
    /// Reserve one unused neighbour slot.
    #[must_use]
    pub const fn empty() -> Self {
        Self(None)
    }
}

/// Separate caller-owned capacities for physical and learned state.
pub struct Storage<'slots> {
    /// Actual direct, validated bidirectional carriers.
    pub neighbours: &'slots mut [NeighbourSlot],
    /// Official route evidence and paths.
    pub routes: &'slots mut [routes::RouteSlot],
    /// One original locally initiated learning probe at a time.
    pub probe: &'slots mut routes::ProbeSlot,
    /// Persistent receive watermark owners for signed initiators.
    pub sources: &'slots mut [routes::SourceSlot],
}

/// An authenticated received LEARN and its original physical attribution.
///
/// The received bytes stay borrowed while persisted work or relay is pending.
pub struct InboundLearn<'id, 'wire> {
    proof: VerifiedLearn<'wire>,
    source: NeighbourId<'id>,
    received: MonoInstant,
    until: MonoInstant,
    accepted: bool,
    returned: bool,
    forwarded: [u64; MAX_FORWARDS],
}

/// One signed LEARN encoded into a mailbox for an exact physical egress.
#[derive(Debug)]
#[must_use]
pub struct StagedLearn<'id> {
    ingress: NeighbourId<'id>,
    egress: NeighbourId<'id>,
    until: MonoInstant,
}

impl<'id> StagedLearn<'id> {
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

/// A still-live route and the exact direct carrier for its first hop.
pub struct Selected<'id, 'slots> {
    /// Current route evidence, path and original expiry.
    pub route: routes::Route<'id, 'slots>,
    /// Actual current first-hop carrier. Revalidate its identity after a wait.
    pub next: NeighbourId<'id>,
}

struct Probe<'id> {
    id: routes::ProbeId<'id>,
    first: NeighbourId<'id>,
    challenge: [u8; 32],
    stamp: NonZeroU64,
    until: MonoInstant,
}

/// A bounded directory of original carriers, wrapping the official route book.
///
/// Wire evidence can install indirect paths. Only the embedding that owns an
/// actual direct carrier can attach it, renew its validation or observe loss.
pub struct Router<'id, 'slots> {
    instance: &'id Instance,
    local: PeerId,
    neighbours: &'slots mut [NeighbourSlot],
    routes: routes::Routes<'id, 'slots>,
    probe: Option<Probe<'id>>,
    learn_lifetime: Duration,
    now: MonoInstant,
}

impl<'id, 'slots> Router<'id, 'slots> {
    /// Adopt independent empty caller storage for this local peer.
    pub fn new(
        instance: &'id Instance,
        local: PeerId,
        storage: Storage<'slots>,
        limits: routes::Limits,
    ) -> Result<Self, Error> {
        EddsaPublicKey::from_bytes(local.0).validate_peer()?;
        if storage.neighbours.is_empty() {
            return Err(Error::Capacity);
        }
        if storage.neighbours.iter().any(|slot| slot.0.is_some()) {
            return Err(Error::Conflict);
        }
        if limits.probe_lifetime.0 == u64::MAX || limits.route_lifetime.0 == u64::MAX {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            instance,
            local,
            neighbours: storage.neighbours,
            routes: routes::Routes::new(
                &instance.route_ids,
                local,
                storage.routes,
                slice::from_mut(storage.probe),
                storage.sources,
                limits,
            )?,
            probe: None,
            learn_lifetime: limits.probe_lifetime,
            now: MonoInstant(0),
        })
    }

    /// The local peer whose signatures and boxes this router accepts.
    #[must_use]
    pub const fn local_peer(&self) -> PeerId {
        self.local
    }

    fn advance(&mut self, now: MonoInstant) -> Result<(), Error> {
        if now < self.now || now.0 == u64::MAX {
            return Err(Error::TimeUncertain);
        }
        self.now = now;
        for slot in &mut *self.neighbours {
            if let Some(neighbour) = slot.0
                && neighbour.until <= now
            {
                self.routes.neighbour_lost(neighbour.peer);
                slot.0 = None;
            }
        }
        Ok(())
    }

    fn index(&self, id: NeighbourId<'id>) -> Result<usize, Error> {
        if !ptr::eq(id.instance, self.instance) {
            return Err(Error::StaleGeneration);
        }
        self.neighbours
            .iter()
            .position(|slot| slot.0.is_some_and(|n| n.serial == id.serial))
            .ok_or(Error::StaleGeneration)
    }

    fn neighbour(&self, id: NeighbourId<'id>) -> Result<Neighbour, Error> {
        self.neighbours[self.index(id)?]
            .0
            .ok_or(Error::StaleGeneration)
    }

    fn check_lease(&self, until: MonoInstant) -> Result<(), Error> {
        if until <= self.now || until.0 == u64::MAX {
            return Err(Error::Deadline);
        }
        Ok(())
    }

    /// Attach one actual authenticated carrier with a current validation lease.
    pub fn attach(
        &mut self,
        peer: PeerId,
        until: MonoInstant,
        now: MonoInstant,
    ) -> Result<NeighbourId<'id>, Error> {
        self.advance(now)?;
        self.check_lease(until)?;
        if peer == self.local {
            return Err(Error::InvalidInput);
        }
        if first_hop(self.instance, self.neighbours, peer).is_some() {
            return Err(Error::Conflict);
        }
        EddsaPublicKey::from_bytes(peer.0).validate_peer()?;
        let slot = self
            .neighbours
            .iter_mut()
            .find(|slot| slot.0.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.instance.next_neighbour.get();
        self.instance
            .next_neighbour
            .set(serial.checked_add(1).ok_or(Error::Overflow)?);
        slot.0 = Some(Neighbour {
            serial,
            peer,
            until,
            forwarding: None,
        });
        Ok(NeighbourId {
            instance: self.instance,
            serial,
        })
    }

    /// Update validation only for the same still-live actual carrier.
    pub fn renew(
        &mut self,
        id: NeighbourId<'id>,
        until: MonoInstant,
        now: MonoInstant,
    ) -> Result<(), Error> {
        self.advance(now)?;
        self.check_lease(until)?;
        let index = self.index(id)?;
        self.neighbours[index]
            .0
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .until = until;
        Ok(())
    }

    /// Observe retirement of an original direct carrier and invalidate its routes.
    pub fn detach(&mut self, id: NeighbourId<'id>) -> Result<(), Error> {
        let index = self.index(id)?;
        let neighbour = self.neighbours[index]
            .0
            .take()
            .ok_or(Error::StaleGeneration)?;
        self.routes.neighbour_lost(neighbour.peer);
        Ok(())
    }

    /// Revalidate a particular physical route or forwarding selection.
    pub fn peer(&mut self, id: NeighbourId<'id>, now: MonoInstant) -> Result<PeerId, Error> {
        self.advance(now)?;
        Ok(self.neighbour(id)?.peer)
    }

    /// Find a current direct carrier before considering an indirect route.
    pub fn direct(
        &mut self,
        peer: PeerId,
        now: MonoInstant,
    ) -> Result<Option<NeighbourId<'id>>, Error> {
        self.advance(now)?;
        Ok(first_hop(self.instance, self.neighbours, peer))
    }

    /// Reserve an official discovery on an actual carrier before submission.
    ///
    /// The caller reserves the signed source stamp durably before this call.
    /// The returned probe does not count as written until its original receipt.
    pub fn begin_probe(
        &mut self,
        first: NeighbourId<'id>,
        now: MonoInstant,
        stamp: NonZeroU64,
        signer: &EddsaPrivateKey,
        entropy: &mut impl Entropy,
    ) -> Result<(routes::ProbeId<'id>, [u8; dv::LEARN_PREFIX]), Error> {
        self.advance(now)?;
        let until = self
            .neighbour(first)?
            .until
            .min(now.after(self.learn_lifetime)?);
        self.check_signer(signer)?;
        if self.probe.is_some() {
            return Err(Error::WouldBlock);
        }
        let mut challenge = [0; 32];
        entropy.fill(&mut challenge)?;
        let signature = signer.sign(dv::INIT_PURPOSE, &dv::init_region(stamp.get(), &challenge))?;
        let id = self.routes.begin_probe(challenge, stamp.get(), now)?;
        self.probe = Some(Probe {
            id,
            first,
            challenge,
            stamp,
            until,
        });
        Ok((
            id,
            dv::initiate(self.local, stamp.get(), &challenge, signature.as_bytes()),
        ))
    }

    /// Record the original fully written discovery on its selected carrier.
    pub fn probe_written(
        &mut self,
        id: routes::ProbeId<'id>,
        first: NeighbourId<'id>,
        now: MonoInstant,
    ) -> Result<(), Error> {
        self.peer(first, now)?;
        let Some(probe) = self
            .probe
            .as_ref()
            .filter(|probe| probe.id == id && probe.first == first)
        else {
            return Err(Error::StaleGeneration);
        };
        if now >= probe.until {
            return Err(Error::Deadline);
        }
        self.routes.probe_written(id, now)
    }

    /// Observe the deadline or first-carrier loss of a still-owned native probe.
    pub fn expired_probe(
        &mut self,
        now: MonoInstant,
    ) -> Result<Option<routes::ProbeId<'id>>, Error> {
        self.advance(now)?;
        if let Some(probe) = &self.probe
            && (now >= probe.until || self.neighbour(probe.first).is_err())
        {
            return Ok(Some(probe.id));
        }
        self.routes.expired_probe(now)
    }

    /// Retire a failed, expired or completed original probe after native cleanup.
    pub fn retire_probe(&mut self, id: routes::ProbeId<'id>) -> Result<(), Error> {
        self.routes.retire_probe(id)?;
        self.probe = None;
        Ok(())
    }

    /// Current original probe deadline including the captured egress lease.
    pub fn probe_deadline(&self, id: routes::ProbeId<'id>) -> Result<MonoInstant, Error> {
        self.probe
            .as_ref()
            .filter(|probe| probe.id == id)
            .map(|probe| probe.until)
            .ok_or(Error::StaleGeneration)
    }

    /// Bind the signed original to the exact validated ingress and receive time.
    ///
    /// Route admission remains separate and may require durable source work.
    pub fn verify_learn<'wire>(
        &mut self,
        source: NeighbourId<'id>,
        bytes: &'wire [u8],
        now: MonoInstant,
    ) -> Result<InboundLearn<'id, 'wire>, Error> {
        self.advance(now)?;
        let ingress = self.neighbour(source)?;
        let packet = Learn::decode(bytes)?;
        unique_hops(packet.hop_count(), |index| Ok(packet.hop(index)?.peer))?;
        let proof = packet.verify(self.local, ingress.peer)?;
        let until = ingress.until.min(now.after(self.learn_lifetime)?);
        Ok(InboundLearn {
            proof,
            source,
            received: now,
            until,
            accepted: false,
            returned: false,
            forwarded: [0; MAX_FORWARDS],
        })
    }

    /// Apply the original signed LEARN against real probe or durable replay state.
    pub fn accept_learn(
        &mut self,
        input: &mut InboundLearn<'id, '_>,
        now: MonoInstant,
    ) -> Result<routes::Admission<'id>, Error> {
        self.check_input(input, now)?;
        if input.accepted {
            return Err(Error::Conflict);
        }
        let packet = input.proof.packet();
        if packet.initiator()? == self.local {
            let probe = self.probe.as_ref().ok_or(Error::StaleGeneration)?;
            let first = self.neighbour(probe.first)?;
            if now >= probe.until {
                return Err(Error::Deadline);
            }
            if packet.hop(0)?.peer != first.peer
                || packet.challenge()? != probe.challenge
                || packet.stamp()? != probe.stamp.get()
            {
                return Err(Error::StaleGeneration);
            }
        }
        let admission = self.routes.accept(input.proof, true, now)?;
        input.accepted = matches!(admission, routes::Admission::Routes { .. });
        Ok(admission)
    }

    /// Supply the exact durable load result for a pending source operation.
    pub fn source_loaded(
        &mut self,
        id: routes::SourceId<'id>,
        stamp: Option<u64>,
    ) -> Result<(), Error> {
        self.routes.source_loaded(id, stamp)
    }

    /// Identify the original persistent source before applying a media effect.
    pub fn source_peer(&self, id: routes::SourceId<'id>) -> Result<PeerId, Error> {
        self.routes.source_peer(id)
    }

    /// Confirm the exact originally requested source stamp committed durably.
    pub fn source_committed(&mut self, id: routes::SourceId<'id>, stamp: u64) -> Result<(), Error> {
        self.routes.source_committed(id, stamp)
    }

    /// Retire a persistent source on a known loss or an uncertain commit.
    pub fn source_lost(&mut self, id: routes::SourceId<'id>) -> Result<(), Error> {
        self.routes.source_lost(id)
    }

    /// Encode one signed relay for an exact egress into caller-owned storage.
    /// Staging commits one fork of the received original for this mailbox.
    pub fn stage_learn(
        &mut self,
        input: &mut InboundLearn<'id, '_>,
        next: NeighbourId<'id>,
        now: MonoInstant,
        signer: &EddsaPrivateKey,
        scratch: &mut [u8],
    ) -> Result<(StagedLearn<'id>, usize), Error> {
        self.check_input(input, now)?;
        if !input.accepted {
            return Err(Error::NotReady);
        }
        self.check_signer(signer)?;
        let packet = input.proof.packet();
        let egress = self.neighbour(next)?;
        let target = egress.peer;
        let initiator = packet.initiator()?;
        if initiator == self.local || target == input.proof.predecessor() {
            return Err(Error::InvalidInput);
        }
        if packet.hop_count() == dv::MAX_HOPS {
            return Err(Error::TooLarge);
        }
        for index in 0..packet.hop_count() {
            if packet.hop(index)?.peer == target {
                return Err(Error::Malformed);
            }
        }
        let fork = if target == initiator {
            if input.returned {
                return Err(Error::Conflict);
            }
            None
        } else {
            if input.forwarded.contains(&next.serial) {
                return Err(Error::Conflict);
            }
            Some(
                input
                    .forwarded
                    .iter_mut()
                    .find(|serial| **serial == 0)
                    .ok_or(Error::Capacity)?,
            )
        };
        let signature = signer.sign(
            dv::HOP_PURPOSE,
            &dv::hop_region(input.proof.predecessor(), target, &packet.challenge()?),
        )?;
        let bytes = packet.forward(
            dv::Hop {
                peer: self.local,
                signature: *signature.as_bytes(),
            },
            true,
            now.duration_since(input.received)?.0,
            scratch,
        )?;
        if let Some(slot) = fork {
            *slot = next.serial;
        } else {
            input.returned = true;
        }
        Ok((
            StagedLearn {
                ingress: input.source,
                egress: next,
                until: input.until.min(egress.until),
            },
            bytes,
        ))
    }

    /// Revalidate the original relay before making its mailbox available.
    pub fn check_staged_learn(
        &mut self,
        relay: &StagedLearn<'id>,
        now: MonoInstant,
    ) -> Result<(), Error> {
        self.check_pair(relay.ingress, relay.egress, relay.until, now)
    }

    fn check_pair(
        &mut self,
        ingress: NeighbourId<'id>,
        egress: NeighbourId<'id>,
        until: MonoInstant,
        now: MonoInstant,
    ) -> Result<(), Error> {
        self.advance(now)?;
        if now >= until {
            return Err(Error::Deadline);
        }
        self.neighbour(ingress)?;
        self.neighbour(egress)?;
        Ok(())
    }

    fn check_input(
        &mut self,
        input: &InboundLearn<'id, '_>,
        now: MonoInstant,
    ) -> Result<(), Error> {
        self.advance(now)?;
        if now >= input.until {
            return Err(Error::Deadline);
        }
        if input.proof.local() != self.local
            || self.neighbour(input.source)?.peer != input.proof.predecessor()
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    fn check_signer(&self, signer: &EddsaPrivateKey) -> Result<(), Error> {
        if *signer.public_key().as_bytes() == self.local.0 {
            Ok(())
        } else {
            Err(Error::Authentication)
        }
    }

    /// Select the best evidenced route with a current real first hop.
    pub fn select(
        &mut self,
        target: PeerId,
        policy: routes::SendPolicy,
        now: MonoInstant,
    ) -> Result<Option<Selected<'id, '_>>, Error> {
        self.advance(now)?;
        let neighbours = &*self.neighbours;
        let instance = self.instance;
        self.routes
            .select(target, policy, now, |peer| {
                first_hop(instance, neighbours, peer).is_some()
            })?
            .map(|route| selected(instance, neighbours, route))
            .transpose()
    }

    /// Revalidate the same learned route and original first hop before egress.
    pub fn select_id(
        &mut self,
        id: routes::RouteId<'id>,
        target: PeerId,
        policy: routes::SendPolicy,
        now: MonoInstant,
    ) -> Result<Selected<'id, '_>, Error> {
        self.advance(now)?;
        let neighbours = &*self.neighbours;
        let instance = self.instance;
        let route = self.routes.select_id(id, target, policy, now, |peer| {
            first_hop(instance, neighbours, peer).is_some()
        })?;
        selected(instance, neighbours, route)
    }
}

fn first_hop<'id>(
    instance: &'id Instance,
    neighbours: &[NeighbourSlot],
    peer: PeerId,
) -> Option<NeighbourId<'id>> {
    neighbours
        .iter()
        .filter_map(|slot| slot.0)
        .find(|n| n.peer == peer)
        .map(|neighbour| NeighbourId {
            instance,
            serial: neighbour.serial,
        })
}

fn selected<'id, 'slots>(
    instance: &'id Instance,
    neighbours: &[NeighbourSlot],
    route: routes::Route<'id, 'slots>,
) -> Result<Selected<'id, 'slots>, Error> {
    let peer = *route.path.first().ok_or(Error::Conflict)?;
    let next = first_hop(instance, neighbours, peer).ok_or(Error::NotReady)?;
    Ok(Selected { route, next })
}

fn unique_hops(
    count: usize,
    mut peer: impl FnMut(usize) -> Result<PeerId, Error>,
) -> Result<(), Error> {
    let mut path = [PeerId([0; 32]); dv::MAX_HOPS];
    for index in 0..count {
        let hop = peer(index)?;
        if path[..index].contains(&hop) {
            return Err(Error::Malformed);
        }
        path[index] = hop;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
