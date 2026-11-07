//! Bounded caller-storage DV route/probe/replay state. Source observations and
//! durable completion declarations must come from the original actual providers.
use super::{MAX_HOPS, VerifiedLearn};
use crate::PeerId;
use core::{cell::Cell, fmt, ptr};
use gnunet_types::{Duration, Error, MonoInstant};

/// Maximum peers after the local source: one direct receiver and at most
/// sixteen additional box route entries, including the ultimate target.
pub const MAX_ROUTE_PEERS: usize = MAX_HOPS + 1;

/// Caller-owned identity domain. Serial allocation is local metadata, not entropy.
pub struct Instance {
    next: Cell<u64>,
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
impl Instance {
    /// New independent domain with no process-global state.
    pub const fn new() -> Self {
        Self { next: Cell::new(1) }
    }
    fn next(&self) -> Result<u64, Error> {
        let n = self.next.get();
        self.next.set(n.checked_add(1).ok_or(Error::Overflow)?);
        Ok(n)
    }
}
macro_rules! identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy)]
        pub struct $name<'id> {
            domain: &'id Instance,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                ptr::eq(self.domain, other.domain) && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.serial)
                    .finish()
            }
        }
    };
}
identity!(
    ProbeId,
    "One original discovery operation; a replacement cannot reuse its identity."
);
identity!(
    SourceId,
    "One original replay-store load/commit owner, invalidated on physical loss."
);
identity!(
    RouteId,
    "One route admission generation, distinct from reused caller slots."
);
/// Distinguish nonce-confirmed routes from passively observed signed routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    /// Actual matching locally transmitted probe returned before its target.
    Confirmed,
    /// Hop signatures verified, but the local peer did not issue this challenge.
    Passive,
}
/// Required route evidence for an actual transmission. Selection does not
/// manufacture local nonce freshness, RTT, a native write or remote delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendPolicy {
    /// Require an original whole-written local probe to have returned in time.
    Confirmed,
    /// Also permit a signature-verified inverse path whose every selected hop
    /// was bidirectional and whose original admission stamp was durably accepted
    /// by its still-live source. A newer watermark does not revoke that lease.
    /// Such a path stays Passive and has no locally measured RTT.
    Bidirectional,
}
impl SendPolicy {
    fn permits(self, freshness: Freshness) -> bool {
        self == Self::Bidirectional || freshness == Freshness::Confirmed
    }
}
// Private admission provenance. A raw peer/stamp or public Freshness value
// cannot install a path or bind it to a replacement source generation.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Evidence {
    Probe(u64),
    Reverse {
        index: usize,
        source: u64,
        stamp: u64,
    },
}
fn evidence_live(sources: &[SourceSlot], evidence: Option<Evidence>) -> bool {
    match evidence {
        Some(Evidence::Probe(_)) => true,
        Some(Evidence::Reverse {
            index,
            source,
            stamp,
        }) => sources.get(index).is_some_and(|s| {
            s.id == Some(source)
                && s.loaded
                && s.committed.is_some_and(|committed| committed >= stamp)
        }),
        None => false,
    }
}
/// Finite local policy. It changes no external message or signature format.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original probe creation through accepted return, never renewed on write.
    pub probe_lifetime: Duration,
    /// Maximum retained route lifetime in this process's monotonic coordinates.
    pub route_lifetime: Duration,
    /// At most three alternative paths per target, matching the active default.
    pub paths_per_target: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            probe_lifetime: Duration(60_000_000),
            route_lifetime: Duration(300_000_000),
            paths_per_target: 3,
        }
    }
}
/// Caller-provided route storage. Unused identity bytes are never sent or trusted.
#[derive(Clone)]
pub struct RouteSlot {
    id: Option<u64>,
    path: [PeerId; MAX_ROUTE_PEERS],
    len: usize,
    until: MonoInstant,
    rtt: Option<Duration>,
    freshness: Freshness,
    evidence: Option<Evidence>,
}
impl Default for RouteSlot {
    fn default() -> Self {
        Self::empty()
    }
}
impl RouteSlot {
    /// One unused route slot; it grants no peer or authentication authority.
    pub const fn empty() -> Self {
        Self {
            id: None,
            path: [PeerId([0; 32]); MAX_ROUTE_PEERS],
            len: 0,
            until: MonoInstant(0),
            rtt: None,
            freshness: Freshness::Passive,
            evidence: None,
        }
    }
}
/// Caller-provided original probe storage. Expiration does not prove native stop.
#[derive(Clone)]
pub struct ProbeSlot {
    id: Option<u64>,
    challenge: [u8; 32],
    stamp: u64,
    sent: Option<MonoInstant>,
    until: MonoInstant,
}
impl Default for ProbeSlot {
    fn default() -> Self {
        Self::empty()
    }
}
impl ProbeSlot {
    /// An unused slot. No nonce is generated by zero initialization.
    pub const fn empty() -> Self {
        Self {
            id: None,
            challenge: [0; 32],
            stamp: 0,
            sent: None,
            until: MonoInstant(0),
        }
    }
}
/// Caller-provided persistent-source state. Missing data is distinct from zero.
#[derive(Clone)]
pub struct SourceSlot {
    id: Option<u64>,
    peer: PeerId,
    loaded: bool,
    committed: Option<u64>,
    pending: Option<u64>,
}
impl Default for SourceSlot {
    fn default() -> Self {
        Self::empty()
    }
}
impl SourceSlot {
    /// One unused source slot, requiring a real load before passive admission.
    pub const fn empty() -> Self {
        Self {
            id: None,
            peer: PeerId([0; 32]),
            loaded: false,
            committed: None,
            pending: None,
        }
    }
}
/// Original source work; declarations are not native admission or persistence receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceWork<'id> {
    /// Load the actual persisted monotime for this source; retain original packet.
    Load {
        /// Original provider owner.
        source: SourceId<'id>,
        /// Actual peer whose watermark is required.
        peer: PeerId,
    },
    /// Commit the exact source watermark before applying the retained packet.
    Store {
        /// Original provider owner.
        source: SourceId<'id>,
        /// Actual source peer.
        peer: PeerId,
        /// Eight-byte network-order monotime value to persist.
        stamp: u64,
    },
}
/// Result of accepting one actually signature-verified learn packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission<'id> {
    /// Native work is required; no path was admitted by this call.
    Source(SourceWork<'id>),
    /// Existing original load/commit is pending; do not create another operation.
    Pending,
    /// Completed local route admissions, not remote reachability acknowledgements.
    Routes {
        /// Number of slots added/refreshed/replaced.
        changed: usize,
        /// Freshness of this packet's route evidence.
        freshness: Freshness,
    },
}
/// Borrowed original route. The mutable table cannot change it while borrowed.
pub struct Route<'id, 'a> {
    /// Exact admission generation.
    pub id: RouteId<'id>,
    /// Path after the local peer, including the direct first hop and final target.
    pub path: &'a [PeerId],
    /// Original monotonic expiration, never a remote signed stamp or UTC.
    pub until: MonoInstant,
    /// Measured local nonce round-trip estimate; passive evidence has no fake RTT.
    pub rtt: Option<Duration>,
    /// Whether this route was freshly probed by this process.
    pub freshness: Freshness,
}
/// Noalloc route book. It owns no sockets, keys, cryptographic worker or storage.
pub struct Routes<'id, 'slots> {
    instance: &'id Instance,
    local: PeerId,
    slots: &'slots mut [RouteSlot],
    probes: &'slots mut [ProbeSlot],
    sources: &'slots mut [SourceSlot],
    limits: Limits,
    now: MonoInstant,
}
impl<'id, 'slots> Routes<'id, 'slots> {
    /// Retained candidate targets, without allocation or reachability claims.
    /// Caller must still select current usable evidence under original time.
    pub fn targets(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.slots
            .iter()
            .filter(|r| {
                r.id.is_some()
                    && r.len > 0
                    && r.until.0 > self.now.0
                    && evidence_live(self.sources, r.evidence)
            })
            .map(|r| r.path[r.len - 1])
    }
    /// Adopt empty caller directories. Reinitialization cannot silently discard
    /// still-live native obligations or persisted-source load state.
    pub fn new(
        instance: &'id Instance,
        local: PeerId,
        slots: &'slots mut [RouteSlot],
        probes: &'slots mut [ProbeSlot],
        sources: &'slots mut [SourceSlot],
        limits: Limits,
    ) -> Result<Self, Error> {
        if slots.is_empty() || probes.is_empty() || sources.is_empty() {
            return Err(Error::Capacity);
        }
        if limits.probe_lifetime.0 == 0
            || limits.route_lifetime.0 == 0
            || !(1..=3).contains(&limits.paths_per_target)
        {
            return Err(Error::InvalidInput);
        }
        if slots.iter().any(|s| s.id.is_some())
            || probes.iter().any(|s| s.id.is_some())
            || sources.iter().any(|s| s.id.is_some())
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            instance,
            local,
            slots,
            probes,
            sources,
            limits,
            now: MonoInstant(0),
        })
    }
    fn advance(&mut self, now: MonoInstant) -> Result<(), Error> {
        if now.0 < self.now.0 {
            return Err(Error::TimeUncertain);
        }
        self.now = now;
        for slot in self.slots.iter_mut() {
            if slot.id.is_some()
                && (slot.until.0 <= now.0 || !evidence_live(self.sources, slot.evidence))
            {
                *slot = RouteSlot::empty();
            }
        }
        Ok(())
    }
    fn check_domain(&self, domain: &Instance) -> Result<(), Error> {
        if ptr::eq(self.instance, domain) {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    /// Admit an actual caller-generated fresh public nonce and durably reserved
    /// signed stamp, before calling the signer or native sender. No send is claimed.
    pub fn begin_probe(
        &mut self,
        challenge: [u8; 32],
        stamp: u64,
        now: MonoInstant,
    ) -> Result<ProbeId<'id>, Error> {
        self.advance(now)?;
        if self
            .probes
            .iter()
            .any(|p| p.id.is_some() && p.challenge == challenge)
        {
            return Err(Error::Replay);
        }
        let i = self
            .probes
            .iter()
            .position(|p| p.id.is_none())
            .ok_or(Error::Capacity)?;
        let until = now.after(self.limits.probe_lifetime)?;
        let serial = self.instance.next()?;
        self.probes[i] = ProbeSlot {
            id: Some(serial),
            challenge,
            stamp,
            sent: None,
            until,
        };
        Ok(ProbeId {
            domain: self.instance,
            serial,
        })
    }
    /// Declare an actual whole native transmission of this original discovery.
    /// Broadcast copies keep the first actual write time and never renew the
    /// deadline anchored at begin_probe. The host retains all original send debt.
    pub fn probe_written(&mut self, id: ProbeId<'id>, now: MonoInstant) -> Result<(), Error> {
        self.check_domain(id.domain)?;
        self.advance(now)?;
        let slot = self
            .probes
            .iter_mut()
            .find(|p| p.id == Some(id.serial))
            .ok_or(Error::StaleGeneration)?;
        if slot.until.0 <= now.0 {
            return Err(Error::Deadline);
        }
        if slot.sent.is_none() {
            slot.sent = Some(now);
        }
        Ok(())
    }
    /// Return one expired original operation requiring actual host retirement.
    /// Merely reaching its deadline does not free/rebind the native obligation.
    pub fn expired_probe(&mut self, now: MonoInstant) -> Result<Option<ProbeId<'id>>, Error> {
        self.advance(now)?;
        Ok(self
            .probes
            .iter()
            .find(|p| p.id.is_some() && p.until.0 <= now.0)
            .and_then(|p| p.id)
            .map(|serial| ProbeId {
                domain: self.instance,
                serial,
            }))
    }
    /// Retire only after the original native operation has stopped or completed.
    pub fn retire_probe(&mut self, id: ProbeId<'id>) -> Result<(), Error> {
        self.check_domain(id.domain)?;
        let slot = self
            .probes
            .iter_mut()
            .find(|p| p.id == Some(id.serial))
            .ok_or(Error::StaleGeneration)?;
        *slot = ProbeSlot::empty();
        Ok(())
    }
    fn source(&mut self, peer: PeerId) -> Result<(usize, bool), Error> {
        if let Some(i) = self
            .sources
            .iter()
            .position(|s| s.id.is_some() && s.peer == peer)
        {
            return Ok((i, false));
        }
        let i = self
            .sources
            .iter()
            .position(|s| s.id.is_none())
            .ok_or(Error::Capacity)?;
        self.sources[i] = SourceSlot {
            id: Some(self.instance.next()?),
            peer,
            loaded: false,
            committed: None,
            pending: None,
        };
        Ok((i, true))
    }
    fn source_index(&self, id: SourceId<'id>) -> Result<usize, Error> {
        self.check_domain(id.domain)?;
        self.sources
            .iter()
            .position(|s| s.id == Some(id.serial))
            .ok_or(Error::StaleGeneration)
    }
    /// Read the public peer bound to this exact live source generation. A
    /// provider uses this to reject a receipt for a differently declared key.
    pub fn source_peer(&self, id: SourceId<'id>) -> Result<PeerId, Error> {
        let i = self.source_index(id)?;
        Ok(self.sources[i].peer)
    }
    /// Apply only the matching original actual PEERSTORE load result. None means
    /// an actual completed empty iteration, not a guessed zero watermark.
    pub fn source_loaded(
        &mut self,
        id: SourceId<'id>,
        persisted: Option<u64>,
    ) -> Result<(), Error> {
        let i = self.source_index(id)?;
        let s = &mut self.sources[i];
        if s.loaded || s.pending.is_some() {
            return Err(Error::Replay);
        }
        s.loaded = true;
        s.committed = persisted;
        Ok(())
    }
    /// A real matching STORE_RESULT completed successfully for this exact source
    /// and proposed value. Queue admission/whole writing are insufficient.
    pub fn source_committed(&mut self, id: SourceId<'id>, stamp: u64) -> Result<(), Error> {
        let i = self.source_index(id)?;
        let s = &mut self.sources[i];
        if !s.loaded || s.pending != Some(stamp) {
            return Err(Error::StaleGeneration);
        }
        s.committed = Some(stamp);
        s.pending = None;
        // This floor controls admission of new LEARN packets. Existing signed
        // routes already passed their own durable barrier and retain their
        // original lease until actual source loss, replacement or expiration.
        Ok(())
    }
    fn invalidate_source(&mut self, serial: u64) {
        for slot in self.slots.iter_mut() {
            if matches!(slot.evidence, Some(Evidence::Reverse { source, .. }) if source == serial) {
                *slot = RouteSlot::empty();
            }
        }
    }
    /// Original source was physically retired after failure/unknown mutation.
    /// A later source requires a fresh identity and actual load, never replay.
    pub fn source_lost(&mut self, id: SourceId<'id>) -> Result<(), Error> {
        let i = self.source_index(id)?;
        self.sources[i] = SourceSlot::empty();
        self.invalidate_source(id.serial);
        Ok(())
    }
    fn reverse_evidence(&self, peer: PeerId, stamp: u64) -> Result<Evidence, Error> {
        let (index, source) = self
            .sources
            .iter()
            .enumerate()
            .find(|(_, s)| {
                s.id.is_some()
                    && s.peer == peer
                    && s.loaded
                    && s.pending.is_none()
                    && s.committed == Some(stamp)
            })
            .and_then(|(index, s)| s.id.map(|source| (index, source)))
            .ok_or(Error::StaleGeneration)?;
        Ok(Evidence::Reverse {
            index,
            source,
            stamp,
        })
    }
    fn source_gate(&mut self, peer: PeerId, stamp: u64) -> Result<Option<Admission<'id>>, Error> {
        let (i, fresh) = self.source(peer)?;
        let s = &mut self.sources[i];
        let source = SourceId {
            domain: self.instance,
            serial: s.id.ok_or(Error::Conflict)?,
        };
        if fresh {
            return Ok(Some(Admission::Source(SourceWork::Load { source, peer })));
        }
        if !s.loaded || s.pending.is_some() {
            return Ok(Some(Admission::Pending));
        }
        match s.committed {
            Some(old) if stamp < old => return Err(Error::Replay),
            Some(old) if stamp == old => return Ok(None),
            _ => {}
        }
        s.pending = Some(stamp);
        Ok(Some(Admission::Source(SourceWork::Store {
            source,
            peer,
            stamp,
        })))
    }
    fn insert(
        &mut self,
        path: &[PeerId],
        until: MonoInstant,
        rtt: Option<Duration>,
        freshness: Freshness,
        evidence: Evidence,
    ) -> Result<bool, Error> {
        if !(2..=MAX_ROUTE_PEERS).contains(&path.len()) {
            return Err(Error::InvalidInput);
        }
        for (i, p) in path.iter().enumerate() {
            if *p == self.local || path[..i].contains(p) {
                return Err(Error::Malformed);
            }
        }
        let target = path[path.len() - 1];
        if let Some(i) = self
            .slots
            .iter()
            .position(|s| s.id.is_some() && s.len == path.len() && &s.path[..s.len] == path)
        {
            if freshness == Freshness::Confirmed || self.slots[i].freshness == Freshness::Passive {
                let serial = if self.slots[i].evidence != Some(evidence) {
                    Some(self.instance.next()?)
                } else {
                    self.slots[i].id
                };
                let s = &mut self.slots[i];
                s.id = serial;
                s.until = until;
                s.rtt = rtt;
                s.freshness = freshness;
                s.evidence = Some(evidence);
            }
            return Ok(true);
        }
        let count = self
            .slots
            .iter()
            .filter(|s| s.id.is_some() && s.path[s.len - 1] == target)
            .count();
        let same_worst = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.id.is_some() && s.path[s.len - 1] == target)
            .max_by_key(|(_, s)| {
                (
                    s.freshness == Freshness::Passive,
                    s.len,
                    s.rtt.map_or(u64::MAX, |r| r.0),
                )
            })
            .map(|(i, _)| i);
        let i = if count >= self.limits.paths_per_target {
            let i = same_worst.ok_or(Error::Conflict)?;
            let old = &self.slots[i];
            if (
                freshness == Freshness::Passive,
                path.len(),
                rtt.map_or(u64::MAX, |r| r.0),
            ) >= (
                old.freshness == Freshness::Passive,
                old.len,
                old.rtt.map_or(u64::MAX, |r| r.0),
            ) {
                return Ok(false);
            }
            i
        } else {
            self.slots
                .iter()
                .position(|s| s.id.is_none())
                .ok_or(Error::Capacity)?
        };
        let mut slot = RouteSlot::empty();
        slot.id = Some(self.instance.next()?);
        slot.len = path.len();
        slot.path[..path.len()].copy_from_slice(path);
        slot.until = until;
        slot.rtt = rtt;
        slot.freshness = freshness;
        slot.evidence = Some(evidence);
        self.slots[i] = slot;
        Ok(true)
    }
    /// Admit signed routes only after original probe freshness or actual source
    /// watermark load/commit. A signed inverse path is usable only through
    /// actually bidirectional hops and its same still-current source generation.
    /// It remains Passive with no fabricated RTT. The host independently checks
    /// the exact current direct first-hop lease before actual transmission.
    pub fn accept(
        &mut self,
        proof: VerifiedLearn<'_>,
        reverse_link: bool,
        now: MonoInstant,
    ) -> Result<Admission<'id>, Error> {
        if proof.local() != self.local {
            return Err(Error::Authentication);
        }
        self.advance(now)?;
        let packet = proof.packet();
        let initiator = packet.initiator()?;
        let until = now.after(self.limits.route_lifetime)?;
        let mut path = [PeerId([0; 32]); MAX_ROUTE_PEERS];
        let mut changed = 0;
        if initiator == self.local {
            let challenge = packet.challenge()?;
            let stamp = packet.stamp()?;
            let probe = self
                .probes
                .iter()
                .find(|p| {
                    p.id.is_some()
                        && p.challenge == challenge
                        && p.stamp == stamp
                        && p.sent.is_some()
                        && p.until.0 > now.0
                })
                .ok_or(Error::StaleGeneration)?;
            let evidence = Evidence::Probe(probe.id.ok_or(Error::Conflict)?);
            let start = probe.sent.ok_or(Error::NotReady)?;
            let elapsed = now.duration_since(start)?.0;
            let network = elapsed
                .checked_sub(packet.delay()?)
                .ok_or(Error::TimeUncertain)?;
            let per_hop = network
                .checked_div(packet.hop_count() as u64)
                .ok_or(Error::Malformed)?;
            for i in 0..packet.hop_count() {
                path[i] = packet.hop(i)?.peer;
                if i > 0
                    && self.insert(
                        &path[..i + 1],
                        until,
                        Some(Duration(per_hop.saturating_mul((i + 1) as u64))),
                        Freshness::Confirmed,
                        evidence,
                    )?
                {
                    changed += 1;
                }
            }
            return Ok(Admission::Routes {
                changed,
                freshness: Freshness::Confirmed,
            });
        }
        if let Some(pending) = self.source_gate(initiator, packet.stamp()?)? {
            return Ok(pending);
        }
        if reverse_link && packet.hop_count() > 0 {
            let evidence = self.reverse_evidence(initiator, packet.stamp()?)?;
            path[0] = proof.predecessor();
            let history = packet.bidirectional()?;
            for i in 0..packet.hop_count() {
                if history & (1u16 << i) == 0 {
                    break;
                }
                path[i + 1] = if i + 1 == packet.hop_count() {
                    initiator
                } else {
                    packet.hop(packet.hop_count() - i - 2)?.peer
                };
                if self.insert(&path[..i + 2], until, None, Freshness::Passive, evidence)? {
                    changed += 1;
                }
            }
        }
        Ok(Admission::Routes {
            changed,
            freshness: Freshness::Passive,
        })
    }
    /// Pick the best live path with a current actual first hop. The false
    /// profile includes only eligible signed bidirectional inverse paths; it
    /// never treats a raw passive observation as transmission authority.
    pub fn best(
        &mut self,
        target: PeerId,
        require_confirmed: bool,
        now: MonoInstant,
        reachable: impl FnMut(PeerId) -> bool,
    ) -> Result<Option<Route<'id, '_>>, Error> {
        self.select(
            target,
            if require_confirmed {
                SendPolicy::Confirmed
            } else {
                SendPolicy::Bidirectional
            },
            now,
            reachable,
        )
    }
    /// Select actual usable route evidence. Local nonce confirmation is ranked
    /// first; signed inverse evidence retains Passive freshness and absent RTT.
    /// Advancing a source watermark gates new packets without revoking an
    /// already admitted route's original lease. Actual source loss still revokes
    /// that source generation, and selection always checks the current first hop.
    pub fn select(
        &mut self,
        target: PeerId,
        policy: SendPolicy,
        now: MonoInstant,
        mut reachable: impl FnMut(PeerId) -> bool,
    ) -> Result<Option<Route<'id, '_>>, Error> {
        self.advance(now)?;
        let best = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.id.is_some()
                    && s.len > 0
                    && s.path[s.len - 1] == target
                    && policy.permits(s.freshness)
                    && evidence_live(self.sources, s.evidence)
                    && reachable(s.path[0])
            })
            .min_by_key(|(_, s)| {
                (
                    s.freshness == Freshness::Passive,
                    s.len,
                    s.rtt.map_or(u64::MAX, |r| r.0),
                )
            })
            .map(|(i, _)| i);
        let Some(i) = best else {
            return Ok(None);
        };
        Ok(Some(self.view(i)?))
    }
    /// Revalidate the SAME selected generation and final target before actual
    /// send admission. A new best route cannot silently replace this one.
    pub fn select_id(
        &mut self,
        id: RouteId<'id>,
        target: PeerId,
        policy: SendPolicy,
        now: MonoInstant,
        mut reachable: impl FnMut(PeerId) -> bool,
    ) -> Result<Route<'id, '_>, Error> {
        self.check_domain(id.domain)?;
        self.advance(now)?;
        let i = self
            .slots
            .iter()
            .position(|s| s.id == Some(id.serial))
            .ok_or(Error::StaleGeneration)?;
        let s = &self.slots[i];
        if s.len == 0 || s.path[s.len - 1] != target {
            return Err(Error::Authentication);
        }
        if !policy.permits(s.freshness)
            || !evidence_live(self.sources, s.evidence)
            || !reachable(s.path[0])
        {
            return Err(Error::NotReady);
        }
        self.view(i)
    }
    fn view(&self, i: usize) -> Result<Route<'id, '_>, Error> {
        let s = self.slots.get(i).ok_or(Error::StaleGeneration)?;
        Ok(Route {
            id: RouteId {
                domain: self.instance,
                serial: s.id.ok_or(Error::StaleGeneration)?,
            },
            path: &s.path[..s.len],
            until: s.until,
            rtt: s.rtt,
            freshness: s.freshness,
        })
    }
    /// Exact still-current route generation; expiration/removal cannot retag a
    /// previously admitted native send under the reused path slot.
    pub fn route(&mut self, id: RouteId<'id>, now: MonoInstant) -> Result<Route<'id, '_>, Error> {
        self.check_domain(id.domain)?;
        self.advance(now)?;
        let i = self
            .slots
            .iter()
            .position(|s| s.id == Some(id.serial))
            .ok_or(Error::StaleGeneration)?;
        self.view(i)
    }
    /// Invalidate all paths whose actual first-hop provider was lost.
    pub fn neighbour_lost(&mut self, peer: PeerId) -> usize {
        let mut count = 0;
        for s in self.slots.iter_mut() {
            if s.id.is_some() && s.path[0] == peer {
                *s = RouteSlot::empty();
                count += 1;
            }
        }
        count
    }
}
