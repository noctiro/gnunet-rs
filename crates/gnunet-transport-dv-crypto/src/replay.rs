//! Exact bounded replay admission for one live caller-observed local source.
//! No disk/store/load/commit or restart protection is implied. Only authentic
//! Opened constructors can supply the private AEAD/signature/header context.
use super::*;
const FRESH: u8 = 0;
const LIVE: u8 = 1;
const LOST: u8 = 2;
#[derive(Clone, Copy)]
struct SourceId<'id> {
    instance: &'id Instance,
    allocation: u64,
}
// Pointer/domain identity, not structural Cell equality.
fn same(a: SourceId<'_>, b: SourceId<'_>) -> bool {
    core::ptr::eq(a.instance, b.instance) && a.allocation == b.allocation
}
fn id<'id>(source: &Source<'id>) -> SourceId<'id> {
    SourceId {
        instance: source.instance,
        allocation: source.allocation,
    }
}
struct Peer<'id> {
    source: SourceId<'id>,
    sender: PeerId,
    highest: u64,
}
struct Nonce<'id> {
    source: SourceId<'id>,
    sender: PeerId,
    encapsulation: [u8; 32],
    stamp: u64,
    nonce: [u8; 24],
}
/// Borrowed historical record from this actual live ledger. Private construction
/// does not turn this view into another admission or persistent/load receipt.
pub struct Recorded<'a, 'id> {
    entry: &'a Nonce<'id>,
    target: PeerId,
}
impl Recorded<'_, '_> {
    /// Original authenticated sender retained on this nonce admission.
    pub const fn sender(&self) -> PeerId {
        self.entry.sender
    }
    /// Original bound local target, fixed for the owning source allocation.
    pub const fn target(&self) -> PeerId {
        self.target
    }
    /// Original authenticated sender-monotonic stamp.
    pub const fn stamp(&self) -> u64 {
        self.entry.stamp
    }
    /// Actual original public encapsulation recorded, never a KEM key.
    pub const fn encapsulation(&self) -> &[u8; 32] {
        &self.entry.encapsulation
    }
    /// Exact original nonce admitted under that target/encapsulation.
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.entry.nonce
    }
}
/// Caller-provided private watermark row. No verified/history constructor exists.
/// Slots contain public replay metadata only, and retain it when Replay drops.
pub struct PeerSlot<'id> {
    value: Option<Peer<'id>>,
}
impl PeerSlot<'_> {
    /// Empty row; constructing fresh storage is not replay recovery.
    pub const fn new() -> Self {
        Self { value: None }
    }
}
impl Default for PeerSlot<'_> {
    fn default() -> Self {
        Self::new()
    }
}
/// Caller-provided private exact-nonce row, retained through cache eviction and
/// Replay-owner Drop. Only actual admission creates a populated record.
pub struct NonceSlot<'id> {
    value: Option<Nonce<'id>>,
}
impl NonceSlot<'_> {
    /// Empty row; no packet or cryptographic state is fabricated.
    pub const fn new() -> Self {
        Self { value: None }
    }
}
impl Default for NonceSlot<'_> {
    fn default() -> Self {
        Self::new()
    }
}
/// Caller CPU bounds for fixed open-addressed tables. Hashing here only chooses
/// a bucket; exact original bytes decide equality and cryptographic authenticity
/// remains the private Opened path. Chosen collisions cause bounded rejection.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum watermark probes per admission, nonzero and clipped to row count.
    pub peer_probes: usize,
    /// Maximum exact-nonce probes per admission, nonzero/clipped to row count.
    pub nonce_probes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peer_probes: 64,
            nonce_probes: 64,
        }
    }
}
fn bucket(parts: &[&[u8]], count: usize) -> usize {
    let mut h = 0xcbf29ce484222325u64;
    for part in parts {
        for byte in *part {
            h = (h ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        }
    }
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    (h as usize) % count
}
/// Actual bounded local rejection. This does not assert a service/IO result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// Source/task expired, retired, mismatched, or replay owner lost.
    Source(Error),
    /// Already admitted this exact nonce under the same local target/key.
    Duplicate,
    /// Sender's authenticated source-monotonic value is below its live watermark.
    OlderStamp,
    /// Fixed peer watermark storage is full; no live peer was evicted.
    PeerCapacity,
    /// Fixed exact-nonce storage is full; no live nonce was evicted.
    NonceCapacity,
    /// Bounded collision-chain work exhausted; existing live history is unchanged.
    ProbeCapacity,
}
/// Rejection preserves the original authenticated plaintext/Task for caller
/// backpressure/reporting/drop. No row/watermark changes on any rejection.
pub struct Denied<T> {
    /// Actual local bounded cause.
    pub reason: Reason,
    /// Original unchanged authenticated owner, erased on drop.
    pub value: T,
}
impl<T> fmt::Debug for Denied<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvReplayDenied")
            .field("reason", &self.reason)
            .field("value", &"[REDACTED]")
            .finish()
    }
}
/// Bounded live-source counts, without payload, key, or invented durable ACK.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// Occupied authenticated sender watermark rows.
    pub peers: usize,
    /// Occupied exact nonce rows; never reclaimed by a cache TTL/hit.
    pub nonces: usize,
}
/// One exclusive live replay owner and fixed caller rows for an original source.
/// Drop latches that source unavailable for another replay owner and PRESERVES
/// rows. A fresh owner cannot silently erase/reopen an active source's history.
/// Actual source retirement permits explicit clock-independent row clearing.
pub struct Replay<'slots, 'source, 'id> {
    source: &'source Source<'id>,
    peers: &'slots mut [PeerSlot<'id>],
    nonces: &'slots mut [NonceSlot<'id>],
    retired: bool,
    limits: Limits,
}
impl<'slots, 'source, 'id> Replay<'slots, 'source, 'id> {
    /// Attach once to the original source and fresh nonempty caller storage.
    /// The source is caller's actual local epoch (not an attacker-chosen key or
    /// a cache entry). Empty/nonfresh storage/refused source leaves it unchanged.
    pub fn new(
        source: &'source Source<'id>,
        peers: &'slots mut [PeerSlot<'id>],
        nonces: &'slots mut [NonceSlot<'id>],
        limits: Limits,
    ) -> Result<Self, Error> {
        if !source.active.get() {
            return Err(Error::Closed);
        }
        if source.replay_claim.get() != FRESH {
            return Err(Error::Conflict);
        }
        if peers.is_empty()
            || nonces.is_empty()
            || limits.peer_probes == 0
            || limits.nonce_probes == 0
        {
            return Err(Error::InvalidInput);
        }
        if peers.iter().any(|p| p.value.is_some()) || nonces.iter().any(|n| n.value.is_some()) {
            return Err(Error::Conflict);
        }
        source.replay_claim.set(LIVE);
        Ok(Self {
            source,
            peers,
            nonces,
            retired: false,
            limits,
        })
    }
    /// Current bounded row use. Occupancy is not persistent/delivery evidence.
    pub fn counts(&self) -> Counts {
        Counts {
            peers: self.peers.iter().filter(|p| p.value.is_some()).count(),
            nonces: self.nonces.iter().filter(|n| n.value.is_some()).count(),
        }
    }
    /// Borrow one actual occupied original nonce record, without allocating or
    /// creating another trusted packet/admission. Empty/out-of-range is None.
    pub fn recorded(&self, index: usize) -> Option<Recorded<'_, 'id>> {
        self.nonces
            .get(index)
            .and_then(|slot| slot.value.as_ref())
            .map(|entry| Recorded {
                entry,
                target: self.source.local,
            })
    }
    fn check(&self, opened: &Opened<'_, 'id, '_>, now: u64) -> Result<(), Error> {
        if self.retired || !self.source.active.get() || self.source.replay_claim.get() != LIVE {
            return Err(Error::Closed);
        }
        opened.task.check(now)?;
        if !same(id(self.source), id(opened.task.source)) || opened.target() != self.source.local {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn peer_row(&self, sender: PeerId) -> Result<usize, Reason> {
        let mut index = bucket(&[&sender.0], self.peers.len());
        let probes = self.limits.peer_probes.min(self.peers.len());
        for _ in 0..probes {
            match self.peers[index].value.as_ref() {
                None => return Ok(index),
                Some(p) if p.sender == sender => return Ok(index),
                Some(_) => index = (index + 1) % self.peers.len(),
            }
        }
        Err(if probes == self.peers.len() {
            Reason::PeerCapacity
        } else {
            Reason::ProbeCapacity
        })
    }
    fn nonce_row(&self, encapsulation: [u8; 32], nonce: [u8; 24]) -> Result<usize, Reason> {
        let mut index = bucket(&[&encapsulation, &nonce], self.nonces.len());
        let probes = self.limits.nonce_probes.min(self.nonces.len());
        for _ in 0..probes {
            match self.nonces[index].value.as_ref() {
                None => return Ok(index),
                Some(n) if n.encapsulation == encapsulation && n.nonce == nonce => {
                    return Err(Reason::Duplicate);
                }
                Some(_) => index = (index + 1) % self.nonces.len(),
            }
        }
        Err(if probes == self.nonces.len() {
            Reason::NonceCapacity
        } else {
            Reason::ProbeCapacity
        })
    }
    /// Atomically admit only a real original AEAD+signature result. Every capacity,
    /// source, stamp and duplicate check precedes row mutation. Exact nonce
    /// uniqueness is under fixed local source/target+encapsulation, even if a
    /// sender tries a different stamp/signature/source claim with the same nonce.
    /// Equal sender stamps with distinct nonces remain legal (cached epoch).
    /// No live row expires/evicts on a later packet, key cache TTL or provider job.
    #[expect(
        clippy::result_large_err,
        reason = "Noalloc backpressure must return the original authenticated zeroizing owner; boxing allocates and dropping loses the caller's retained packet"
    )]
    pub fn admit<'out>(
        &mut self,
        opened: Opened<'source, 'id, 'out>,
        now: u64,
    ) -> Result<Admitted<'source, 'id, 'out>, Denied<Opened<'source, 'id, 'out>>> {
        if let Err(error) = self.check(&opened, now) {
            return Err(Denied {
                reason: Reason::Source(error),
                value: opened,
            });
        }
        let source = id(self.source);
        let nonce = match self.nonce_row(opened.encapsulation, opened.nonce) {
            Ok(i) => i,
            Err(reason) => {
                return Err(Denied {
                    reason,
                    value: opened,
                });
            }
        };
        let peer = match self.peer_row(opened.source) {
            Ok(i) => i,
            Err(reason) => {
                return Err(Denied {
                    reason,
                    value: opened,
                });
            }
        };
        if self.peers[peer]
            .value
            .as_ref()
            .is_some_and(|p| opened.stamp < p.highest)
        {
            return Err(Denied {
                reason: Reason::OlderStamp,
                value: opened,
            });
        }
        // No fallible allocation/callback/store follows these two assignments.
        self.nonces[nonce].value = Some(Nonce {
            source,
            sender: opened.source,
            encapsulation: opened.encapsulation,
            stamp: opened.stamp,
            nonce: opened.nonce,
        });
        let highest = self.peers[peer]
            .value
            .as_ref()
            .map_or(opened.stamp, |p| p.highest.max(opened.stamp));
        self.peers[peer].value = Some(Peer {
            source,
            sender: opened.source,
            highest,
        });
        Ok(Admitted { opened })
    }
    /// Clear this original history only AFTER the surrounding owner physically
    /// retires the original source and calls its pure Source::retire signal.
    /// This function does no IO and is not itself proof of a native close.
    /// Failed source clock is irrelevant; active source cannot clear live rows.
    pub fn retire(&mut self) -> Result<Counts, Error> {
        if self.source.active.get() {
            return Err(Error::NotReady);
        }
        let result = clear_retired(self.source, self.peers, self.nonces)?;
        self.retired = true;
        Ok(result)
    }
}
impl Drop for Replay<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.retired {
            self.source.replay_claim.set(LOST)
        } /* Public row history deliberately stays populated. */
    }
}
/// Explicit post-retirement cleanup after a dropped/lost replay owner. The
/// original Source must have been retired; foreign source rows refuse the whole
/// operation before any mutation. No new source/clock/provider is substituted.
pub fn clear_retired(
    source: &Source<'_>,
    peers: &mut [PeerSlot<'_>],
    nonces: &mut [NonceSlot<'_>],
) -> Result<Counts, Error> {
    if source.active.get() {
        return Err(Error::NotReady);
    }
    let original = id(source);
    if peers
        .iter()
        .any(|p| p.value.as_ref().is_some_and(|p| !same(p.source, original)))
        || nonces
            .iter()
            .any(|n| n.value.as_ref().is_some_and(|n| !same(n.source, original)))
    {
        return Err(Error::Stale);
    }
    let counts = Counts {
        peers: peers.iter().filter(|p| p.value.is_some()).count(),
        nonces: nonces.iter().filter(|n| n.value.is_some()).count(),
    };
    for p in peers {
        p.value = None
    }
    for n in nonces {
        n.value = None
    }
    source.replay_claim.set(LOST);
    Ok(counts)
}
/// Private-constructor real live replay admission plus its authenticated,
/// redacted zeroizing plaintext. Not Clone and not a restart/durable receipt.
/// Engine/native/physical write admission remains an independent future step.
pub struct Admitted<'source, 'id, 'out> {
    opened: Opened<'source, 'id, 'out>,
}
impl fmt::Debug for Admitted<'_, '_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveDvAdmitted")
            .field("task", &self.opened.token())
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id, 'out> Admitted<'source, 'id, 'out> {
    /// Original exact crypto/packet task, no new/retagged work.
    pub fn token(&self) -> Token<'id> {
        self.opened.token()
    }
    /// Actual authenticated sender of the admitted packet.
    pub const fn sender(&self) -> PeerId {
        self.opened.source
    }
    /// Original fixed local target.
    pub const fn target(&self) -> PeerId {
        self.opened.target()
    }
    /// Actual authenticated epoch's sender-monotonic stamp.
    pub const fn stamp(&self) -> u64 {
        self.opened.stamp
    }
    /// Actual original encapsulation, never a key/provider/durable receipt.
    pub const fn encapsulation(&self) -> &[u8; 32] {
        &self.opened.encapsulation
    }
    /// Exact nonce recorded for this live source/key context.
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.opened.nonce
    }
    /// Borrow only while original task/source AND replay owner remain live.
    /// Outer owner additionally checks its actual immutable native hard bound.
    pub fn message(&self, now: u64) -> Result<&[u8], Error> {
        if self.opened.task.source.replay_claim.get() != LIVE {
            return Err(Error::Closed);
        }
        self.opened.message(now)
    }
    /// Consume live replay/authentication authority and return the complete
    /// zeroized caller output loan. The replay nonce remains admitted; this is
    /// neither a network FC acknowledgment nor a provider/Engine completion.
    pub fn recycle(self) -> &'out mut [u8] {
        self.opened.recycle()
    }
}
