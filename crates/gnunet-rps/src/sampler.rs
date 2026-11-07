use crate::Peer;
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_types::Error;
use zeroize::Zeroize;

/// Fresh cryptographic randomness supplied by the actual host.
pub trait Random {
    /// Fill all bytes, or return the original entropy failure.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error>;
}
/// Independent keyed min-wise ranking; the required algorithm is HMAC-SHA512.
pub trait Rank {
    /// Return HMAC-SHA512(key, peer). A failure grants no sampler update.
    fn rank(&mut self, key: &[u8; 64], peer: &Peer) -> Result<[u8; 64], Error>;
}

pub(crate) fn reserve<T>(values: &mut Vec<T>, additional: usize) -> Result<(), Error> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| Error::Capacity)
}
pub(crate) fn copied<T: Copy>(values: &[T]) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    reserve(&mut out, values.len())?;
    out.extend_from_slice(values);
    Ok(out)
}
pub(crate) fn bytes<T>(values: &Vec<T>) -> Result<usize, Error> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Overflow)
}
pub(crate) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
pub(crate) fn uniform(random: &mut impl Random, bound: usize) -> Result<usize, Error> {
    usize::try_from(uniform_u64(
        random,
        u64::try_from(bound).map_err(|_| Error::Overflow)?,
    )?)
    .map_err(|_| Error::Overflow)
}
pub(crate) fn uniform_u64(random: &mut impl Random, bound: u64) -> Result<u64, Error> {
    if bound == 0 {
        return Err(Error::InvalidInput);
    }
    let threshold = bound.wrapping_neg() % bound;
    for _ in 0..128 {
        let mut raw = [0; 8];
        random.fill(&mut raw)?;
        let value = u64::from_le_bytes(raw);
        if value >= threshold {
            return Ok(value % bound);
        }
    }
    Err(Error::Entropy)
}
pub(crate) fn shuffled(peers: &[Peer], random: &mut impl Random) -> Result<Vec<Peer>, Error> {
    let mut out = copied(peers)?;
    shuffle(&mut out, random)?;
    Ok(out)
}

pub(crate) fn shuffle(peers: &mut [Peer], random: &mut impl Random) -> Result<(), Error> {
    for upper in (2..=peers.len()).rev() {
        let selected = uniform(random, upper)?;
        peers.swap(upper - 1, selected);
    }
    Ok(())
}

struct Element {
    key: [u8; 64],
    winner: Option<Peer>,
    rank: [u8; 64],
    observed: u64,
}
impl Drop for Element {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl Element {
    fn new(random: &mut impl Random) -> Result<Self, Error> {
        let mut key = [0; 64];
        if let Err(error) = random.fill(&mut key) {
            key.zeroize();
            return Err(error);
        }
        Ok(Self {
            key,
            winner: None,
            rank: [0; 64],
            observed: 0,
        })
    }
    fn copy(&self) -> Self {
        Self {
            key: self.key,
            winner: self.winner,
            rank: self.rank,
            observed: self.observed,
        }
    }
}

/// Bounded independent min-wise HMAC samplers used by Brahms history.
///
/// Canonical byte ordering of the uniformly distributed HMAC output is an
/// internal ordering choice. It does not change any peer wire format.
pub struct Sampler {
    slots: Vec<Element>,
    scratch: Vec<[u8; 64]>,
}
impl Sampler {
    /// Maximum permitted slot count for an individual allocation.
    pub const MAX_SLOTS: usize = 65_536;
    pub(crate) fn minimum_bytes(count: usize) -> Result<usize, Error> {
        count
            .checked_mul(size_of::<Element>() + size_of::<[u8; 64]>())
            .ok_or(Error::Overflow)
    }
    /// Create independent empty slots; allocation and entropy are fallible.
    pub fn new(count: usize, random: &mut impl Random) -> Result<Self, Error> {
        if count == 0 || count > Self::MAX_SLOTS {
            return Err(Error::InvalidInput);
        }
        let mut slots = Vec::new();
        let mut scratch = Vec::new();
        reserve(&mut slots, count)?;
        reserve(&mut scratch, count)?;
        for _ in 0..count {
            slots.push(Element::new(random)?);
            scratch.push([0; 64]);
        }
        Ok(Self { slots, scratch })
    }
    pub(crate) fn copy(&self) -> Result<Self, Error> {
        let mut slots = Vec::new();
        reserve(&mut slots, self.slots.len())?;
        for slot in &self.slots {
            slots.push(slot.copy());
        }
        Ok(Self {
            slots,
            scratch: copied(&self.scratch)?,
        })
    }
    /// Actual allocated bytes, excluding the inline owner.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        add(bytes(&self.slots)?, bytes(&self.scratch)?)
    }
    /// Number of independent history elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }
    /// This sampler always has at least one element.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
    /// Observe one peer atomically across all elements.
    pub fn observe(&mut self, peer: Peer, rank: &mut impl Rank) -> Result<(), Error> {
        for (slot, proposal) in self.slots.iter().zip(&mut self.scratch) {
            slot.observed.checked_add(1).ok_or(Error::Overflow)?;
            *proposal = if slot.winner == Some(peer) {
                slot.rank
            } else {
                rank.rank(&slot.key, &peer)?
            };
        }
        for (slot, proposal) in self.slots.iter_mut().zip(&self.scratch) {
            if slot.winner.is_none() || *proposal < slot.rank {
                slot.winner = Some(peer);
                slot.rank = *proposal;
            }
            slot.observed += 1;
        }
        Ok(())
    }
    /// Select a uniformly random element; an empty element supplies no peer.
    pub fn sample(&self, random: &mut impl Random) -> Result<Option<Peer>, Error> {
        Ok(self.slots[uniform(random, self.slots.len())?].winner)
    }
    /// Resize while preserving existing elements; new elements get fresh keys.
    pub fn resize(&mut self, count: usize, random: &mut impl Random) -> Result<(), Error> {
        if count == 0 || count > Self::MAX_SLOTS {
            return Err(Error::InvalidInput);
        }
        if count <= self.slots.len() {
            self.slots.truncate(count);
            self.scratch.truncate(count);
            return Ok(());
        }
        let extra = count - self.slots.len();
        let mut added = Vec::new();
        reserve(&mut added, extra)?;
        for _ in 0..extra {
            added.push(Element::new(random)?);
        }
        reserve(&mut self.slots, extra)?;
        reserve(&mut self.scratch, extra)?;
        self.slots.extend(added);
        self.scratch.resize(count, [0; 64]);
        Ok(())
    }
}

/// Actual client result metadata, not an authenticated confidence certificate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SampleInfo {
    /// Selected public peer identity.
    pub peer: Peer,
    /// Upstream currently reports zero; no statistical confidence is invented.
    pub probability: f64,
    /// Number of biased-stream observations made by this independent element.
    pub observed: u64,
}

/// One original client request's independent stream-fed sampling operation.
///
/// The native owner retains the request ID, deadline and cancellation. It must
/// drop an incomplete sampler on terminal source loss rather than fabricate a
/// reply. Distinct slots can select the same peer, as in the public C API.
pub struct ClientSampler {
    sampler: Option<Sampler>,
    consumed: Vec<bool>,
    remaining: usize,
    cursor: usize,
    last_now: u64,
}
impl ClientSampler {
    /// Allocate only the actual request count. Zero is an immediate empty result.
    pub fn new(count: usize, now: u64, random: &mut impl Random) -> Result<Self, Error> {
        if count > Sampler::MAX_SLOTS {
            return Err(Error::TooLarge);
        }
        let mut consumed = Vec::new();
        reserve(&mut consumed, count)?;
        consumed.resize(count, false);
        Ok(Self {
            sampler: if count == 0 {
                None
            } else {
                Some(Sampler::new(count, random)?)
            },
            consumed,
            remaining: count,
            cursor: 0,
            last_now: now,
        })
    }
    /// Retained allocation extent of this original request.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        add(
            bytes(&self.consumed)?,
            self.sampler
                .as_ref()
                .map_or(Ok(0), Sampler::retained_bytes)?,
        )
    }
    /// Observe the original biased stream. Each peer is an atomic observation.
    pub fn observe(&mut self, peers: &[Peer], rank: &mut impl Rank) -> Result<(), Error> {
        if self.remaining == 0 {
            return Ok(());
        }
        if let Some(sampler) = &mut self.sampler {
            for peer in peers {
                sampler.observe(*peer, rank)?;
            }
        }
        Ok(())
    }
    /// Return one eligible element once; fewer than two observations waits.
    pub fn next(
        &mut self,
        now: u64,
        random: &mut impl Random,
    ) -> Result<Option<SampleInfo>, Error> {
        if now < self.last_now {
            return Err(Error::TimeUncertain);
        }
        let Some(sampler) = &mut self.sampler else {
            self.last_now = now;
            return Ok(None);
        };
        for offset in 0..self.consumed.len() {
            let index = (self.cursor + offset) % self.consumed.len();
            if self.consumed[index] {
                continue;
            }
            let slot = &sampler.slots[index];
            if slot.observed < 2 {
                continue;
            }
            let Some(peer) = slot.winner else {
                continue;
            };
            let result = SampleInfo {
                peer,
                probability: 0.0,
                observed: slot.observed,
            };
            let fresh = Element::new(random)?;
            sampler.slots[index] = fresh;
            self.consumed[index] = true;
            self.remaining -= 1;
            self.cursor = (index + 1) % self.consumed.len();
            self.last_now = now;
            return Ok(Some(result));
        }
        self.last_now = now;
        Ok(None)
    }
    /// Number of results still owed to this exact original request.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }
}
