//! Allocation-free R5N peer filtering and routing decisions.
//!
//! Peer filters use the official 128-byte, 16-position peer-key Bloom scheme,
//! independently of BLOCK result groups. Candidate admission/authentication is
//! the underlay owner's responsibility; this planner cannot create a session.
use core::cmp::Ordering;
use gnunet_crypto::{Entropy, hash512};
use gnunet_types::Error;

/// Maximum desired replication/outdegree in the official R5N profile.
pub const MAX_REPLICATION: usize = 16;
/// Official peer Bloom filter, including its false-positive semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerBloom([u8; 128]);
impl PeerBloom {
    /// Start an empty visited-peer filter.
    #[must_use]
    pub const fn empty() -> Self {
        Self([0; 128])
    }
    /// Retain the exact untrusted filter bytes, without treating a match as proof.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 128]) -> Self {
        Self(bytes)
    }
    /// Official serialized bits.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 128] {
        &self.0
    }
    /// Insert SHA512(public identity), using sixteen big-endian uint32 positions.
    pub fn insert_key(&mut self, key: &[u8; 64]) {
        for word in key.as_chunks::<4>().0 {
            let bit = (u32::from_be_bytes(*word) % 1024) as usize;
            self.0[bit / 8] |= 1 << (bit % 8);
        }
    }
    /// A possible membership match, never an identity/authentication decision.
    #[must_use]
    pub fn contains_key(&self, key: &[u8; 64]) -> bool {
        key.as_chunks::<4>().0.iter().all(|word| {
            let bit = (u32::from_be_bytes(*word) % 1024) as usize;
            self.0[bit / 8] & (1 << (bit % 8)) != 0
        })
    }
}
impl Default for PeerBloom {
    fn default() -> Self {
        Self::empty()
    }
}
/// Official routing key is SHA512 over exactly the 32 public identity bytes.
#[must_use]
pub fn peer_key(identity: &[u8; 32]) -> [u8; 64] {
    hash512(identity)
}
/// Compare XOR distances as unsigned 512-bit big-endian integers.
#[must_use]
pub fn distance_cmp(a: &[u8; 64], b: &[u8; 64], target: &[u8; 64]) -> Ordering {
    a.iter()
        .zip(b)
        .zip(target)
        .map(|((&a, &b), &t)| (a ^ t).cmp(&(b ^ t)))
        .find(|x| *x != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}
/// First differing bit, counted from the most significant bit; equal keys yield None.
#[must_use]
pub fn bucket(local: &[u8; 64], peer: &[u8; 64]) -> Option<usize> {
    local
        .iter()
        .zip(peer)
        .enumerate()
        .find_map(|(i, (&a, &b))| {
            let x = a ^ b;
            (x != 0).then(|| i * 8 + x.leading_zeros() as usize)
        })
}
/// Validated finite log2 network-size estimate, with reference bootstrap minimum.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Estimate(f64);
impl Estimate {
    /// Reject non-finite external estimates; finite small values clamp to 0.5.
    pub fn new(log2: f64) -> Result<Self, Error> {
        if !log2.is_finite() {
            return Err(Error::InvalidInput);
        }
        Ok(Self(log2.max(0.5)))
    }
    /// Current clamped logarithm.
    #[must_use]
    pub const fn log2(self) -> f64 {
        self.0
    }
    /// Whether this hop is still in the random-walk phase.
    #[must_use]
    pub fn random_walk(self, hop: u16) -> bool {
        f64::from(hop) < self.0
    }
    /// R5N probabilistic outdegree for one uniform 32-bit draw.
    /// Replication zero means one; replication is capped at sixteen. The exact
    /// documented real-valued expression is used rather than a private TTL.
    #[must_use]
    pub fn fanout(self, hop: u16, replication: u16, draw: u32) -> usize {
        let hop = f64::from(hop);
        if hop > self.0 * 4.0 {
            return 0;
        }
        if hop > self.0 * 2.0 {
            return 1;
        }
        let r = f64::from(replication.clamp(1, MAX_REPLICATION as u16) - 1);
        let target = 1.0 + r / (self.0 + r * hop);
        let whole = target as usize;
        let fractional = target - whole as f64;
        let extra = f64::from(draw) / 4_294_967_296.0 < fractional;
        (whole + usize::from(extra)).min(MAX_REPLICATION)
    }
}
/// One already admitted peer candidate. `origin` remains the caller's original
/// underlay/session capability; identity bytes do not reconstruct that authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate<T> {
    /// Original authenticated/explicitly profiled session token.
    pub origin: T,
    /// Public peer identity.
    pub identity: [u8; 32],
}
/// Atomic routing plan; failure exposes no partially updated external Bloom filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan<T: Copy> {
    selected: [Option<T>; MAX_REPLICATION],
    bloom: PeerBloom,
    len: usize,
}
impl<T: Copy> Plan<T> {
    /// Selected distinct original sessions, in forwarding order.
    pub fn selected(&self) -> impl Iterator<Item = T> + '_ {
        self.selected[..self.len].iter().flatten().copied()
    }
    /// Filter after inserting local identity and all selected destinations.
    #[must_use]
    pub const fn bloom(&self) -> &PeerBloom {
        &self.bloom
    }
}
/// Construct one bounded plan. At most `bucket_size` original candidates from
/// each of the 512 buckets are eligible. Source fallback is eight; the shipped
/// normal configuration explicitly selects four. The caller supplies this policy.
/// Entropy refusal leaves all caller-owned candidates/filter untouched.
#[expect(
    clippy::too_many_arguments,
    reason = "The original candidate slice, filter, routing policy and entropy port are independent caller-owned inputs."
)]
pub fn plan<T: Copy>(
    local: &[u8; 32],
    target: &[u8; 64],
    candidates: &[Candidate<T>],
    visited: PeerBloom,
    estimate: Estimate,
    hop: u16,
    replication: u16,
    bucket_size: usize,
    entropy: &mut impl Entropy,
) -> Result<Plan<T>, Error> {
    let local_key = peer_key(local);
    let mut result = Plan {
        selected: [None; MAX_REPLICATION],
        bloom: visited,
        len: 0,
    };
    result.bloom.insert_key(&local_key);
    let draw = if f64::from(hop) > estimate.0 * 2.0 || replication <= 1 {
        0
    } else {
        random(entropy)? as u32
    };
    let count = estimate.fanout(hop, replication, draw);
    for _ in 0..count {
        let mut counts = [0usize; 512];
        let mut chosen: Option<(T, [u8; 64])> = None;
        let mut eligible = 0u64;
        for candidate in candidates {
            let key = peer_key(&candidate.identity);
            let Some(index) = bucket(&local_key, &key) else {
                continue;
            };
            let position = counts[index];
            counts[index] = position.saturating_add(1);
            if position >= bucket_size || result.bloom.contains_key(&key) {
                continue;
            }
            if estimate.random_walk(hop) {
                eligible = eligible.checked_add(1).ok_or(Error::Overflow)?;
                if uniform(entropy, eligible)? == 0 {
                    chosen = Some((candidate.origin, key));
                }
            } else if chosen
                .as_ref()
                .is_none_or(|(_, old)| distance_cmp(&key, old, target) == Ordering::Less)
            {
                chosen = Some((candidate.origin, key));
            }
        }
        let Some((origin, key)) = chosen else {
            break;
        };
        result.selected[result.len] = Some(origin);
        result.len += 1;
        result.bloom.insert_key(&key);
    }
    Ok(result)
}
/// Whether local is no farther than every eligible unfiltered candidate.
#[must_use]
pub fn am_closest<T>(
    local: &[u8; 32],
    target: &[u8; 64],
    candidates: &[Candidate<T>],
    visited: Option<&PeerBloom>,
    bucket_size: usize,
) -> bool {
    let local = peer_key(local);
    let mut counts = [0usize; 512];
    for peer in candidates {
        let key = peer_key(&peer.identity);
        let Some(index) = bucket(&local, &key) else {
            continue;
        };
        let position = counts[index];
        counts[index] = position.saturating_add(1);
        if position < bucket_size
            && !visited.is_some_and(|b| b.contains_key(&key))
            && distance_cmp(&key, &local, target) == Ordering::Less
        {
            return false;
        }
    }
    true
}
fn random(entropy: &mut impl Entropy) -> Result<u64, Error> {
    let mut bytes = [0; 8];
    entropy.fill(&mut bytes).map_err(|_| Error::Entropy)?;
    Ok(u64::from_be_bytes(bytes))
}
fn uniform(entropy: &mut impl Entropy, bound: u64) -> Result<u64, Error> {
    // Rejection sampling avoids modulo bias. Bound is positive candidate count.
    if bound == 1 {
        return Ok(0);
    }
    let threshold = bound.wrapping_neg() % bound;
    for _ in 0..64 {
        let value = random(entropy)?;
        if value >= threshold {
            return Ok(value % bound);
        }
    }
    Err(Error::Entropy)
}
