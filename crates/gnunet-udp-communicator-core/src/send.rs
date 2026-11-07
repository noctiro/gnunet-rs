//! Bounded outgoing secret/sequence owner; native transmission is a separate effect.
use crate::{
    Identity, PeerId, handshake,
    wire::{self, Ack, Rekey},
};
use alloc::{collections::VecDeque, vec::Vec};
use core::num::NonZeroUsize;
use gnunet_crypto::Entropy;
use gnunet_session_crypto::{
    Prk,
    exchange::{self, EcdhePublic},
    session,
    udp::DatagramKey,
};
use gnunet_types::Error;
use gnunet_wire::official::Frame;
use zeroize::Zeroizing;
/// Explicit local storage/rotation choices, not negotiated private wire fields.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Ordinary UDP payload size, including the48-byte prefix.
    pub datagram_bytes: usize,
    /// Maximum concurrent outgoing masters for this peer/address owner.
    pub secrets: usize,
    /// Positive BOX-byte rotation threshold per master. Initial KX is not
    /// charged; one admitted whole BOX may reach or cross this threshold.
    pub maximum_secret_bytes: u64,
    /// Begin an authenticated ordinary-KEM rekey at this byte count.
    pub rekey_after_bytes: u64,
    /// Begin rekey at this finite elapsed time; MAX disables the time trigger.
    pub rekey_after_us: u64,
    /// Matched ACK liveness timeout; outgoing activity never extends it.
    pub acknowledgement_timeout_us: u64,
    /// Explicit Elligator rejection-loop budget.
    pub kem_attempts: NonZeroUsize,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            datagram_bytes: 1452,
            secrets: 256,
            maximum_secret_bytes: 4 * 1024 * 1024 * 1024,
            rekey_after_bytes: 28 * 1024 * 1024 * 1024 / 10,
            rekey_after_us: 24 * 60 * 60 * 1_000_000,
            acknowledgement_timeout_us: 5 * 60 * 1_000_000,
            kem_attempts: NonZeroUsize::new(128).unwrap_or(NonZeroUsize::MIN),
        }
    }
}
/// Datagram mode is public observation, not a remote-delivery receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Fresh initial Elligator exchange with a signed confirmation.
    Initial,
    /// One previously ACKed master/sequence, optionally carrying a rekey.
    Box {
        /// Consumed original master sequence.
        sequence: u32,
        /// Whether an ordinary rekey header precedes the application payload.
        rekey: bool,
    },
}
/// Immutable admitted bytes. Dropping before native send burns its BOX sequence;
/// it cannot silently regenerate a different plaintext with the same nonce.
/// There is no Clone, mutable view or secret Debug representation.
pub struct Datagram {
    bytes: Zeroizing<Vec<u8>>,
    operation: u64,
    mode: Mode,
}
impl Datagram {
    /// Exact original bytes for atomic native UDP send; never send a suffix.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Diagnostic serial only; not a queue/MID, ACK or native-write authority.
    #[must_use]
    pub const fn operation(&self) -> u64 {
        self.operation
    }
    /// Public initial/BOX mode and consumed sequence.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }
}
struct Secret {
    master: Prk,
    cmac: [u8; 64],
    used: u32,
    allowed: u32,
    bytes: u64,
    created: u64,
    rekeyed: bool,
}
/// Observable result of one authenticated-peer ACK, independent of native1210.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Grant {
    /// The marker is absent from this original peer/address owner.
    Unknown,
    /// Matched but duplicate/lower ACK; it creates no additional credit.
    Unchanged,
    /// Exact additional finite queue grant offered to the native IPC owner.
    Increased {
        /// Exact positive increase in this original master limit.
        delta: u32,
        /// Sum of unconsumed offered sequences, separate from byte policy.
        available: u64,
    },
}
/// Outgoing peer/address key owner. No socket, timer, callback or hidden RNG.
pub struct Sender {
    local: PeerId,
    peer: PeerId,
    policy: Policy,
    secrets: VecDeque<Secret>,
    last_clock: u64,
    last_ack: u64,
    last_initial: Option<u64>,
    operation: u64,
    closed: bool,
}
fn storage(n: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut b = Vec::new();
    b.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    b.resize(n, 0);
    Ok(Zeroizing::new(b))
}
fn padded(
    message: &[u8],
    rekey: Option<Rekey>,
    size: usize,
    entropy: &mut impl Entropy,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let extra = usize::from(rekey.is_some()) * 36;
    let needed = message.len().checked_add(extra).ok_or(Error::Overflow)?;
    if needed > size {
        return Err(Error::TooLarge);
    }
    let mut b = storage(size)?;
    let at = if let Some(rekey) = rekey {
        rekey.encode(&mut b)?
    } else {
        0
    };
    b[at..needed].copy_from_slice(message);
    entropy.fill(&mut b[needed..])?;
    if size - needed > 4 {
        b[needed..needed + 2].copy_from_slice(
            &u16::try_from(size - needed)
                .map_err(|_| Error::TooLarge)?
                .to_be_bytes(),
        );
        b[needed + 2..needed + 4].copy_from_slice(&wire::PAD.to_be_bytes());
    }
    Ok(b)
}
impl Sender {
    /// Reserve all secret-table metadata; constructor has no key/queue effects.
    pub fn new(local: PeerId, peer: PeerId, policy: Policy, now: u64) -> Result<Self, Error> {
        if policy.secrets < 2
            || !(156..=65471).contains(&policy.datagram_bytes)
            || policy.maximum_secret_bytes == 0
            || policy.rekey_after_bytes >= policy.maximum_secret_bytes
            || policy.acknowledgement_timeout_us == 0
        {
            return Err(Error::InvalidInput);
        }
        u64::try_from(policy.secrets)
            .ok()
            .and_then(|count| count.checked_mul(u64::from(u32::MAX)))
            .ok_or(Error::Capacity)?;
        EcdhePublic::from_edwards(&peer)?;
        let mut secrets = VecDeque::new();
        secrets
            .try_reserve_exact(policy.secrets)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            local,
            peer,
            policy,
            secrets,
            last_clock: now,
            last_ack: now,
            last_initial: None,
            operation: 0,
            closed: false,
        })
    }
    fn check(&self, identity: &Identity, now: u64) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Stale);
        }
        if identity.peer() != self.local {
            return Err(Error::Authentication);
        }
        if now < self.last_clock {
            return Err(Error::TimeUncertain);
        }
        let deadline = self
            .last_ack
            .saturating_add(self.policy.acknowledgement_timeout_us);
        if deadline != u64::MAX && now >= deadline {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    /// Original endpoint identity; a native address/QID remains a separate owner.
    #[must_use]
    pub const fn peer(&self) -> PeerId {
        self.peer
    }
    /// Unconsumed peer-offered BOX sequences, not byte-budget, native queue or
    /// delivery authority. A master can exhaust its byte policy before this count.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.secrets
            .iter()
            .map(|s| u64::from(s.allowed - s.used))
            .sum()
    }
    /// Current secret-table entries; no keys or CMAC enumeration is exported.
    #[must_use]
    pub fn secrets(&self) -> usize {
        self.secrets.len()
    }
    /// KX queue's payload MTU, before signature confirmation/prefix and padding.
    #[must_use]
    pub fn initial_mtu(&self) -> usize {
        self.policy.datagram_bytes - wire::PREFIX - wire::CONFIRMATION
    }
    /// BOX queue's payload MTU, before its optional internally injected rekey.
    #[must_use]
    pub fn boxed_mtu(&self) -> usize {
        self.policy.datagram_bytes - wire::PREFIX
    }
    /// Offer an actual peer-bound ACK. Only an increased original secret limit
    /// supplies a finite q_len delta; duplicates refresh liveness but add none.
    pub fn acknowledge(&mut self, peer: PeerId, ack: Ack, now: u64) -> Result<Grant, Error> {
        if self.closed {
            return Err(Error::Stale);
        }
        if now < self.last_clock {
            return Err(Error::TimeUncertain);
        }
        if peer != self.peer {
            return Err(Error::Authentication);
        }
        let Some(index) = self.secrets.iter().position(|s| s.cmac == ack.cmac) else {
            self.last_clock = now;
            return Ok(Grant::Unknown);
        };
        self.last_ack = now;
        self.last_clock = now;
        if ack.allowed <= self.secrets[index].allowed {
            return Ok(Grant::Unchanged);
        }
        let delta = ack.allowed - self.secrets[index].allowed;
        self.secrets[index].allowed = ack.allowed;
        Ok(Grant::Increased {
            delta,
            available: self.available(),
        })
    }
    /// Prepare a fresh immutable initial packet. Native admission/completion is
    /// not inferred. Monotonic input must come from the native durable issuer;
    /// this local check cannot protect a restarted process by itself.
    pub fn initial(
        &mut self,
        identity: &Identity,
        message: &[u8],
        monotonic: u64,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Datagram, Error> {
        self.check(identity, now)?;
        Frame::decode(message)?;
        if message.len() > self.initial_mtu() {
            return Err(Error::TooLarge);
        }
        if self.last_initial.is_some_and(|last| monotonic <= last) {
            return Err(Error::Replay);
        }
        let operation = self.operation.checked_add(1).ok_or(Error::Overflow)?;
        let mut bytes = storage(self.policy.datagram_bytes)?;
        let plain = padded(message, None, self.initial_mtu(), entropy)?;
        let (_, secret) = handshake::seal(
            identity,
            self.peer,
            monotonic,
            &plain,
            &mut bytes,
            entropy,
            self.policy.kem_attempts,
        )?;
        if self.secrets.iter().any(|s| s.cmac == secret.cmac) {
            return Err(Error::Entropy);
        }
        let cmac = secret.cmac;
        let s = Secret {
            master: secret.into_master(),
            cmac,
            used: 0,
            allowed: 0,
            bytes: 0,
            created: now,
            rekeyed: false,
        };
        if self.secrets.len() == self.policy.secrets {
            drop(self.secrets.pop_front());
        }
        self.secrets.push_back(s);
        self.last_initial = Some(monotonic);
        self.last_clock = now;
        self.operation = operation;
        Ok(Datagram {
            bytes,
            operation,
            mode: Mode::Initial,
        })
    }
    /// Prepare one BOX using exactly one offered sequence. All fallible staging
    /// precedes the state commit. Cancellation after success burns the sequence;
    /// local send callbacks never replenish it. No usable key yields NotReady,
    /// so the native owner can choose the actual KX queue/failure policy.
    pub fn boxed(
        &mut self,
        identity: &Identity,
        message: &[u8],
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Datagram, Error> {
        self.check(identity, now)?;
        Frame::decode(message)?;
        if message.len() > self.boxed_mtu() {
            return Err(Error::TooLarge);
        }
        let needs_rekey = |s: &Secret| {
            let time = s.created.saturating_add(self.policy.rekey_after_us);
            !s.rekeyed
                && (s.bytes >= self.policy.rekey_after_bytes || (time != u64::MAX && now >= time))
        };
        // A fresh authenticated ACK proves the peer currently holds that
        // master. Prefer the newest usable one: after a peer restart, older
        // offered credit can survive here while its volatile receive keys do
        // not. Selection does not revoke old grants, mutate sealed datagrams or
        // reuse a nonce; original in-flight packets keep their original keys.
        let Some(index) = self.secrets.iter().rposition(|s| {
            let size = self.policy.datagram_bytes + usize::from(needs_rekey(s)) * 36;
            s.used < s.allowed
                && s.bytes < self.policy.maximum_secret_bytes
                && s.bytes.checked_add(size as u64).is_some()
        }) else {
            return Err(Error::NotReady);
        };
        let old = &self.secrets[index];
        let rekey = needs_rekey(old);
        let size = self.policy.datagram_bytes + usize::from(rekey) * 36;
        let next_bytes = old.bytes.checked_add(size as u64).ok_or(Error::Overflow)?;
        let sequence = old.used.checked_add(1).ok_or(Error::Overflow)?;
        let operation = self.operation.checked_add(1).ok_or(Error::Overflow)?;
        let mut next = None;
        let header = if rekey {
            let (enc, master) =
                exchange::kem_encapsulate_random(EcdhePublic::from_edwards(&self.peer)?, entropy)?;
            let cmac = session::udp_cmac(&master)?;
            if self.secrets.iter().any(|s| s.cmac == cmac) {
                return Err(Error::Entropy);
            }
            next = Some(Secret {
                master,
                cmac,
                used: 0,
                allowed: 0,
                bytes: 0,
                created: now,
                rekeyed: false,
            });
            Some(Rekey(*enc.as_bytes()))
        } else {
            None
        };
        let plain = padded(message, header, size - wire::PREFIX, entropy)?;
        let mut bytes = storage(size)?;
        DatagramKey::derive(&old.master, sequence)?.seal_box(&plain, &mut bytes)?;
        self.secrets[index].used = sequence;
        self.secrets[index].bytes = next_bytes;
        self.secrets[index].rekeyed |= rekey;
        if let Some(next) = next {
            if self.secrets.len() == self.policy.secrets {
                // At least two slots exist, so one other master is evictable.
                let victim = if index == 0 { 1 } else { 0 };
                drop(self.secrets.remove(victim));
            }
            self.secrets.push_back(next);
        }
        self.last_clock = now;
        self.operation = operation;
        Ok(Datagram {
            bytes,
            operation,
            mode: Mode::Box { sequence, rekey },
        })
    }
    /// Retire this generation and erase every master. A new owner must be built
    /// explicitly; old ACKs cannot reactivate this closed owner.
    pub fn close(&mut self) {
        self.closed = true;
        self.secrets.clear();
    }
}
