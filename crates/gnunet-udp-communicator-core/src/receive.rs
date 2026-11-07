//! Bounded authenticated receive windows and an explicit durable replay boundary.
use crate::{
    Identity, PeerId, handshake,
    wire::{Ack, Body, Control},
};
use alloc::{collections::VecDeque, vec::Vec};
use gnunet_session_crypto::{
    Prk, session,
    udp::{BoxView, DatagramKey},
};
use gnunet_types::Error;
use zeroize::Zeroizing;
const INITIAL_KEYS: u32 = 128;
const REFILL_KEYS: u32 = 64;
const LOW_KEYS: usize = 96;
const CACHE: usize = 161;
// Ordinary UDP packets fit this independent finite wire extent. The configured
// BOX rotation threshold is not a packet-size limit; jumbograms are unsupported.
const MAX_PACKET_BYTES: usize = u16::MAX as usize;
/// Maximum additional public KID selectors installed by one authenticated
/// datagram: an initial master plus one leading ordinary rekey. A dispatcher
/// may reserve this many index entries before the irreversible replay commit.
pub const MAX_NEW_KEY_IDS: usize = 256;
/// Native implementation must return success only after a durable strictly-newer
/// timestamp commit in this exact local-identity/remote-peer namespace. It must
/// preserve Storage/OutcomeUnknown/Replay errors and never claim a read/write is
/// durable. Volatile unit implementations are not persistent replay evidence.
pub trait ReplayStore {
    /// Commit the authenticated timestamp, rejecting old/equal values.
    fn commit(&mut self, local: PeerId, peer: PeerId, monotonic: u64) -> Result<(), Error>;
}
/// Explicit bounded receive policy, independent of C's internal maps/tasks.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Maximum overlapping masters for this authenticated peer owner (at least2).
    pub secrets: usize,
    /// Positive BOX-byte retirement threshold per master. Initial KX is not
    /// charged; the authenticated whole BOX reaching it is delivered first.
    pub maximum_secret_bytes: u64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            secrets: 256,
            maximum_secret_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy)]
struct Slot {
    kid: [u8; 32],
    sequence: u32,
    used: bool,
}
impl Slot {
    const EMPTY: Self = Self {
        kid: [0; 32],
        sequence: 0,
        used: false,
    };
}
struct Window {
    master: Prk,
    cmac: [u8; 64],
    allowed: u32,
    keys: Vec<Slot>,
    bytes: u64,
}
struct RekeyPlan {
    window: Option<Window>,
    ack: Option<Ack>,
    protect: Option<usize>,
}
struct Refill {
    slots: [Slot; 64],
    count: usize,
    allowed: u32,
}
impl Window {
    fn new(master: Prk, cmac: [u8; 64]) -> Result<Self, Error> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(CACHE).map_err(|_| Error::Capacity)?;
        for sequence in 1..=INITIAL_KEYS {
            keys.push(Slot {
                kid: session::udp_key_id(&master, sequence)?,
                sequence,
                used: false,
            });
        }
        Ok(Self {
            master,
            cmac,
            allowed: INITIAL_KEYS,
            keys,
            bytes: 0,
        })
    }
    fn plan_refill(&self, consume: usize) -> Result<Option<Refill>, Error> {
        let remaining = self
            .keys
            .iter()
            .filter(|s| !s.used)
            .count()
            .saturating_sub(consume);
        if remaining >= LOW_KEYS || self.allowed == u32::MAX {
            return Ok(None);
        }
        let count = (u32::MAX - self.allowed).min(REFILL_KEYS);
        let allowed = self.allowed + count;
        let mut slots = [Slot::EMPTY; 64];
        for (index, sequence) in (self.allowed + 1..=allowed).enumerate() {
            slots[index] = Slot {
                kid: session::udp_key_id(&self.master, sequence)?,
                sequence,
                used: false,
            };
        }
        Ok(Some(Refill {
            slots,
            count: count as usize,
            allowed,
        }))
    }
    fn refill(&mut self, plan: Refill) {
        let minimum = plan.allowed.saturating_sub(160);
        self.keys.retain(|s| s.sequence >= minimum);
        self.keys.extend_from_slice(&plan.slots[..plan.count]);
        self.allowed = plan.allowed;
    }
    fn ack(&self) -> Ack {
        Ack {
            allowed: self.allowed,
            cmac: self.cmac,
        }
    }
}
/// Authenticated application bytes, erased with all spare capacity on drop.
/// Incoming/outgoing ACKs are distinct and never represent native1210 completion.
pub struct Received {
    message: Option<Zeroizing<Vec<u8>>>,
    /// Optional peer-issued ACK to be applied to the original outgoing master.
    pub incoming_ack: Option<Ack>,
    /// Up to two locally prepared ACKs, only for keys already fully cached here.
    /// Native IPC admission/transmission remains an explicit subsequent effect.
    pub acknowledgements: [Option<Ack>; 2],
}
impl Received {
    /// Exact first application message, excluding control headers and padding.
    #[must_use]
    pub fn message(&self) -> Option<&[u8]> {
        self.message.as_deref().map(Vec::as_slice)
    }
}
fn payload(body: &Body<'_>) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let Some(message) = body.message else {
        return Ok(None);
    };
    let mut b = Vec::new();
    b.try_reserve_exact(message.len())
        .map_err(|_| Error::Capacity)?;
    b.extend_from_slice(message);
    Ok(Some(Zeroizing::new(b)))
}
/// Incoming secrets for one local namespace and authenticated remote peer.
/// KID lookup is peer-bound but not tied to UDP source-address bytes, matching
/// legitimate NAT/backchannel routing. A host still owns every actual endpoint.
pub struct Receiver {
    local: PeerId,
    peer: PeerId,
    policy: Policy,
    windows: VecDeque<Window>,
    closed: bool,
}
impl Receiver {
    /// Reserve the bounded master table. Key caches are allocated/precomputed
    /// before their ACK or any durable replay commit is published.
    pub fn new(local: PeerId, peer: PeerId, policy: Policy) -> Result<Self, Error> {
        if policy.secrets < 2 || policy.maximum_secret_bytes == 0 {
            return Err(Error::InvalidInput);
        }
        policy.secrets.checked_mul(CACHE).ok_or(Error::Capacity)?;
        let mut windows = VecDeque::new();
        windows
            .try_reserve_exact(policy.secrets)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            local,
            peer,
            policy,
            windows,
            closed: false,
        })
    }
    fn check(&self, identity: &Identity) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Stale);
        }
        if self.local != identity.peer() {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// Retained masters; no secret or full key-cache byte exporter exists.
    #[must_use]
    pub fn secrets(&self) -> usize {
        self.windows.len()
    }
    /// Original KIDs not consumed and not pruned from the bounded cache.
    #[must_use]
    pub fn available(&self) -> usize {
        self.windows
            .iter()
            .map(|w| w.keys.iter().filter(|s| !s.used).count())
            .sum()
    }
    /// Borrow public on-wire KID selectors for a bounded dispatch index. Used
    /// entries remain visible until pruning so the original owner can classify
    /// replay. These bytes contain no master, key, nonce or admission authority.
    pub fn key_ids(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.windows
            .iter()
            .flat_map(|window| window.keys.iter().map(|slot| &slot.kid))
    }
    fn contains(&self, cmac: &[u8; 64]) -> Option<usize> {
        self.windows.iter().position(|w| &w.cmac == cmac)
    }
    fn rekey(&self, identity: &Identity, body: &Body<'_>) -> Result<RekeyPlan, Error> {
        let Some(Control::Rekey(header)) = body.control else {
            return Ok(RekeyPlan {
                window: None,
                ack: None,
                protect: None,
            });
        };
        let master = identity.decapsulate_rekey(header.0)?;
        let cmac = session::udp_cmac(&master)?;
        if let Some(index) = self.contains(&cmac) {
            return Ok(RekeyPlan {
                window: None,
                ack: Some(self.windows[index].ack()),
                protect: Some(index),
            });
        }
        let window = Window::new(master, cmac)?;
        let ack = window.ack();
        Ok(RekeyPlan {
            window: Some(window),
            ack: Some(ack),
            protect: None,
        })
    }
    // Victims are chosen while the original table is unchanged, before replay
    // persistence or KID consumption. Removing descending indices never shifts a
    // still-planned index. No allocation/fallible work follows this plan's commit.
    fn victims(&self, adding: usize, protect: Option<usize>) -> Result<[Option<usize>; 2], Error> {
        let remove = self
            .windows
            .len()
            .checked_add(adding)
            .ok_or(Error::Overflow)?
            .saturating_sub(self.policy.secrets);
        if adding > 2 || remove > 2 {
            return Err(Error::Capacity);
        }
        let mut plan = [None; 2];
        let mut at = 0;
        for index in 0..self.windows.len() {
            if Some(index) != protect && at < remove {
                plan[at] = Some(index);
                at += 1;
            }
        }
        if at != remove {
            return Err(Error::Capacity);
        }
        plan.reverse();
        Ok(plan)
    }
    fn remove(&mut self, plan: [Option<usize>; 2]) {
        for index in plan.into_iter().flatten() {
            drop(self.windows.remove(index));
        }
    }
    /// Authenticate a genuine KX, preflight every retained effect/key, then commit
    /// durable replay exactly once before activation or application release.
    /// Rejected storage/unknown outcomes publish no new ACK/payload/key window.
    pub fn initial(
        &mut self,
        identity: &Identity,
        packet: &[u8],
        scratch: &mut [u8],
        replay: &mut impl ReplayStore,
    ) -> Result<Received, Error> {
        self.check(identity)?;
        if packet.len() > MAX_PACKET_BYTES {
            return Err(Error::TooLarge);
        }
        let opened = handshake::open(identity, packet, scratch)?;
        self.admit_initial(identity, opened, replay)
    }
    /// Consume one original fully authenticated initial packet after a bounded
    /// multi-peer dispatcher selected this exact peer. Authentication/KEM is not
    /// repeated, and no replay commit, ACK or application bytes were released by
    /// the Opened guard itself. The guard's immutable transcript binding and
    /// actual packet extent are checked before the one durable replay commit.
    pub fn initial_opened(
        &mut self,
        identity: &Identity,
        opened: handshake::Opened<'_>,
        replay: &mut impl ReplayStore,
    ) -> Result<Received, Error> {
        self.check(identity)?;
        if opened.packet_bytes() > MAX_PACKET_BYTES {
            return Err(Error::TooLarge);
        }
        self.admit_initial(identity, opened, replay)
    }
    fn admit_initial(
        &mut self,
        identity: &Identity,
        opened: handshake::Opened<'_>,
        replay: &mut impl ReplayStore,
    ) -> Result<Received, Error> {
        if opened.receiver() != self.local || opened.sender() != self.peer {
            return Err(Error::Authentication);
        }
        let cmac = *opened.cmac().ok_or(Error::Stale)?;
        if self.contains(&cmac).is_some() {
            return Err(Error::Replay);
        }
        let body = Body::decode(opened.body())?;
        let message = payload(&body)?;
        let incoming_ack = match body.control {
            Some(Control::Ack(ack)) => Some(ack),
            _ => None,
        };
        let RekeyPlan {
            window: rekey,
            ack: rekey_ack,
            protect: rekey_protected,
        } = self.rekey(identity, &body)?;
        if rekey.as_ref().is_some_and(|r| r.cmac == cmac) {
            return Err(Error::Replay);
        }
        let sender = opened.sender();
        let monotonic = opened.monotonic();
        let secret = opened.into_secret()?;
        let window = Window::new(secret.into_master(), cmac)?;
        let ack = window.ack();
        let victims = self.victims(1 + usize::from(rekey.is_some()), rekey_protected)?;
        replay.commit(self.local, sender, monotonic)?;
        self.remove(victims);
        self.windows.push_back(window);
        if let Some(window) = rekey {
            self.windows.push_back(window);
        }
        Ok(Received {
            message,
            incoming_ack,
            acknowledgements: [Some(ack), rekey_ack],
        })
    }
    /// Authenticate an original cached KID before replay/byte/window commit.
    /// Unknown or consumed IDs are explicit; forged tags leave the valid original
    /// KID available. Only exact used plaintext scratch is erased on every path.
    pub fn boxed(
        &mut self,
        identity: &Identity,
        packet: &[u8],
        scratch: &mut [u8],
    ) -> Result<Received, Error> {
        self.check(identity)?;
        if packet.len() > MAX_PACKET_BYTES {
            return Err(Error::TooLarge);
        }
        let view = BoxView::parse(packet)?;
        if scratch.len() < view.ciphertext.len() {
            return Err(Error::Capacity);
        }
        let mut matching = false;
        let mut unused = false;
        let mut selected = None;
        // A public selector is not an authenticator. Try each original unused
        // candidate before rejecting a collision; no candidate is consumed by a
        // bad tag, and a used earlier candidate cannot hide a live later one.
        'windows: for (window_index, window) in self.windows.iter().enumerate() {
            for (slot_index, slot) in window.keys.iter().enumerate() {
                if slot.kid != *view.kid {
                    continue;
                }
                matching = true;
                if slot.used {
                    continue;
                }
                unused = true;
                let key = DatagramKey::derive(&window.master, slot.sequence)?;
                match key.open_box(packet, scratch) {
                    Ok(n) => {
                        selected = Some((window_index, slot_index, n));
                        break 'windows;
                    }
                    Err(Error::Authentication) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        let Some((window, slot, n)) = selected else {
            return Err(if unused {
                Error::Authentication
            } else if matching {
                Error::Replay
            } else {
                Error::NotFound
            });
        };
        // Borrowed scratch is never retained after this closure, even if payload,
        // rekey preflight or subsequent parsing refuses an authenticated packet.
        let prepared = (|| {
            let bytes = self.windows[window]
                .bytes
                .checked_add(packet.len() as u64)
                .ok_or(Error::Overflow)?;
            let retire = bytes >= self.policy.maximum_secret_bytes;
            let body = Body::decode(&scratch[..n])?;
            let message = payload(&body)?;
            let incoming_ack = match body.control {
                Some(Control::Ack(ack)) => Some(ack),
                _ => None,
            };
            let RekeyPlan {
                window: rekey,
                ack: rekey_ack,
                ..
            } = self.rekey(identity, &body)?;
            // A retiring original window itself makes room for at most one
            // newly authenticated rekey. It must not receive fresh KID credit.
            let victims = if retire {
                [None; 2]
            } else {
                self.victims(usize::from(rekey.is_some()), Some(window))?
            };
            let refill = if retire {
                None
            } else {
                self.windows[window].plan_refill(1)?
            };
            let rekey_ack =
                rekey_ack.filter(|ack| !retire || ack.cmac != self.windows[window].cmac);
            Ok::<_, Error>((
                message,
                incoming_ack,
                rekey,
                rekey_ack,
                victims,
                refill,
                bytes,
                retire,
            ))
        })();
        use zeroize::Zeroize as _;
        scratch[..n].zeroize();
        let (message, incoming_ack, rekey, rekey_ack, victims, refill, bytes, retire) = prepared?;
        self.windows[window].keys[slot].used = true;
        self.windows[window].bytes = bytes;
        let mut ack = None;
        if let Some(refill) = refill {
            self.windows[window].refill(refill);
            ack = Some(self.windows[window].ack());
        }
        if retire {
            drop(self.windows.remove(window));
        } else {
            self.remove(victims);
        }
        if let Some(window) = rekey {
            self.windows.push_back(window);
        }
        Ok(Received {
            message,
            incoming_ack,
            acknowledgements: [ack, rekey_ack],
        })
    }
    /// Retire this namespace/peer generation and erase all masters immediately.
    pub fn close(&mut self) {
        self.closed = true;
        self.windows.clear();
    }
}
