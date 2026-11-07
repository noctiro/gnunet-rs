//! Caller-storage bounded reuse of actual certified DV material. No cache hit
//! renews an expiry, replaces an original source, proves replay admission or
//! completes provider/IO debt. Material-use leases and packet deadlines remain
//! independent; both must be live during actual crypto. Every packet still has
//! real AEAD authentication, and authenticated output keeps its packet deadline.
use super::*;
fn source_eq(a: &Source<'_>, b: &Source<'_>) -> bool {
    core::ptr::eq(a.instance, b.instance) && a.allocation == b.allocation
}
fn check_packet_use(material: &Task<'_, '_>, packet: &Task<'_, '_>, now: u64) -> Result<(), Error> {
    material.check(now)?;
    packet.check(now)?;
    if !source_eq(packet.source, material.source) {
        return Err(Error::Stale);
    }
    Ok(())
}
/// Original immutable per-packet input. Borrowed bytes/route are never cloned.
pub struct Packet<'a> {
    /// Route excludes source/direct recipient and includes target.
    pub route: &'a [PeerId],
    /// Original flow-control flag.
    pub without_fc: bool,
    /// One complete non-nested inner GNUnet frame.
    pub message: &'a [u8],
}
fn layout(
    local: PeerId,
    target: PeerId,
    packet: &Packet<'_>,
    work: usize,
    out: usize,
) -> Result<(usize, usize), Error> {
    let inner = Frame::decode(packet.message)?;
    if matches!(
        inner.header().message_type().value(),
        dv::LEARN_TYPE | dv::BOX_TYPE
    ) {
        return Err(Error::Malformed);
    }
    if packet.route.len() > dv::MAX_HOPS
        || (!packet.route.is_empty() && packet.route.last() != Some(&target))
    {
        return Err(Error::InvalidInput);
    }
    for (i, p) in packet.route.iter().enumerate() {
        if *p == local || packet.route[..i].contains(p) {
            return Err(Error::InvalidInput);
        }
    }
    let plain = dv::PAYLOAD_PREFIX
        .checked_add(packet.message.len())
        .ok_or(Error::Overflow)?;
    let size = dv::BOX_PREFIX
        .checked_add(packet.route.len() * 32)
        .and_then(|n| n.checked_add(plain))
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or(Error::TooLarge)?;
    if work < plain || out < size {
        return Err(Error::Capacity);
    }
    Ok((plain, size))
}
/// One original actual certified ephemeral epoch. Key and signature are retained
/// once, target/source/expiry stay fixed, and each seal burns a unique nonce.
/// No Clone, raw key view or serialization is provided.
pub struct SendMaterial<'source, 'id> {
    original: Task<'source, 'id>,
    target: PeerId,
    encapsulation: [u8; 32],
    signature: EddsaSignature,
    key: Zeroizing<[u8; 32]>,
    prefix: [u8; 16],
    next: Option<u64>,
    remaining: u64,
    certified_at: u64,
}
impl fmt::Debug for SendMaterial<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvSendMaterial")
            .field("epoch", &self.original.token())
            .field("remaining", &self.remaining)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id> PreparedSeal<'source, 'id> {
    /// Original material-task expiry, before any external provider admission.
    pub const fn until(&self) -> u64 {
        self.task.until
    }
    /// Independently verify the actual original purpose30 result once, then
    /// retain this original key/stamp/signature epoch for bounded packet reuse.
    /// `messages` is a nonzero finite caller budget, at most2^32−1. No new
    /// entropy, longer deadline or native/provider success is invented here.
    pub fn certify(
        self,
        signature: &EddsaSignature,
        now: u64,
        messages: u32,
    ) -> Result<SendMaterial<'source, 'id>, Error> {
        self.check(now)?;
        if messages == 0 {
            return Err(Error::InvalidInput);
        }
        EddsaPublicKey::from_bytes(self.local().0).verify(
            dv::EPHEMERAL_PURPOSE,
            &self.region(),
            signature,
        )?;
        let mut prefix = [0; 16];
        prefix.copy_from_slice(&self.nonce[..16]);
        let mut counter = [0; 8];
        counter.copy_from_slice(&self.nonce[16..]);
        Ok(SendMaterial {
            original: self.task,
            target: self.target,
            encapsulation: self.encapsulation,
            signature: *signature,
            key: self.key,
            prefix,
            next: Some(u64::from_be_bytes(counter)),
            remaining: u64::from(messages),
            certified_at: now,
        })
    }
    /// Actual explicit local signer path to the same private certified epoch.
    pub fn certify_local(
        self,
        key: &EddsaPrivateKey,
        now: u64,
        messages: u32,
    ) -> Result<SendMaterial<'source, 'id>, Error> {
        self.check(now)?;
        if key.public_key().as_bytes() != &self.local().0 {
            return Err(Error::Authentication);
        }
        let signature = key.sign(dv::EPHEMERAL_PURPOSE, &self.region())?;
        self.certify(&signature, now, messages)
    }
}
impl<'source, 'id> SendMaterial<'source, 'id> {
    /// Original actual crypto/provider task, distinct from per-packet task ids.
    pub fn token(&self) -> Token<'id> {
        self.original.token()
    }
    /// Signed source-monotonic epoch stamp to use when minting packet tasks.
    pub const fn stamp(&self) -> u64 {
        self.original.stamp
    }
    /// Immutable key-use lease; hits never renew it. A packet may retain its own
    /// later deadline after crypto completes while both tasks are live.
    pub const fn until(&self) -> u64 {
        self.original.until
    }
    /// Actual fixed ultimate target.
    pub const fn target(&self) -> PeerId {
        self.target
    }
    /// Actual public encapsulation. It is not a key or replay receipt.
    pub const fn encapsulation(&self) -> &[u8; 32] {
        &self.encapsulation
    }
    fn check(&self, now: u64) -> Result<(), Error> {
        self.original.check(now)?;
        if now < self.certified_at || self.remaining == 0 || self.next.is_none() {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    fn nonce(&mut self) -> Result<[u8; 24], Error> {
        let next = self.next.ok_or(Error::Overflow)?;
        if self.remaining == 0 {
            return Err(Error::Capacity);
        }
        let mut nonce = [0; 24];
        nonce[..16].copy_from_slice(&self.prefix);
        nonce[16..].copy_from_slice(&next.to_be_bytes());
        self.next = next.checked_add(1);
        self.remaining -= 1;
        Ok(nonce)
    }
    /// Encrypt one new original packet with its own task and unique24-byte nonce.
    /// The randomly seeded nonce counter never wraps. Preflight refuses before
    /// consuming a nonce; any error after encryption begins burns that nonce.
    /// The exact verified signature is reused only under this fixed source,
    /// target, encapsulation, stamp and original key-use lease. The packet keeps
    /// its own original task and deadline. No per-packet PILS sign.
    pub fn seal(
        &mut self,
        task: Task<'source, 'id>,
        now: u64,
        packet: Packet<'_>,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Sealed<'id>, Error> {
        let work = Scratch::new(scratch);
        self.check(now)?;
        check_packet_use(&self.original, &task, now)?;
        if task.stamp != self.original.stamp {
            return Err(Error::InvalidInput);
        }
        let (plain, bytes) = layout(task.local(), self.target, &packet, work.0.len(), out.len())?;
        let nonce = self.nonce()?;
        dv::encode_plaintext(
            task.local(),
            self.original.stamp,
            self.signature.as_bytes(),
            packet.message,
            &mut work.0[..plain],
        )?;
        let mac = xchacha20poly1305_seal(&self.key, &nonce, &[], &mut work.0[..plain])?;
        BoxHeader {
            without_fc: packet.without_fc,
            encapsulation: self.encapsulation,
            nonce,
            mac,
        }
        .encode(packet.route, &work.0[..plain], out)?;
        Ok(Sealed {
            token: task.token(),
            source: task.local(),
            target: self.target,
            stamp: self.original.stamp,
            bytes,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Id<'id> {
    index: usize,
    epoch: Token<'id>,
}
/// Original occupied send-cache slot and actual material epoch, not an IO id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendId<'id>(Id<'id>);
impl<'id> SendId<'id> {
    /// Original certified material/provider epoch.
    pub const fn token(self) -> Token<'id> {
        self.0.epoch
    }
}
/// One caller-provided fixed send slot. Empty construction performs no crypto.
pub struct SendSlot<'source, 'id> {
    value: Option<SendMaterial<'source, 'id>>,
}
impl SendSlot<'_, '_> {
    /// Empty slot; do not prefill or share another owner's live row.
    pub const fn new() -> Self {
        Self { value: None }
    }
}
impl Default for SendSlot<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}
/// Fixed caller storage with explicit replace/revoke, no heap/LRU timer/global.
/// Drop erases every still-owned slot rather than leaving secrets in caller rows.
pub struct SendCache<'slots, 'source, 'id> {
    slots: &'slots mut [SendSlot<'source, 'id>],
}
impl<'slots, 'source, 'id> SendCache<'slots, 'source, 'id> {
    /// Admit only nonempty, entirely empty caller slot storage.
    pub fn new(slots: &'slots mut [SendSlot<'source, 'id>]) -> Result<Self, Error> {
        if slots.is_empty() {
            return Err(Error::InvalidInput);
        }
        if slots.iter().any(|s| s.value.is_some()) {
            return Err(Error::Conflict);
        }
        Ok(Self { slots })
    }
    /// Install the current certified epoch at exactly this caller-selected index.
    /// A lower stamp than ANY retained same-source/target material is refused,
    /// including an expired or exhausted material. Refusal preserves every slot.
    /// Successful installation retires all other materials for that pair, so
    /// expiry/exhaustion cannot make later lookups fall back to an older epoch.
    /// Equal stamps remain legal; the old key/SendId still retires on replacement.
    ///
    /// This bounded cache holds no unlimited historical watermark after eviction.
    /// Its native owner must serialize same-target material construction and
    /// retire canceled completions before they can install an old epoch again.
    /// Replacement drops/zeroizes keys, never settling original native IO debt.
    pub fn insert(
        &mut self,
        index: usize,
        material: SendMaterial<'source, 'id>,
        now: u64,
    ) -> Result<SendId<'id>, Error> {
        material.check(now)?;
        if index >= self.slots.len() {
            return Err(Error::NotFound);
        }
        let same_pair = |old: &SendMaterial<'source, 'id>| {
            source_eq(material.original.source, old.original.source)
                && material.target == old.target
        };
        if self.slots.iter().any(|slot| {
            slot.value
                .as_ref()
                .is_some_and(|old| same_pair(old) && old.stamp() > material.stamp())
        }) {
            return Err(Error::Stale);
        }
        // No fallible operation follows the preflight. Preserve the exact chosen
        // index even when the old same-target epoch occupied another index.
        let epoch = material.token();
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if i != index && slot.value.as_ref().is_some_and(same_pair) {
                slot.value = None;
            }
        }
        self.slots[index].value = Some(material);
        Ok(SendId(Id { index, epoch }))
    }
    /// Bounded lookup of an actual live source/target. Hits do not renew expiry.
    pub fn find(&self, source: &Source<'id>, target: PeerId, now: u64) -> Option<SendId<'id>> {
        self.slots.iter().enumerate().find_map(|(index, s)| {
            s.value
                .as_ref()
                .filter(|m| {
                    source_eq(source, m.original.source)
                        && m.target == target
                        && m.check(now).is_ok()
                })
                .map(|m| {
                    SendId(Id {
                        index,
                        epoch: m.token(),
                    })
                })
        })
    }
    /// Inspect original signed stamp/expiry for minting a new bounded packet task.
    pub fn material(&self, id: SendId<'id>) -> Result<&SendMaterial<'source, 'id>, Error> {
        self.slots
            .get(id.0.index)
            .and_then(|s| s.value.as_ref())
            .filter(|m| m.token() == id.0.epoch)
            .ok_or(Error::Stale)
    }
    /// Actual per-packet AEAD, preserving the exact original cache epoch and task.
    pub fn seal(
        &mut self,
        id: SendId<'id>,
        task: Task<'source, 'id>,
        now: u64,
        packet: Packet<'_>,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Sealed<'id>, Error> {
        let work = Scratch::new(scratch);
        let material = self
            .slots
            .get_mut(id.0.index)
            .and_then(|s| s.value.as_mut())
            .filter(|m| m.token() == id.0.epoch)
            .ok_or(Error::Stale)?;
        material.seal(task, now, packet, &mut *work.0, out)
    }
    /// Revoke exactly this original slot/epoch, without touching its replacement.
    pub fn revoke(&mut self, id: SendId<'id>) -> Result<(), Error> {
        self.material(id)?;
        self.slots[id.0.index].value = None;
        Ok(())
    }
    /// Source-loss cleanup without reading clocks or acknowledging original IO.
    pub fn revoke_source(&mut self, source: &Source<'id>) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.value
                .as_ref()
                .is_some_and(|m| source_eq(source, m.original.source))
            {
                s.value = None;
                n += 1
            }
        }
        n
    }
    /// Erase all original key owners without clock sampling or native IO claims.
    pub fn clear(&mut self) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.value.take().is_some() {
                n += 1
            }
        }
        n
    }
    /// Drop all expired/retired/exhausted material; no hit/expiry extends a target.
    pub fn reap(&mut self, now: u64) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.value.as_ref().is_some_and(|m| m.check(now).is_err()) {
                s.value = None;
                n += 1
            }
        }
        n
    }
}
impl Drop for SendCache<'_, '_, '_> {
    fn drop(&mut self) {
        for s in self.slots.iter_mut() {
            s.value = None
        }
    }
}
#[derive(Clone, Copy)]
struct SignatureProof {
    sender: PeerId,
    stamp: u64,
    signature: [u8; 64],
}
/// Actual original recipient KEM material. Signature cache starts empty and can
/// only be populated by real AEAD + exact purpose30 verification in open().
pub struct ReceiveMaterial<'source, 'id> {
    original: Task<'source, 'id>,
    encapsulation: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    proof: Option<SignatureProof>,
    created_at: u64,
}
impl fmt::Debug for ReceiveMaterial<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvReceiveMaterial")
            .field("epoch", &self.original.token())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id> ReceiveMaterial<'source, 'id> {
    /// Real local decapsulation into one original cache epoch. The actual scalar
    /// is already caller owned and bound to its converted EdDSA public identity.
    pub fn local(
        task: Task<'source, 'id>,
        encapsulation: [u8; 32],
        key: &RecipientKey,
        now: u64,
    ) -> Result<Self, Error> {
        task.check(now)?;
        if task.local() != key.local {
            return Err(Error::Authentication);
        }
        let key = kem_decapsulate(&key.secret, EcdhePublic::from_bytes(encapsulation))?
            .into_secret_bytes();
        Ok(Self {
            original: task,
            encapsulation,
            key,
            proof: None,
            created_at: now,
        })
    }
    /// Explicit trusted provider material, never claimed as an independently
    /// proven KEM result. Actual native PILS glue calls this only after checking
    /// original operation/identity/MQ/source/encapsulation. AEAD + signature still
    /// run on the first packet and every changed signature statement.
    pub fn from_shared_secret(
        task: Task<'source, 'id>,
        encapsulation: [u8; 32],
        material: &[u8; 32],
        now: u64,
    ) -> Result<Self, Error> {
        task.check(now)?;
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(material);
        Ok(Self {
            original: task,
            encapsulation,
            key,
            proof: None,
            created_at: now,
        })
    }
    /// Original actual provider/KEM task epoch, distinct from each packet task.
    pub fn token(&self) -> Token<'id> {
        self.original.token()
    }
    /// Original immutable key-use lease, never renewed by a packet/cache hit.
    /// Authenticated plaintext keeps its own packet task and deadline.
    pub const fn until(&self) -> u64 {
        self.original.until
    }
    /// Actual public encapsulation bound to this original recipient material.
    pub const fn encapsulation(&self) -> &[u8; 32] {
        &self.encapsulation
    }
    fn check(&self, now: u64) -> Result<(), Error> {
        self.original.check(now)?;
        if now < self.created_at {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    /// Actual AEAD on every packet. Reuse signature verification only for exact
    /// sender+stamp+signature bytes under this immutable target+encapsulation;
    /// changed statements get a full real check before replacing the proof.
    /// Material and packet tasks must each be live; the authenticated output
    /// retains the packet task independently of later material expiry/revocation.
    /// No nonce/stamp is marked replay-admitted, persisted or remotely processed.
    pub fn open<'out>(
        &mut self,
        request: OpenRequest<'source, 'id, '_>,
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, Error> {
        self.open_recover(request, now, scratch, out)
            .map_err(|failure| failure.error())
    }
    /// Same authentication and fixed material cache, preserving the COMPLETE
    /// zeroized caller output loan on every failure for bounded pool reuse.
    pub fn open_recover<'out>(
        &mut self,
        request: OpenRequest<'source, 'id, '_>,
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, OpenFailure<'out>> {
        let work = Scratch::new(scratch);
        let checked = (|| {
            self.check(now)?;
            check_packet_use(&self.original, &request.task, now)?;
            if request.encapsulation()? != self.encapsulation {
                return Err(Error::Stale);
            }
            let n = request.packet.ciphertext().len();
            let used = n.checked_sub(dv::PAYLOAD_PREFIX).ok_or(Error::Truncated)?;
            if work.0.len() < n || out.len() < used {
                return Err(Error::Capacity);
            }
            work.0[..n].copy_from_slice(request.packet.ciphertext());
            let encapsulation = request.packet.encapsulation()?;
            let nonce = request.packet.nonce()?;
            xchacha20poly1305_open(
                &self.key,
                &nonce,
                &[],
                &mut work.0[..n],
                &request.packet.mac()?,
            )?;
            let plain = Plaintext::decode(&work.0[..n])?;
            let sender = plain.sender()?;
            let stamp = plain.stamp()?;
            let mut signature = [0; 64];
            signature.copy_from_slice(&work.0[32..96]);
            let reused = self.proof.is_some_and(|p| {
                p.sender == sender && p.stamp == stamp && p.signature == signature
            });
            if !reused {
                plain.verify_signature(request.local(), &self.encapsulation)?;
            }
            Ok((encapsulation, nonce, sender, stamp, signature, used))
        })();
        let (encapsulation, nonce, sender, stamp, signature, used) = match checked {
            Ok(parts) => parts,
            Err(error) => return Err(OpenFailure::new(error, out)),
        };
        out[..used].copy_from_slice(&work.0[dv::PAYLOAD_PREFIX..dv::PAYLOAD_PREFIX + used]);
        self.proof = Some(SignatureProof {
            sender,
            stamp,
            signature,
        });
        Ok(Opened {
            encapsulation,
            nonce,
            task: request.task,
            source: sender,
            stamp,
            output: out,
            used,
        })
    }
}
/// Original occupied receive slot and actual material epoch, never an IO/replay id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveId<'id>(Id<'id>);
impl<'id> ReceiveId<'id> {
    /// Original provider/KEM task epoch.
    pub const fn token(self) -> Token<'id> {
        self.0.epoch
    }
}
/// One fixed caller-provided erased-on-owner-drop receive slot.
pub struct ReceiveSlot<'source, 'id> {
    value: Option<ReceiveMaterial<'source, 'id>>,
}
impl ReceiveSlot<'_, '_> {
    /// Empty slot, without key construction or allocation.
    pub const fn new() -> Self {
        Self { value: None }
    }
}
impl Default for ReceiveSlot<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}
/// Bounded fixed receive cache. Capacity/eviction never depends on attacker rows
/// or grows a hash table; owner chooses exact replacement index explicitly.
pub struct ReceiveCache<'slots, 'source, 'id> {
    slots: &'slots mut [ReceiveSlot<'source, 'id>],
}
impl<'slots, 'source, 'id> ReceiveCache<'slots, 'source, 'id> {
    /// Admit only nonempty, fresh caller storage without taking over live rows.
    pub fn new(slots: &'slots mut [ReceiveSlot<'source, 'id>]) -> Result<Self, Error> {
        if slots.is_empty() {
            return Err(Error::InvalidInput);
        }
        if slots.iter().any(|s| s.value.is_some()) {
            return Err(Error::Conflict);
        }
        Ok(Self { slots })
    }
    /// Explicit exact-index replacement. Validate new material before old erasure.
    pub fn insert(
        &mut self,
        index: usize,
        material: ReceiveMaterial<'source, 'id>,
        now: u64,
    ) -> Result<ReceiveId<'id>, Error> {
        material.check(now)?;
        let slot = self.slots.get_mut(index).ok_or(Error::NotFound)?;
        let epoch = material.token();
        slot.value = Some(material);
        Ok(ReceiveId(Id { index, epoch }))
    }
    /// Match original local source/encapsulation without renewing expiry/proof.
    pub fn find(
        &self,
        source: &Source<'id>,
        encapsulation: &[u8; 32],
        now: u64,
    ) -> Option<ReceiveId<'id>> {
        self.slots.iter().enumerate().find_map(|(index, s)| {
            s.value
                .as_ref()
                .filter(|m| {
                    source_eq(source, m.original.source)
                        && m.encapsulation == *encapsulation
                        && m.check(now).is_ok()
                })
                .map(|m| {
                    ReceiveId(Id {
                        index,
                        epoch: m.token(),
                    })
                })
        })
    }
    /// Original material expiry/encapsulation for a caller's packet task creation.
    pub fn material(&self, id: ReceiveId<'id>) -> Result<&ReceiveMaterial<'source, 'id>, Error> {
        self.slots
            .get(id.0.index)
            .and_then(|s| s.value.as_ref())
            .filter(|m| m.token() == id.0.epoch)
            .ok_or(Error::Stale)
    }
    /// Authenticate original packet under the exact occupied recipient epoch.
    pub fn open<'out>(
        &mut self,
        id: ReceiveId<'id>,
        request: OpenRequest<'source, 'id, '_>,
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, Error> {
        self.open_recover(id, request, now, scratch, out)
            .map_err(|failure| failure.error())
    }
    /// Authenticate under the exact original cache slot, returning the complete
    /// erased caller loan even if the slot was revoked/replaced or crypto fails.
    pub fn open_recover<'out>(
        &mut self,
        id: ReceiveId<'id>,
        request: OpenRequest<'source, 'id, '_>,
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, OpenFailure<'out>> {
        let Some(material) = self
            .slots
            .get_mut(id.0.index)
            .and_then(|s| s.value.as_mut())
            .filter(|m| m.token() == id.0.epoch)
        else {
            scratch.zeroize();
            return Err(OpenFailure::new(Error::Stale, out));
        };
        material.open_recover(request, now, scratch, out)
    }
    /// Revoke this exact original epoch; a reused/replaced index is left untouched.
    pub fn revoke(&mut self, id: ReceiveId<'id>) -> Result<(), Error> {
        self.material(id)?;
        self.slots[id.0.index].value = None;
        Ok(())
    }
    /// Source-loss key cleanup without clock access or native-debt inference.
    pub fn revoke_source(&mut self, source: &Source<'id>) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.value
                .as_ref()
                .is_some_and(|m| source_eq(source, m.original.source))
            {
                s.value = None;
                n += 1
            }
        }
        n
    }
    /// Erase all key/proof owners without sampling any possibly failed clock.
    pub fn clear(&mut self) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.value.take().is_some() {
                n += 1
            }
        }
        n
    }
    /// Erase expired/retired material; malformed packets do not renew/replace it.
    pub fn reap(&mut self, now: u64) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.value.as_ref().is_some_and(|m| m.check(now).is_err()) {
                s.value = None;
                n += 1
            }
        }
        n
    }
}
impl Drop for ReceiveCache<'_, '_, '_> {
    fn drop(&mut self) {
        for s in self.slots.iter_mut() {
            s.value = None
        }
    }
}

#[cfg(test)]
mod send_generation_tests {
    use super::*;

    // Repeatable fixture entropy is confined to these cryptographic unit cases.
    // The production cache never constructs an entropy provider.
    struct FixtureEntropy(u8);
    impl Entropy for FixtureEntropy {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
            for byte in output {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }
    fn check(value: bool) -> Result<(), Error> {
        if value { Ok(()) } else { Err(Error::Conflict) }
    }
    fn certified<'source, 'id>(
        source: &'source Source<'id>,
        key: &EddsaPrivateKey,
        target: PeerId,
        stamp: u64,
        until: u64,
        messages: u32,
        entropy: &mut FixtureEntropy,
    ) -> Result<SendMaterial<'source, 'id>, Error> {
        source
            .task(stamp, 1, until)?
            .prepare_seal(target, 1, entropy)?
            .certify_local(key, 2, messages)
    }

    #[test]
    fn reverse_certification_refuses_old_epoch_and_preserves_selected_index() -> Result<(), Error> {
        let instance = Instance::new();
        let key = EddsaPrivateKey::from_seed([1; 32]);
        let target = PeerId(*EddsaPrivateKey::from_seed([2; 32]).public_key().as_bytes());
        let source = instance.source(PeerId(*key.public_key().as_bytes()), 0, 100)?;
        let mut entropy = FixtureEntropy(0);
        // Both real encapsulations exist before either certificate completes.
        let old = source
            .task(10, 1, 90)?
            .prepare_seal(target, 1, &mut entropy)?;
        let new = source
            .task(20, 1, 60)?
            .prepare_seal(target, 1, &mut entropy)?;
        let mut slots = [SendSlot::new(), SendSlot::new(), SendSlot::new()];
        let mut cache = SendCache::new(&mut slots)?;
        let current = cache.insert(1, new.certify_local(&key, 2, 4)?, 2)?;
        let late = old.certify_local(&key, 3, 4)?;
        check(matches!(cache.insert(0, late, 3), Err(Error::Stale)))?;
        check(cache.find(&source, target, 3) == Some(current))?;
        check(cache.material(current)?.stamp() == 20)?;

        // Invalid destination preflight must not revoke the existing material.
        let invalid = certified(&source, &key, target, 30, 60, 4, &mut entropy)?;
        check(matches!(cache.insert(3, invalid, 3), Err(Error::NotFound)))?;
        check(cache.find(&source, target, 3) == Some(current))?;

        let replacement = certified(&source, &key, target, 30, 60, 4, &mut entropy)?;
        let selected = cache.insert(0, replacement, 3)?;
        check(selected.0.index == 0)?;
        check(matches!(cache.material(current), Err(Error::Stale)))?;
        check(cache.find(&source, target, 3) == Some(selected))?;
        let mut scratch = [0; dv::PAYLOAD_PREFIX + 4];
        let mut out = [0; dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4];
        let sealed = cache.seal(
            selected,
            source.task(30, 3, 50)?,
            3,
            Packet {
                route: &[],
                without_fc: false,
                message: &[0, 4, 0, 0],
            },
            &mut scratch,
            &mut out,
        )?;
        check(sealed.stamp() == 30 && sealed.target() == target)
    }

    #[test]
    fn newest_expiry_or_nonce_exhaustion_cannot_reveal_old_epoch() -> Result<(), Error> {
        for exhaust in [false, true] {
            let instance = Instance::new();
            let key = EddsaPrivateKey::from_seed([3; 32]);
            let target = PeerId(*EddsaPrivateKey::from_seed([4; 32]).public_key().as_bytes());
            let source = instance.source(PeerId(*key.public_key().as_bytes()), 0, 100)?;
            let mut entropy = FixtureEntropy(40);
            let late = source
                .task(9, 1, 90)?
                .prepare_seal(target, 1, &mut entropy)?;
            let old = certified(&source, &key, target, 10, 90, 4, &mut entropy)?;
            let new = certified(&source, &key, target, 20, 5, 1, &mut entropy)?;
            let mut slots = [SendSlot::new(), SendSlot::new()];
            let mut cache = SendCache::new(&mut slots)?;
            let retired = cache.insert(0, old, 2)?;
            let current = cache.insert(1, new, 2)?;
            check(matches!(cache.material(retired), Err(Error::Stale)))?;
            let now = if exhaust {
                let mut scratch = [0; dv::PAYLOAD_PREFIX + 4];
                let mut out = [0; dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4];
                let sealed = cache.seal(
                    current,
                    source.task(20, 3, 5)?,
                    3,
                    Packet {
                        route: &[],
                        without_fc: false,
                        message: &[0, 4, 0, 0],
                    },
                    &mut scratch,
                    &mut out,
                )?;
                check(sealed.stamp() == 20)?;
                3
            } else {
                5
            };
            check(cache.find(&source, target, now).is_none())?;
            // A retained latest epoch remains the floor even after its local
            // expiry/nonce budget. It cannot be replaced by a late old proof.
            check(matches!(
                cache.insert(0, late.certify_local(&key, now, 4)?, now),
                Err(Error::Stale)
            ))?;
            check(cache.reap(now) == 1)?;
            check(cache.find(&source, target, now).is_none())?;
        }
        Ok(())
    }

    #[test]
    fn replacement_keeps_other_targets_and_source_allocations() -> Result<(), Error> {
        let instance = Instance::new();
        let key = EddsaPrivateKey::from_seed([5; 32]);
        let local = PeerId(*key.public_key().as_bytes());
        let source = instance.source(local, 0, 100)?;
        let other_source = instance.source(local, 0, 100)?;
        let target = PeerId(*EddsaPrivateKey::from_seed([6; 32]).public_key().as_bytes());
        let other_target = PeerId(*EddsaPrivateKey::from_seed([7; 32]).public_key().as_bytes());
        let mut entropy = FixtureEntropy(80);
        let mut slots = [SendSlot::new(), SendSlot::new(), SendSlot::new()];
        let mut cache = SendCache::new(&mut slots)?;
        let old = cache.insert(
            0,
            certified(&source, &key, target, 10, 90, 2, &mut entropy)?,
            2,
        )?;
        let different_target = cache.insert(
            1,
            certified(&source, &key, other_target, 100, 90, 2, &mut entropy)?,
            2,
        )?;
        let different_source = cache.insert(
            2,
            certified(&other_source, &key, target, 100, 90, 2, &mut entropy)?,
            2,
        )?;
        let current = cache.insert(
            0,
            certified(&source, &key, target, 20, 90, 2, &mut entropy)?,
            2,
        )?;
        check(matches!(cache.material(old), Err(Error::Stale)))?;
        check(cache.find(&source, target, 3) == Some(current))?;
        check(cache.find(&source, other_target, 3) == Some(different_target))?;
        check(cache.find(&other_source, target, 3) == Some(different_source))
    }
}

#[cfg(test)]
#[path = "cache/packet_lease_tests.rs"]
mod packet_lease_tests;
