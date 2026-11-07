//! Real official DV boxed-payload KEM, XChaCha20-Poly1305 and purpose30 material.
//! No IO, allocator, clock or hidden entropy is used. Caller-owned source/task
//! brands bind each operation; the separate replay module grants bounded live
//! admission. Authentication alone proves neither freshness nor durability.
#![no_std]
#![forbid(unsafe_code)]
/// Fixed caller-storage certified material reuse, with no IO/replay admission.
pub mod cache;
/// Bounded exact live-source replay admission from authentic plaintext only.
pub mod replay;
use core::{cell::Cell, fmt};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature, Entropy};
use gnunet_session_crypto::{
    aead::{xchacha20poly1305_open, xchacha20poly1305_seal},
    exchange::{EcdhePublic, EcdheSecret, kem_decapsulate, kem_encapsulate_random},
};
use gnunet_transport::{
    PeerId,
    dv::{self, BoxHeader, BoxPacket, Plaintext},
};
use gnunet_types::Error;
use gnunet_wire::official::Frame;
use zeroize::{Zeroize, Zeroizing};
/// Stable caller allocation domain, with checked counters and no Atomic64/global.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Construct no crypto or IO resources.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    /// Mint one source for an actual caller-owned epoch. `until` is an absolute
    /// logical hard target, not the remote source-monotonic signed stamp.
    /// Caller creates this only for its original actual local identity/source;
    /// this pure constructor does not attest that an MQ/peer/store exists.
    pub fn source(&self, local: PeerId, now: u64, until: u64) -> Result<Source<'_>, Error> {
        if now >= until || until == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let allocation = self.next.get().checked_add(1).ok_or(Error::Overflow)?;
        self.next.set(allocation);
        Ok(Source {
            instance: self,
            allocation,
            local,
            until,
            active: Cell::new(true),
            replay_claim: Cell::new(0),
            next: Cell::new(0),
        })
    }
}
/// Original caller source. Retirement invalidates every retained task, including
/// a same-peer future source; minting another source gets a distinct allocation.
pub struct Source<'id> {
    instance: &'id Instance,
    allocation: u64,
    local: PeerId,
    until: u64,
    active: Cell<bool>,
    // 0=fresh, 1=one live Replay owner, 2=retired/lost: never silently reopen.
    replay_claim: Cell<u8>,
    next: Cell<u64>,
}
impl<'id> Source<'id> {
    /// Permanently retire this original source without crypto/IO.
    pub fn retire(&self) {
        self.active.set(false);
        self.replay_claim.set(2)
    }
    /// Original local public identity; never an authenticated peer by itself.
    pub const fn local(&self) -> PeerId {
        self.local
    }
    /// Mint one finite task with caller's actual source-monotonic stamp.
    /// The surrounding native owner additionally enforces its immutable native
    /// deadline, cancellation and physical source lifetime; no clock is read.
    pub fn task<'source>(
        &'source self,
        stamp: u64,
        now: u64,
        until: u64,
    ) -> Result<Task<'source, 'id>, Error> {
        if !self.active.get() {
            return Err(Error::Closed);
        }
        let until = until.min(self.until);
        if until == u64::MAX || now >= until {
            return Err(Error::InvalidInput);
        }
        let serial = self.next.get().checked_add(1).ok_or(Error::Overflow)?;
        self.next.set(serial);
        Ok(Task {
            source: self,
            serial,
            stamp,
            until,
        })
    }
}
/// One nonforgeable source/allocation/task identity. Opaque application IDs never
/// enter the wire, and an old token can survive bounded source-slot reuse.
#[derive(Clone, Copy)]
pub struct Token<'id> {
    instance: &'id Instance,
    allocation: u64,
    serial: u64,
}
impl PartialEq for Token<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.instance, other.instance)
            && self.allocation == other.allocation
            && self.serial == other.serial
    }
}
impl Eq for Token<'_> {}
impl fmt::Debug for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvTask")
            .field("source", &self.allocation)
            .field("task", &self.serial)
            .finish()
    }
}
/// Original operation ownership. No Clone: a sealing task consumes its one KEM
/// and nonce once, rather than silently reusing a ciphertext/nonce on retry.
pub struct Task<'source, 'id> {
    source: &'source Source<'id>,
    serial: u64,
    stamp: u64,
    until: u64,
}
impl<'source, 'id> Task<'source, 'id> {
    /// Original local source token.
    pub fn token(&self) -> Token<'id> {
        Token {
            instance: self.source.instance,
            allocation: self.source.allocation,
            serial: self.serial,
        }
    }
    /// Original source's actual caller-bound public identity.
    pub fn local(&self) -> PeerId {
        self.source.local
    }
    /// Original finite logical target.
    pub const fn until(&self) -> u64 {
        self.until
    }
    /// Original signed source-monotonic value; not interpreted as recipient UTC.
    pub const fn stamp(&self) -> u64 {
        self.stamp
    }
    /// Check original source/expiry; caller also checks its native hard bound.
    pub fn check(&self, now: u64) -> Result<(), Error> {
        if !self.source.active.get() {
            return Err(Error::Closed);
        }
        if now >= self.until {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    /// Real fresh EdDSA-to-X25519/DHKEM encapsulation and a fresh nonce24 from
    /// caller entropy. Partial entropy failure drops/wipes all secret material.
    /// No deterministic/static secret or fallback entropy is supplied.
    pub fn prepare_seal(
        self,
        target: PeerId,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<PreparedSeal<'source, 'id>, Error> {
        self.check(now)?;
        let recipient = EcdhePublic::from_edwards(&target.0)?;
        let (enc, key) = kem_encapsulate_random(recipient, entropy)?;
        let key = key.into_secret_bytes();
        let mut nonce = Zeroizing::new([0; 24]);
        entropy.fill(nonce.as_mut()).map_err(|_| Error::Entropy)?;
        Ok(PreparedSeal {
            task: self,
            target,
            encapsulation: *enc.as_bytes(),
            nonce: *nonce,
            key,
        })
    }
    /// Retain the original complete received packet and exact local target for a
    /// real decapsulation/open. This is structural admission, never decryption.
    pub fn prepare_open<'packet>(
        self,
        packet: BoxPacket<'packet>,
        now: u64,
    ) -> Result<OpenRequest<'source, 'id, 'packet>, Error> {
        self.check(now)?;
        packet.check_recipient(self.local())?;
        if packet.hop_count() != 0 {
            return Err(Error::InvalidInput);
        }
        if packet.ciphertext().len() < dv::PAYLOAD_PREFIX + 4 {
            return Err(Error::Truncated);
        }
        Ok(OpenRequest { task: self, packet })
    }
}
/// Real ephemeral KEM material retained while an asynchronous actual signer
/// produces the exact original statement. No Clone/raw key getter/secret Debug.
pub struct PreparedSeal<'source, 'id> {
    task: Task<'source, 'id>,
    target: PeerId,
    encapsulation: [u8; 32],
    nonce: [u8; 24],
    key: Zeroizing<[u8; 32]>,
}
impl fmt::Debug for PreparedSeal<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedDvSeal")
            .field("task", &self.task.token())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id> PreparedSeal<'source, 'id> {
    /// Original task identity.
    pub fn token(&self) -> Token<'id> {
        self.task.token()
    }
    /// Fixed actual caller source, required of the real signer.
    pub fn local(&self) -> PeerId {
        self.task.local()
    }
    /// Fixed ultimate target, not a routing hint that may be silently rebound.
    pub const fn target(&self) -> PeerId {
        self.target
    }
    /// Original current source/expiry check.
    pub fn check(&self, now: u64) -> Result<(), Error> {
        self.task.check(now)
    }
    /// Exact official purpose30 region80 over original target/stamp/encapsulation.
    pub fn region(&self) -> [u8; 80] {
        dv::ephemeral_region(self.target, self.task.stamp, &self.encapsulation)
    }
    /// Actual explicit caller-owned signer path, with public/source equality.
    /// Output is atomic; whole scratch wipes on every return. This consumes the
    /// ephemeral material even on failure and performs real signature + AEAD.
    pub fn seal_local(
        self,
        key: &EddsaPrivateKey,
        now: u64,
        packet: cache::Packet<'_>,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Sealed<'id>, Error> {
        let work = Scratch::new(scratch);
        self.check(now)?;
        if key.public_key().as_bytes() != &self.local().0 {
            return Err(Error::Authentication);
        }
        let signature = key.sign(dv::EPHEMERAL_PURPOSE, &self.region())?;
        self.seal_inner(&signature, now, packet, work, out)
    }
    /// Finish a real external signer result. Signature is independently verified
    /// against the original local identity/region before plaintext or encryption.
    /// The caller must correlate its provider result to token(); native PILS glue
    /// additionally checks actual operation+original MQ identity. No provider ACK
    /// or successful IO is invented here. Scratch wipes even on early rejection.
    pub fn seal(
        self,
        signature: &EddsaSignature,
        now: u64,
        packet: cache::Packet<'_>,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Sealed<'id>, Error> {
        self.seal_inner(signature, now, packet, Scratch::new(scratch), out)
    }
    fn seal_inner(
        self,
        signature: &EddsaSignature,
        now: u64,
        packet: cache::Packet<'_>,
        work: Scratch<'_>,
        out: &mut [u8],
    ) -> Result<Sealed<'id>, Error> {
        self.check(now)?;
        let cache::Packet {
            route,
            without_fc,
            message,
        } = packet;
        let inner = Frame::decode(message)?;
        if matches!(
            inner.header().message_type().value(),
            dv::LEARN_TYPE | dv::BOX_TYPE
        ) {
            return Err(Error::Malformed);
        }
        if route.len() > dv::MAX_HOPS || (!route.is_empty() && route.last() != Some(&self.target)) {
            return Err(Error::InvalidInput);
        }
        for (i, peer) in route.iter().enumerate() {
            if *peer == self.local() || route[..i].contains(peer) {
                return Err(Error::InvalidInput);
            }
        }
        let plain = dv::PAYLOAD_PREFIX
            .checked_add(message.len())
            .ok_or(Error::Overflow)?;
        let length = dv::BOX_PREFIX
            .checked_add(route.len() * 32)
            .and_then(|n| n.checked_add(plain))
            .filter(|n| *n <= u16::MAX as usize)
            .ok_or(Error::TooLarge)?;
        if work.0.len() < plain || out.len() < length {
            return Err(Error::Capacity);
        }
        EddsaPublicKey::from_bytes(self.local().0).verify(
            dv::EPHEMERAL_PURPOSE,
            &self.region(),
            signature,
        )?;
        dv::encode_plaintext(
            self.local(),
            self.task.stamp,
            signature.as_bytes(),
            message,
            &mut work.0[..plain],
        )?;
        let mac = xchacha20poly1305_seal(&self.key, &self.nonce, &[], &mut work.0[..plain])?;
        let header = BoxHeader {
            without_fc,
            encapsulation: self.encapsulation,
            nonce: self.nonce,
            mac,
        };
        header.encode(route, &work.0[..plain], out)?;
        Ok(Sealed {
            token: self.task.token(),
            source: self.local(),
            target: self.target,
            stamp: self.task.stamp,
            bytes: length,
        })
    }
}
/// Actual complete crypto construction receipt, not an enqueue/write/remote ACK.
/// The original caller still owns the immutable encoded output and its IO lease.
#[derive(Clone, Copy, Debug)]
pub struct Sealed<'id> {
    token: Token<'id>,
    source: PeerId,
    target: PeerId,
    stamp: u64,
    bytes: usize,
}
impl<'id> Sealed<'id> {
    /// Original task, without any reassigned source.
    pub const fn token(self) -> Token<'id> {
        self.token
    }
    /// Actual signed source.
    pub const fn source(self) -> PeerId {
        self.source
    }
    /// Actual fixed ultimate target.
    pub const fn target(self) -> PeerId {
        self.target
    }
    /// Signed source-monotonic value.
    pub const fn stamp(self) -> u64 {
        self.stamp
    }
    /// Exact constructed immutable frame byte count.
    pub const fn bytes(self) -> usize {
        self.bytes
    }
}
/// Explicit caller-owned actual recipient scalar. Constructor checks its derived
/// X25519 public equals conversion of the bound EdDSA identity. No seed read,
/// import or key-file operation is performed by this API.
pub struct RecipientKey {
    local: PeerId,
    secret: EcdheSecret,
}
impl fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvRecipientKey")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl RecipientKey {
    /// Bind an already caller-owned scalar to its actual public identity.
    pub fn new(local: PeerId, secret: EcdheSecret) -> Result<Self, Error> {
        if secret.public_key() != EcdhePublic::from_edwards(&local.0)? {
            return Err(Error::Authentication);
        }
        Ok(Self { local, secret })
    }
}
/// Original immutable received box and original recipient/source/task.
/// No ciphertext clone/allocation is necessary while a real KEM provider runs.
pub struct OpenRequest<'source, 'id, 'packet> {
    task: Task<'source, 'id>,
    packet: BoxPacket<'packet>,
}
impl fmt::Debug for OpenRequest<'_, '_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvOpenRequest")
            .field("task", &self.task.token())
            .field("ciphertext_bytes", &self.packet.ciphertext().len())
            .finish()
    }
}
impl<'source, 'id, 'packet> OpenRequest<'source, 'id, 'packet> {
    /// Original source/task identity.
    pub fn token(&self) -> Token<'id> {
        self.task.token()
    }
    /// Fixed original local recipient.
    pub fn local(&self) -> PeerId {
        self.task.local()
    }
    /// Exact original encapsulation for the actual KEM provider.
    pub fn encapsulation(&self) -> Result<[u8; 32], Error> {
        self.packet.encapsulation()
    }
    /// Original current source/expiry check.
    pub fn check(&self, now: u64) -> Result<(), Error> {
        self.task.check(now)
    }
    /// Real local KEM decapsulation, followed by AEAD and sender signature.
    /// Only caller-owned matched recipient material is accepted. No plaintext
    /// leaves scratch before all actual authentication/structural checks succeed.
    pub fn open_local<'out>(
        self,
        key: &RecipientKey,
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, Error> {
        self.open_local_recover(key, now, scratch, out)
            .map_err(|failure| failure.error())
    }
    /// Real local decapsulation with complete erased-loan recovery on every
    /// key/source/KEM/authentication/capacity refusal. No failed result carries
    /// authentication authority; scratch is erased on every return.
    pub fn open_local_recover<'out>(
        self,
        key: &RecipientKey,
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, OpenFailure<'out>> {
        let work = Scratch::new(scratch);
        let checked = (|| {
            self.check(now)?;
            if self.local() != key.local {
                return Err(Error::Authentication);
            }
            Ok(
                kem_decapsulate(&key.secret, EcdhePublic::from_bytes(self.encapsulation()?))?
                    .into_secret_bytes(),
            )
        })();
        let material = match checked {
            Ok(material) => material,
            Err(error) => return Err(OpenFailure::new(error, out)),
        };
        self.open_inner_recover(&material, now, work, out)
    }

    /// Use exact32 bytes from an explicitly trusted caller-owned decapsulation
    /// provider, then perform real AEAD and purpose30 verification here. This
    /// function makes no independent KEM/identity provenance claim about the
    /// supplied material. The separate native PILS owner checks its real result
    /// operation/identity/source before calling this function; raw material is
    /// borrowed, never retained/copied by an externally constructible receipt.
    pub fn open_with_shared_secret<'out>(
        self,
        material: &[u8; 32],
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, Error> {
        self.open_inner(material, now, Scratch::new(scratch), out)
    }
    /// Recover the complete zeroized caller loan on authentication, capacity or
    /// source refusal. A failed loan carries no authentication/replay authority.
    pub fn open_recover<'out>(
        self,
        material: &[u8; 32],
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, OpenFailure<'out>> {
        self.open_inner_recover(material, now, Scratch::new(scratch), out)
    }
    fn open_inner<'out>(
        self,
        key: &[u8; 32],
        now: u64,
        work: Scratch<'_>,
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, Error> {
        self.open_inner_recover(key, now, work, out)
            .map_err(|failure| failure.error())
    }
    fn open_inner_recover<'out>(
        self,
        key: &[u8; 32],
        now: u64,
        work: Scratch<'_>,
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, OpenFailure<'out>> {
        let checked = (|| {
            self.check(now)?;
            let n = self.packet.ciphertext().len();
            let message = n.checked_sub(dv::PAYLOAD_PREFIX).ok_or(Error::Truncated)?;
            if work.0.len() < n || out.len() < message {
                return Err(Error::Capacity);
            }
            work.0[..n].copy_from_slice(self.packet.ciphertext());
            let encapsulation = self.packet.encapsulation()?;
            let nonce = self.packet.nonce()?;
            xchacha20poly1305_open(key, &nonce, &[], &mut work.0[..n], &self.packet.mac()?)?;
            let plain = Plaintext::decode(&work.0[..n])?;
            plain.verify_signature(self.local(), &encapsulation)?;
            Ok((
                encapsulation,
                nonce,
                plain.sender()?,
                plain.stamp()?,
                message,
            ))
        })();
        let (encapsulation, nonce, source, stamp, used) = match checked {
            Ok(parts) => parts,
            Err(error) => return Err(OpenFailure::new(error, out)),
        };
        out[..used].copy_from_slice(&work.0[dv::PAYLOAD_PREFIX..dv::PAYLOAD_PREFIX + used]);
        Ok(Opened {
            encapsulation,
            nonce,
            task: self.task,
            source,
            stamp,
            output: out,
            used,
        })
    }
}
/// Actual AEAD + purpose30 authentication receipt and borrowed zeroizing plaintext
/// owner. It does NOT prove replay admission, durable stamp/nonce state, current
/// route validation, enqueue, IO or remote processing. Drop erases its output.
pub struct Opened<'source, 'id, 'out> {
    encapsulation: [u8; 32],
    nonce: [u8; 24],
    task: Task<'source, 'id>,
    source: PeerId,
    stamp: u64,
    output: &'out mut [u8],
    used: usize,
}
impl fmt::Debug for Opened<'_, '_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedDvPayload")
            .field("task", &self.task.token())
            .field("bytes", &self.used)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id, 'out> Opened<'source, 'id, 'out> {
    /// Original authenticated target, retained by the immutable source binding.
    /// This alone is no replay/IO receipt; no duplicate target array is stored.
    pub const fn target(&self) -> PeerId {
        self.task.source.local
    }
    /// Actual encapsulation authenticated by the retained purpose30 check.
    pub const fn encapsulation(&self) -> &[u8; 32] {
        &self.encapsulation
    }
    /// Original AEAD nonce from the exact authenticated ciphertext.
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }
    /// Original crypto task, not a replay/durability receipt.
    pub fn token(&self) -> Token<'id> {
        self.task.token()
    }
    /// Actual signature-verified sender.
    pub const fn sender(&self) -> PeerId {
        self.source
    }
    /// Signed original sender-monotonic stamp, not a local expiration.
    pub const fn stamp(&self) -> u64 {
        self.stamp
    }
    /// Borrow actual authenticated plaintext only while original source/task is
    /// current. The outer owner additionally checks its immutable native target.
    pub fn message(&self, now: u64) -> Result<&[u8], Error> {
        self.task.check(now)?;
        Ok(&self.output[..self.used])
    }
    /// Consume all authentication authority and erase the COMPLETE original
    /// caller slice before returning it for bounded pool reuse. This does not
    /// acknowledge a network input, cancel a provider or undo replay admission.
    pub fn recycle(mut self) -> &'out mut [u8] {
        self.output.zeroize();
        core::mem::take(&mut self.output)
    }
}
impl Drop for Opened<'_, '_, '_> {
    fn drop(&mut self) {
        self.output.zeroize()
    }
}
/// Failed authentication/capacity/source check plus the complete zeroized caller
/// output loan. No raw key, plaintext or authenticated constructor is exposed.
pub struct OpenFailure<'out> {
    error: Error,
    output: &'out mut [u8],
}
impl core::fmt::Debug for OpenFailure<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DvOpenFailure")
            .field("error", &self.error)
            .field("capacity", &self.output.len())
            .finish()
    }
}
impl<'out> OpenFailure<'out> {
    fn new(error: Error, output: &'out mut [u8]) -> Self {
        output.zeroize();
        Self { error, output }
    }
    /// Actual original refusal; no successful crypto result is manufactured.
    pub const fn error(&self) -> Error {
        self.error
    }
    /// Consume this failed operation and return the complete erased loan.
    pub fn recycle(mut self) -> &'out mut [u8] {
        self.output.zeroize();
        core::mem::take(&mut self.output)
    }
}
impl Drop for OpenFailure<'_> {
    fn drop(&mut self) {
        self.output.zeroize();
    }
}

struct Scratch<'a>(&'a mut [u8]);
impl<'a> Scratch<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        bytes.zeroize();
        Self(bytes)
    }
}
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}
