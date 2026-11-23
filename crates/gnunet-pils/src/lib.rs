//! Official peer identity lifecycle, separated from persistence, IPC and scheduling.
//! Profile selection is explicit: failed verification never tries another profile.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Typed allocation-free client ownership over the official PILS IPC.
pub mod client;
mod fixed;
mod storage;

pub use fixed::FixedService;
/// Explicit public HELLO parsing and canonical-address resource limits.
pub use gnunet_hello::Limits as HelloLimits;

use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_hello::{AddAddress, Hello, HelloBuilder, Limits, SignatureProfile};
use gnunet_session_crypto::{
    exchange::{EcdhePublic, EcdheSecret, kem_decapsulate},
    hkdf_extract,
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, MessageHeader, SignaturePurpose, message_type,
    pils::{self, PeerUpdate, Request, Response},
};
#[cfg(feature = "alloc")]
use storage::HeapBytes;
use storage::{ByteStorage, InlineBytes};
use zeroize::{Zeroize, Zeroizing};

/// Reference HELLO validity: two days in microseconds.
pub const HELLO_LIFETIME: u64 = 172_800_000_000;

/// The actual current source and the published work-in-progress specification differ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Normal v0.29.1: empty address hash, source's ephemeral-key HKDF label.
    Reference029,
    /// Official conditional build: canonical address hash, source's ephemeral label.
    ReferenceDeterministic,
    /// LSD0014 July2025 text: contextual label. Its published vector disagrees;
    /// it matches ReferenceDeterministic instead. No automatic fallback is used.
    Lsd0014Text,
}
impl Profile {
    /// Select explicit identity-derivation semantics. Official normal and
    /// conditional builds remain distinct from the published contextual-label
    /// text; failed verification never changes this selection.
    pub fn from_label(label: &[u8]) -> Result<Self, Error> {
        match label {
            b"reference029" | b"reference-0.29.1" => Ok(Self::Reference029),
            b"deterministic" | b"reference-deterministic" => Ok(Self::ReferenceDeterministic),
            b"lsd0014-text" => Ok(Self::Lsd0014Text),
            _ => Err(Error::InvalidInput),
        }
    }
    /// Resolve a node-wide choice and an optional explicit source-local choice.
    /// Conflicting choices fail before any identity or native operation exists.
    /// An absent selection keeps the official normal-build default.
    pub fn configured(global: Option<&[u8]>, local: Option<&[u8]>) -> Result<Self, Error> {
        let global = global.map(Self::from_label).transpose()?;
        let local = local.map(Self::from_label).transpose()?;
        match (global, local) {
            (Some(global), Some(local)) if global != local => Err(Error::Conflict),
            (Some(profile), _) | (_, Some(profile)) => Ok(profile),
            (None, None) => Ok(Self::Reference029),
        }
    }
    /// HELLO address coverage used by this one selected profile.
    #[must_use]
    pub const fn hello(self) -> SignatureProfile {
        match self {
            Self::Reference029 => SignatureProfile::Gnunet029,
            _ => SignatureProfile::DeterministicPidDerivation,
        }
    }
    fn label(self) -> &'static [u8] {
        match self {
            Self::Lsd0014Text => b"gnunet-pils-contextual-peer-key",
            _ => b"gnunet-pils-ephemeral-peer-key",
        }
    }
}

/// Persisted 32-byte initial key material. No Clone, Debug or raw export.
/// Storage belongs to the outer owner; constructing this type performs no I/O.
pub struct MasterKey(Zeroizing<[u8; 32]>);
impl MasterKey {
    /// Construct another purpose-specific key owner from an explicitly verified
    /// context. Callers must bind `hash` to a verified PILS announcement before
    /// publishing this key. The temporary seed owner is erased after the callback.
    pub fn with_active_seed<T>(
        &self,
        hash: &[u8; 64],
        profile: Profile,
        construct: impl FnOnce(&[u8; 32]) -> T,
    ) -> Result<T, Error> {
        let seed = self.derive_seed(hash, profile)?;
        Ok(construct(&seed))
    }
    /// Import the persisted seed and erase this local input copy.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let key = Self(Zeroizing::new(seed));
        seed.zeroize();
        key
    }
    /// Public Ed25519 projection of the persisted raw32 initial seed, used by
    /// the ordinary offline NSE proof utility. This is not an active PILS
    /// announcement/derived identity and grants no service or epoch authority.
    /// No private bytes leave this owner; the temporary signing key is erased.
    #[must_use]
    pub fn initial_public_key(&self) -> EddsaPublicKey {
        EddsaPrivateKey::from_seed(*self.0).public_key()
    }
    fn derive_seed(&self, hash: &[u8; 64], profile: Profile) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut seed = Zeroizing::new([0; 32]);
        hkdf_extract(hash, &[self.0.as_ref()]).expand(&[profile.label()], seed.as_mut())?;
        Ok(seed)
    }
    /// Construct fresh purpose-specific key owners under the chosen context.
    pub fn derive(&self, hash: &[u8; 64], profile: Profile) -> Result<ActiveIdentity, Error> {
        let seed = self.derive_seed(hash, profile)?;
        Ok(ActiveIdentity::from_active_seed(&seed))
    }
}

/// The current signing and exchange keys. Their borrows cannot outlive this owner.
pub struct ActiveIdentity {
    signing: EddsaPrivateKey,
    exchange: EcdheSecret,
}
impl ActiveIdentity {
    /// Import an already selected active Ed25519 seed. The caller retains its
    /// original seed and has established which public identity it represents.
    #[must_use]
    pub fn from_active_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: EddsaPrivateKey::from_seed(*seed),
            exchange: EcdheSecret::from_eddsa_seed(*seed),
        }
    }
    /// Public identity; this is not proof of any remote connection.
    #[must_use]
    pub fn public_key(&self) -> EddsaPublicKey {
        self.signing.public_key()
    }
    /// Sign the exact complete purpose region, including its size and purpose.
    pub fn sign(&self, region: &[u8]) -> Result<EddsaSignature, Error> {
        let purpose = SignaturePurpose::decode(region.get(..8).ok_or(Error::Truncated)?)?;
        self.signing.sign(purpose.purpose(), region)
    }
    /// Legacy SHA512(X25519), erased when the returned owner is dropped.
    pub fn ecdh(&self, public: [u8; 32]) -> Result<Zeroizing<[u8; 64]>, Error> {
        Ok(self
            .exchange
            .exchange_hashed(EcdhePublic::from_bytes(public))?
            .into_secret_bytes())
    }
    /// RFC9180 DHKEM output, erased when the returned owner is dropped.
    pub fn decapsulate(&self, encapsulation: [u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        Ok(
            kem_decapsulate(&self.exchange, EcdhePublic::from_bytes(encapsulation))?
                .into_secret_bytes(),
        )
    }
}

/// Observable result; encoded output does not imply host queue admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Broadcast the retained announcement to every current subscriber.
    Broadcast {
        /// Whether the actual public identity changed.
        identity_changed: bool,
    },
    /// Official conditional profile suppresses an unchanged address set.
    Unchanged,
    /// Reply only to the original connection. Zero crypto results are explicit failures.
    Reply {
        /// Exact encoded length.
        len: usize,
        /// Original crypto error; zero result is sent as in the reference.
        crypto_error: Option<Error>,
    },
}

/// PILS service owner with inline announcement storage by default. `H` bounds
/// the retained public announcement for either storage profile.
/// The host owns clients, immutable queued frame copies and secret-buffer erasure.
pub struct Service<const H: usize = 4096, A: ByteStorage = InlineBytes<H>> {
    master: MasterKey,
    profile: Profile,
    identity: ActiveIdentity,
    hash: [u8; 64],
    announcement: A,
    announcement_len: usize,
    limits: Limits,
}
/// PILS service owner with exact-length heap storage for each announcement.
#[cfg(feature = "alloc")]
pub type HeapService<const H: usize = 4096> = Service<H, HeapBytes>;

impl<const H: usize> Service<H> {
    /// Start with the source's real empty-address identity and signed HELLO
    /// in allocation-free inline storage.
    pub fn new(
        master: MasterKey,
        profile: Profile,
        now: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::build(master, profile, now, limits)
    }
}
#[cfg(feature = "alloc")]
impl<const H: usize> HeapService<H> {
    /// Start with the source's real empty-address identity and signed HELLO
    /// in exact-length heap storage. Allocation failure returns `Error::Capacity`.
    pub fn new_heap(
        master: MasterKey,
        profile: Profile,
        now: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::build(master, profile, now, limits)
    }
}
impl<const H: usize, A: ByteStorage> Service<H, A> {
    fn build(master: MasterKey, profile: Profile, now: u64, limits: Limits) -> Result<Self, Error> {
        let mut empty = [];
        let builder = HelloBuilder::new(&mut empty, limits);
        let hash = builder.address_hash(profile.hello());
        let identity = master.derive(&hash, profile)?;
        let (announcement, announcement_len) =
            announcement_for::<H, A>(&builder, &identity, hash, profile, now)?;
        Ok(Self {
            master,
            profile,
            identity,
            hash,
            announcement,
            announcement_len,
            limits,
        })
    }
    /// Current public update sent immediately to a newly connected client.
    #[must_use]
    pub fn announcement(&self) -> &[u8] {
        &self.announcement[..self.announcement_len]
    }
    /// Current key authority. Rotation requires old borrowers to be released first.
    #[must_use]
    pub const fn identity(&self) -> &ActiveIdentity {
        &self.identity
    }
    /// Current announced context hash.
    #[must_use]
    pub const fn address_hash(&self) -> [u8; 64] {
        self.hash
    }
    /// Construct a purpose-specific owner such as CORE/TCP without exporting the
    /// master seed. The callback's temporary active-seed borrow cannot escape;
    /// callers must erase any deliberate temporary copies in their constructors.
    pub fn with_active_seed<T>(&self, construct: impl FnOnce(&[u8; 32]) -> T) -> Result<T, Error> {
        let seed = self.master.derive_seed(&self.hash, self.profile)?;
        Ok(construct(&seed))
    }
    /// Verify an announcement against the persisted master before using its identity.
    /// Scratch is public address storage and may change when verification fails.
    pub fn verify_update<'a>(
        &self,
        bytes: &[u8],
        scratch: &'a mut [u8],
        now: u64,
    ) -> Result<Hello<'a>, Error> {
        let update = PeerUpdate::decode(bytes)?;
        let hello = Hello::parse_block(update.block, scratch, self.limits)?;
        hello.verify_at(self.profile.hello(), AbsoluteTime::from_micros(now))?;
        if hello.address_hash(self.profile.hello()) != update.hash
            || self.master.derive(&update.hash, self.profile)?.public_key() != hello.peer()
        {
            return Err(Error::Authentication);
        }
        Ok(hello)
    }
    /// Process one original client request. Refusal preserves the current identity
    /// and announcement. FEED uses unsigned addresses, not its claimed key/signature.
    pub fn receive(
        &mut self,
        bytes: &[u8],
        scratch: &mut [u8],
        now: u64,
        out: &mut [u8],
    ) -> Result<Action, Error> {
        let request = Request::decode(bytes)?;
        let Request::Feed { block } = request else {
            return self.identity.reply(request, out);
        };
        let builder = fed_addresses(block, scratch, self.limits)?;
        let hash = builder.address_hash(self.profile.hello());
        if self.profile == Profile::ReferenceDeterministic && hash == self.hash {
            return Ok(Action::Unchanged);
        }
        let identity = self.master.derive(&hash, self.profile)?;
        let (next, n) = announcement_for::<H, A>(&builder, &identity, hash, self.profile, now)?;
        let identity_changed = identity.public_key() != self.identity.public_key();
        self.identity = identity;
        self.hash = hash;
        self.announcement = next;
        self.announcement_len = n;
        Ok(Action::Broadcast { identity_changed })
    }
}

impl ActiveIdentity {
    fn reply(&self, request: Request<'_>, out: &mut [u8]) -> Result<Action, Error> {
        match request {
            Request::Sign { request, region } => {
                if out.len() < pils::SIGN_RESULT_LEN {
                    return Err(Error::Capacity);
                }
                let (signature, crypto_error) = match self.sign(region) {
                    Ok(sig) => (*sig.as_bytes(), None),
                    Err(e) => ([0; 64], Some(e)),
                };
                let len = Response::Signature {
                    request,
                    peer: *self.public_key().as_bytes(),
                    signature,
                }
                .encode(out)?;
                Ok(Action::Reply { len, crypto_error })
            }
            Request::Decapsulate {
                request,
                encapsulation,
            } => {
                if out.len() < pils::KEY_MESSAGE_LEN {
                    return Err(Error::Capacity);
                }
                let (key, crypto_error) = match self.decapsulate(encapsulation) {
                    Ok(k) => (k, None),
                    Err(e) => (Zeroizing::new([0; 32]), Some(e)),
                };
                let len = Response::Decapsulation { request, key: &key }.encode(out)?;
                Ok(Action::Reply { len, crypto_error })
            }
            Request::Ecdh { request, public } => {
                if out.len() < pils::ECDH_RESULT_LEN {
                    return Err(Error::Capacity);
                }
                let (key, crypto_error) = match self.ecdh(public) {
                    Ok(k) => (k, None),
                    Err(e) => (Zeroizing::new([0; 64]), Some(e)),
                };
                let len = Response::Ecdh { request, key: &key }.encode(out)?;
                Ok(Action::Reply { len, crypto_error })
            }
            Request::Feed { .. } => Err(Error::InvalidInput),
        }
    }
}

fn fed_addresses<'a>(
    block: &[u8],
    scratch: &'a mut [u8],
    limits: Limits,
) -> Result<HelloBuilder<'a>, Error> {
    if block.len() > limits.maximum_input_bytes {
        return Err(Error::Capacity);
    }
    let mut addresses = block
        .get(gnunet_hello::BLOCK_HEADER_LEN..)
        .ok_or(Error::Truncated)?;
    let mut builder = HelloBuilder::new(scratch, limits);
    while !addresses.is_empty() {
        let end = addresses
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(Error::Truncated)?;
        if builder.add_address(&addresses[..end])? == AddAddress::AlreadyPresent {
            return Err(Error::Malformed);
        }
        addresses = &addresses[end + 1..];
    }
    Ok(builder)
}

fn announcement_for<const H: usize, A: ByteStorage>(
    builder: &HelloBuilder<'_>,
    identity: &ActiveIdentity,
    hash: [u8; 64],
    profile: Profile,
    now: u64,
) -> Result<(A, usize), Error> {
    let update = Announcement::new(builder, identity, hash, profile, now)?;
    let length = update.header.size();
    if H < length {
        return Err(Error::Capacity);
    }
    let mut out = A::zeroed(length)?;
    update.encode(&mut out)?;
    Ok((out, length))
}

struct Announcement<'a> {
    hello: Hello<'a>,
    hash: [u8; 64],
    header: MessageHeader,
}

impl<'a> Announcement<'a> {
    fn new(
        builder: &'a HelloBuilder<'_>,
        identity: &ActiveIdentity,
        hash: [u8; 64],
        profile: Profile,
        now: u64,
    ) -> Result<Self, Error> {
        let hello = builder.sign(
            &identity.signing,
            AbsoluteTime::from_micros(now.saturating_add(HELLO_LIFETIME)),
            profile.hello(),
        )?;
        let length = pils::PEER_UPDATE_PREFIX
            .checked_add(hello.block_len()?)
            .ok_or(Error::Overflow)?;
        let header = MessageHeader::from_total_size(message_type::PILS_PEER_ID, length)?;
        Ok(Self {
            hello,
            hash,
            header,
        })
    }

    fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let length = self.header.size();
        let out = out.get_mut(..length).ok_or(Error::Capacity)?;
        let block_len = self
            .hello
            .encode_block(&mut out[pils::PEER_UPDATE_PREFIX..])?;
        self.header.encode(out)?;
        out[4..68].copy_from_slice(&self.hash);
        out[68..72].copy_from_slice(&(block_len as u32).to_be_bytes());
        Ok(length)
    }
}
