//! Official peer identity lifecycle, separated from persistence, IPC and scheduling.
//! Profile selection is explicit: failed verification never tries another profile.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Typed allocation-free client ownership over the official PILS IPC.
pub mod client;

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
    AbsoluteTime, SignaturePurpose,
    pils::{PeerUpdate, Request, Response},
};
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
        Ok(ActiveIdentity {
            signing: EddsaPrivateKey::from_seed(*seed),
            exchange: EcdheSecret::from_eddsa_seed(*seed),
        })
    }
}

/// The current signing and exchange keys. Their borrows cannot outlive this owner.
pub struct ActiveIdentity {
    signing: EddsaPrivateKey,
    exchange: EcdheSecret,
}
impl ActiveIdentity {
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

/// Allocation-free PILS service owner. H bounds the retained public announcement.
/// The host owns clients, immutable queued frame copies and secret-buffer erasure.
pub struct Service<const H: usize = 4096> {
    master: MasterKey,
    profile: Profile,
    identity: ActiveIdentity,
    hash: [u8; 64],
    announcement: [u8; H],
    announcement_len: usize,
    limits: Limits,
}
impl<const H: usize> Service<H> {
    /// Start with the source's real empty-address identity and signed HELLO.
    pub fn new(
        master: MasterKey,
        profile: Profile,
        now: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut empty = [];
        let builder = HelloBuilder::new(&mut empty, limits);
        let hash = builder.address_hash(profile.hello());
        let identity = master.derive(&hash, profile)?;
        let mut announcement = [0; H];
        let announcement_len =
            announcement_for(&builder, &identity, hash, profile, now, &mut announcement)?;
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
        match Request::decode(bytes)? {
            Request::Feed { block } => {
                let mut builder = HelloBuilder::new(scratch, self.limits);
                let mut addresses = block
                    .get(gnunet_hello::BLOCK_HEADER_LEN..)
                    .ok_or(Error::Truncated)?;
                if block.len() > self.limits.maximum_input_bytes {
                    return Err(Error::Capacity);
                }
                while !addresses.is_empty() {
                    let end = addresses
                        .iter()
                        .position(|b| *b == 0)
                        .ok_or(Error::Truncated)?;
                    if builder.add_address(&addresses[..end])? == AddAddress::AlreadyPresent {
                        return Err(Error::Malformed);
                    }
                    addresses = &addresses[end + 1..];
                }
                let hash = builder.address_hash(self.profile.hello());
                if self.profile == Profile::ReferenceDeterministic && hash == self.hash {
                    return Ok(Action::Unchanged);
                }
                let identity = self.master.derive(&hash, self.profile)?;
                let mut next = [0; H];
                let n = announcement_for(&builder, &identity, hash, self.profile, now, &mut next)?;
                let identity_changed = identity.public_key() != self.identity.public_key();
                self.identity = identity;
                self.hash = hash;
                self.announcement = next;
                self.announcement_len = n;
                Ok(Action::Broadcast { identity_changed })
            }
            Request::Sign { request, region } => {
                if out.len() < gnunet_wire::official::pils::SIGN_RESULT_LEN {
                    return Err(Error::Capacity);
                }
                let (signature, crypto_error) = match self.identity.sign(region) {
                    Ok(sig) => (*sig.as_bytes(), None),
                    Err(e) => ([0; 64], Some(e)),
                };
                let len = Response::Signature {
                    request,
                    peer: *self.identity.public_key().as_bytes(),
                    signature,
                }
                .encode(out)?;
                Ok(Action::Reply { len, crypto_error })
            }
            Request::Decapsulate {
                request,
                encapsulation,
            } => {
                if out.len() < gnunet_wire::official::pils::KEY_MESSAGE_LEN {
                    return Err(Error::Capacity);
                }
                let (key, crypto_error) = match self.identity.decapsulate(encapsulation) {
                    Ok(k) => (k, None),
                    Err(e) => (Zeroizing::new([0; 32]), Some(e)),
                };
                let len = Response::Decapsulation { request, key: &key }.encode(out)?;
                Ok(Action::Reply { len, crypto_error })
            }
            Request::Ecdh { request, public } => {
                if out.len() < gnunet_wire::official::pils::ECDH_RESULT_LEN {
                    return Err(Error::Capacity);
                }
                let (key, crypto_error) = match self.identity.ecdh(public) {
                    Ok(k) => (k, None),
                    Err(e) => (Zeroizing::new([0; 64]), Some(e)),
                };
                let len = Response::Ecdh { request, key: &key }.encode(out)?;
                Ok(Action::Reply { len, crypto_error })
            }
        }
    }
}
fn announcement_for(
    builder: &HelloBuilder<'_>,
    identity: &ActiveIdentity,
    hash: [u8; 64],
    profile: Profile,
    now: u64,
    out: &mut [u8],
) -> Result<usize, Error> {
    let hello = builder.sign(
        &identity.signing,
        AbsoluteTime::from_micros(now.saturating_add(HELLO_LIFETIME)),
        profile.hello(),
    )?;
    let n = gnunet_wire::official::pils::PEER_UPDATE_PREFIX
        .checked_add(hello.block_len()?)
        .ok_or(Error::Overflow)?;
    let header = gnunet_wire::official::MessageHeader::from_total_size(
        gnunet_wire::official::message_type::PILS_PEER_ID,
        n,
    )?;
    if out.len() < n {
        return Err(Error::Capacity);
    }
    header.encode(out)?;
    out[4..68].copy_from_slice(&hash);
    out[68..72].copy_from_slice(&((n - 72) as u32).to_be_bytes());
    hello.encode_block(&mut out[72..n])?;
    Ok(n)
}
