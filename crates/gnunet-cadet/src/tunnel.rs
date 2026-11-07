//! Pure pinned CADET Axolotl core with a caller-driven original KX controller.
//!
//! The caller authorizes the actual CORE peer/route before selecting this live
//! context. CID is only an unauthenticated routing label. Authentication is
//! committed only after both header and body tags pass. Seal consumes its key
//! before returning immutable bytes; there is deliberately no counter rollback.
/// Stable node domain, bounded live registry and owned dynamic context leases.
pub mod context;
/// Role, retry, candidate promotion and original output ownership.
pub mod controller;
/// Actual asynchronous identity-DH backend ports, separate from public peer metadata.
pub mod identity_dh;
pub use context::{Context, Scope};
mod keys;
use gnunet_crypto::{EddsaPrivateKey, Entropy, hash512};
use gnunet_session_crypto::{
    aead::{xchacha20poly1305_open, xchacha20poly1305_seal},
    exchange::{EcdhePublic, EcdheSecret},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    Frame, MessageHeader,
    cadet_peer::{
        AxHeader, ChannelMessage, ENCRYPTED_PREFIX, EncryptedBody, KX_FORCE_REPLY, MAC_LEN,
        MAX_TUNNEL_PLAINTEXT_LEN, PeerMessage,
    },
    message_type,
};
use keys::{Keys, Secret};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Actual role selected by bytewise ordering of the two public peer identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Lower public identity, the initial KX initiator and first DH ratcheter.
    Alice,
    /// Higher public identity, the initial KX_AUTH responder.
    Betty,
}

/// Owned actual derived Ed25519 peer identity's DH secret, erased on drop.
/// This seed is the actual peer key, not PILS's persistent root derivation IKM.
pub struct Identity {
    peer: [u8; 32],
    dh: EcdheSecret,
}
impl Identity {
    /// Consume an actual Ed25519 peer seed and erase this local input copy.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let owned = Zeroizing::new(seed);
        seed.zeroize();
        let signing = EddsaPrivateKey::from_seed(*owned);
        let peer = *signing.public_key().as_bytes();
        drop(signing);
        let dh = EcdheSecret::from_eddsa_seed(*owned);
        Self { peer, dh }
    }
    /// Actual public identity derived from this private owner.
    #[must_use]
    pub const fn peer(&self) -> [u8; 32] {
        self.peer
    }
}

/// Two original private scalar owners; no Clone, Debug or secret export.
pub struct LocalKeys {
    // Only generate() constructs production keys. No partial persistence/import
    // API can silently recreate an old key epoch with counters reset to zero.
    ephemeral: EcdheSecret,
    ratchet: EcdheSecret,
}
impl LocalKeys {
    /// Generate independent fresh original ephemeral/ratchet owners. A restarted
    /// session must use fresh keys; partial counter/key restoration is unsupported.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let ephemeral = EcdheSecret::generate(entropy)?;
        let ratchet = EcdheSecret::generate(entropy)?;
        if ephemeral.public_key() == ratchet.public_key() {
            return Err(Error::Entropy);
        }
        Ok(Self { ephemeral, ratchet })
    }
    /// Public fields to retain alongside the original outgoing KX control frame.
    #[must_use]
    pub fn exchange(&self) -> Exchange {
        Exchange {
            ephemeral_key: *self.ephemeral.public_key().as_bytes(),
            ratchet_key: *self.ratchet.public_key().as_bytes(),
        }
    }
}
/// Exact public key fields from one original KX/KX_AUTH candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exchange {
    /// Original A0/B0 public coordinate.
    pub ephemeral_key: [u8; 32],
    /// Original public ratchet coordinate.
    pub ratchet_key: [u8; 32],
}

struct Skipped {
    header: Secret,
    message: Secret,
    ratchet: [u8; 32],
    number: u32,
}
/// One caller-owned skipped-key slot; secrets are erased when retired or dropped.
/// The slot exposes no key bytes and cannot be cloned or formatted.
pub struct SkippedSlot {
    value: Option<Skipped>,
}
impl SkippedSlot {
    /// Empty fixed storage, without allocation or a global key cache.
    #[must_use]
    pub const fn new() -> Self {
        Self { value: None }
    }
    fn clear(&mut self) {
        self.value = None;
    }
}
impl Default for SkippedSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Explicit caller-owned committed and transactional skipped-key storage.
pub struct Storage<'slots> {
    /// Current unconsumed authenticated-session skipped message keys.
    pub skipped: &'slots mut [SkippedSlot],
    /// Separate staging slots, at least as many as committed slots. Cleared on
    /// every refused packet; no speculative key enters the committed cache.
    pub staging: &'slots mut [SkippedSlot],
}
/// Explicit resource limits; no clock, automatic eviction or hidden allocator.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete tunnel plaintext bytes, at least four.
    pub plaintext_bytes: usize,
    /// Maximum skipped derivations in one chain, at most pinned C's256.
    pub maximum_gap: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            plaintext_bytes: MAX_TUNNEL_PLAINTEXT_LEN,
            maximum_gap: 256,
        }
    }
}
/// Public observations only; no master/header/chain key is disclosed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Next message number to seal in the current local ratchet.
    pub sent: u32,
    /// Next missing receive number in the current remote ratchet.
    pub received: u32,
    /// Previous local ratchet's sent count, included as PNs.
    pub previous_sent: u32,
    /// Current retained skipped-key count.
    pub skipped: usize,
    /// Peer proved the initial3-DH or a whole authenticated data packet.
    pub peer_confirmed: bool,
    /// A new send ratchet is allowed by an authenticated remote step.
    pub ratchet_allowed: bool,
    /// Next seal must use a fresh local ratchet (including Alice's first send).
    pub ratchet_pending: bool,
}

/// Original immutable output bytes. Seal already consumed this message key;
/// cancellation/drop never restores it. Retrying means retaining these bytes.
pub struct Sealed<'id, 'out> {
    scope: Scope<'id>,
    bytes: &'out [u8],
    header: AxHeader,
}
impl<'id, 'out> Sealed<'id, 'out> {
    /// Exact complete official TUNNEL_ENCRYPTED bytes, with both real tags.
    #[must_use]
    pub const fn bytes(&self) -> &'out [u8] {
        self.bytes
    }
    /// Original end-to-end context for the caller's immutable output metadata.
    #[must_use]
    pub const fn scope(&self) -> Scope<'id> {
        self.scope
    }
    /// Public diagnostic counter/ratchet fields; this grants no exposure/ACK.
    #[must_use]
    pub const fn header(&self) -> AxHeader {
        self.header
    }
}
/// Authenticated original plaintext with its exact end-to-end context.
pub struct Opened<'id, 'out> {
    scope: Scope<'id>,
    bytes: &'out [u8],
    header: AxHeader,
}
impl<'id, 'out> Opened<'id, 'out> {
    /// Complete authenticated plaintext; channel dispatch is a separate owner.
    #[must_use]
    pub const fn bytes(&self) -> &'out [u8] {
        self.bytes
    }
    /// Actual session binding to select the correct channel owner.
    #[must_use]
    pub const fn scope(&self) -> Scope<'id> {
        self.scope
    }
    /// Only now authenticated Ns/PNs/DHRs fields.
    #[must_use]
    pub const fn header(&self) -> AxHeader {
        self.header
    }
}

// Erased symmetric candidate only; no private scalar duplication or public clone.
struct CandidateKeys {
    keys: Keys,
    local: Exchange,
    remote: Exchange,
}

/// One initial exchange and subsequent DH/message chains for one bound peer.
/// No Clone, key export, detached success, transport retry or implicit KX reset.
pub struct Session<'id, 'slots> {
    context: Scope<'id>,
    owns_lease: bool,
    keys: Keys,
    local_ratchet: EcdheSecret,
    local_ratchet_public: [u8; 32],
    remote_ratchet: EcdhePublic,
    local_exchange: Exchange,
    remote_exchange: Exchange,
    initial_proof: [u8; 64],
    sent: u32,
    received: u32,
    previous_sent: u32,
    peer_confirmed: bool,
    ratchet_allowed: bool,
    ratchet_pending: bool,
    storage: Storage<'slots>,
    limits: Limits,
}
impl<'id, 'slots> Session<'id, 'slots> {
    /// Derive the original three64-byte DH hashes and exact five-key schedule.
    /// This is a candidate until verify_initial_auth or a full data open passes.
    /// KX message ordering/retry/monotime replay policy remains the controller.
    pub fn new(
        context: Context<'id>,
        identity: &Identity,
        local: LocalKeys,
        remote: Exchange,
        storage: Storage<'slots>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let binding = context.scope();
        binding.authorize()?;
        if binding.local != identity.peer {
            return Err(Error::PermissionDenied);
        }
        Self::validate_storage(&storage, limits)?;
        let candidate = Self::candidate_keys(binding, identity, &local, remote)?;
        let mut session =
            Self::from_candidate(context.into_scope(), local, candidate, storage, limits);
        session.owns_lease = true;
        Ok(session)
    }
    // Private controller hooks retain the original peer Context, never expose
    // reset/clone/restore publicly, and derive before consuming original keys.
    fn validate_storage(storage: &Storage<'_>, limits: Limits) -> Result<(), Error> {
        if !(4..=MAX_TUNNEL_PLAINTEXT_LEN).contains(&limits.plaintext_bytes)
            || limits.maximum_gap > 256
        {
            return Err(Error::InvalidInput);
        }
        if storage.staging.len() < storage.skipped.len() {
            return Err(Error::Capacity);
        }
        if storage
            .skipped
            .iter()
            .chain(storage.staging.iter())
            .any(|slot| slot.value.is_some())
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn candidate_keys(
        context: Scope<'_>,
        identity: &Identity,
        local: &LocalKeys,
        remote: Exchange,
    ) -> Result<CandidateKeys, Error> {
        if context.local != identity.peer {
            return Err(Error::PermissionDenied);
        }
        let local_exchange = local.exchange();
        let keys = keys::initial(
            context.role,
            identity,
            &context.peer,
            &local.ephemeral,
            EcdhePublic::from_bytes(remote.ephemeral_key),
        )?;
        // Validate the advertised ratchet's DH contribution without replacing
        // any root or treating a public coordinate as authentication.
        drop(
            local
                .ratchet
                .exchange_hashed(EcdhePublic::from_bytes(remote.ratchet_key))?,
        );
        Ok(CandidateKeys {
            keys,
            local: local_exchange,
            remote,
        })
    }
    // Invoked only inside the controller's trusted original-source port callback;
    // no arbitrary raw public completion is accepted by the controller API.
    fn candidate_keys_with_identity_hash(
        context: Scope<'_>,
        local: &LocalKeys,
        remote: Exchange,
        identity_hash: &[u8; 64],
    ) -> Result<CandidateKeys, Error> {
        let keys = keys::initial_with_identity_hash(
            context.role,
            identity_hash,
            &context.peer,
            &local.ephemeral,
            EcdhePublic::from_bytes(remote.ephemeral_key),
        )?;
        drop(
            local
                .ratchet
                .exchange_hashed(EcdhePublic::from_bytes(remote.ratchet_key))?,
        );
        Ok(CandidateKeys {
            keys,
            local: local.exchange(),
            remote,
        })
    }
    fn from_candidate(
        context: Scope<'id>,
        local: LocalKeys,
        candidate: CandidateKeys,
        storage: Storage<'slots>,
        limits: Limits,
    ) -> Self {
        let initial_proof = hash512(candidate.keys.root.as_ref());
        Self {
            context,
            owns_lease: false,
            keys: candidate.keys,
            local_ratchet: local.ratchet,
            local_ratchet_public: candidate.local.ratchet_key,
            remote_ratchet: EcdhePublic::from_bytes(candidate.remote.ratchet_key),
            local_exchange: candidate.local,
            remote_exchange: candidate.remote,
            initial_proof,
            sent: 0,
            received: 0,
            previous_sent: 0,
            peer_confirmed: false,
            ratchet_allowed: false,
            ratchet_pending: context.role == Role::Alice,
            storage,
            limits,
        }
    }
    fn recycle_storage(mut self) -> Storage<'slots> {
        for slot in self.storage.skipped.iter_mut() {
            slot.clear();
        }
        self.clear_staging();
        core::mem::replace(
            &mut self.storage,
            Storage {
                skipped: &mut [],
                staging: &mut [],
            },
        )
    }
    /// Original current context capability; caller still checks real CORE source.
    #[must_use]
    pub const fn scope(&self) -> Scope<'id> {
        self.context
    }
    fn authorize(&self, scope: Scope<'id>) -> Result<(), Error> {
        if self.context != scope {
            return Err(Error::StaleGeneration);
        }
        self.context.authorize()
    }
    /// Snapshot only public counters and ownership/resource observations.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            sent: self.sent,
            received: self.received,
            previous_sent: self.previous_sent,
            skipped: self
                .storage
                .skipped
                .iter()
                .filter(|s| s.value.is_some())
                .count(),
            peer_confirmed: self.peer_confirmed,
            ratchet_allowed: self.ratchet_allowed,
            ratchet_pending: self.ratchet_pending,
        }
    }
    /// Emit the original KX_AUTH fields/proof; caller owns actual immutable
    /// control submission, role/phase, FORCE_REPLY and retry scheduling.
    pub fn initial_auth(
        &self,
        scope: Scope<'id>,
        connection: [u8; 32],
        force_reply: bool,
    ) -> Result<PeerMessage<'static>, Error> {
        self.authorize(scope)?;
        Ok(PeerMessage::KeyExchangeAuth {
            flags: if force_reply { KX_FORCE_REPLY } else { 0 },
            connection,
            ephemeral_key: self.local_exchange.ephemeral_key,
            ratchet_key: self.local_exchange.ratchet_key,
            auth: self.initial_proof,
        })
    }
    /// Verify proof only for this exact original remote exchange. A duplicate
    /// cannot reset counters, clear skipped keys or recreate an old key epoch.
    pub fn verify_initial_auth(
        &mut self,
        scope: Scope<'id>,
        remote: Exchange,
        proof: &[u8; 64],
    ) -> Result<(), Error> {
        self.authorize(scope)?;
        if remote != self.remote_exchange || !bool::from(proof.ct_eq(&self.initial_proof)) {
            return Err(Error::Authentication);
        }
        if self.peer_confirmed {
            return Err(Error::Replay);
        }
        self.peer_confirmed = true;
        Ok(())
    }
    /// Request the next fresh send DH step only when the authenticated peer has
    /// advanced. External message-count/time policy decides when to request it.
    pub fn request_ratchet(&mut self, scope: Scope<'id>) -> Result<(), Error> {
        self.authorize(scope)?;
        if !self.ratchet_allowed {
            return Err(Error::WouldBlock);
        }
        self.ratchet_pending = true;
        Ok(())
    }
    /// Explicitly discard unconsumed old receive keys under caller policy.
    /// This never rewinds a chain or makes an already accepted packet reusable.
    pub fn forget_skipped(&mut self, scope: Scope<'id>) -> Result<usize, Error> {
        self.authorize(scope)?;
        let count = self.snapshot().skipped;
        for slot in self.storage.skipped.iter_mut() {
            slot.clear();
        }
        Ok(count)
    }
    /// Seal one whole plaintext frame. Preflight precedes output/key changes.
    /// On success the key/counter are consumed regardless of later exposure,
    /// cancellation or transport failure. Retransmit the original retained bytes.
    pub fn seal<'out>(
        &mut self,
        scope: Scope<'id>,
        connection: [u8; 32],
        plaintext: &[u8],
        output: &'out mut [u8],
        entropy: &mut impl Entropy,
    ) -> Result<Sealed<'id, 'out>, Error> {
        self.authorize(scope)?;
        if !self.peer_confirmed {
            return Err(Error::NotReady);
        }
        Frame::decode(plaintext)?;
        if plaintext.len() > self.limits.plaintext_bytes {
            return Err(Error::Capacity);
        }
        let total = ENCRYPTED_PREFIX + plaintext.len() + MAC_LEN;
        let outer = MessageHeader::from_total_size(message_type::CADET_TUNNEL_ENCRYPTED, total)?;
        if output.len() < total {
            return Err(Error::Capacity);
        }
        let mut keys = self.keys.clone();
        let mut new_ratchet = None;
        let mut ratchet_public = self.local_ratchet_public;
        let (number, previous) = if self.ratchet_pending {
            let fresh = EcdheSecret::generate(entropy)?;
            let public = *fresh.public_key().as_bytes();
            if public == self.local_ratchet_public {
                return Err(Error::Entropy);
            }
            let (root, next_header, chain) =
                keys::ratchet(&keys.root, &fresh, self.remote_ratchet)?;
            keys.root = root;
            keys.send_header = Some(keys::copy(&keys.next_send_header));
            keys.next_send_header = next_header;
            keys.send_chain = Some(chain);
            new_ratchet = Some(fresh);
            ratchet_public = public;
            (0, self.sent)
        } else {
            (self.sent, self.previous_sent)
        };
        let next_number = number.checked_add(1).ok_or(Error::Overflow)?;
        let (message_key, next_chain) =
            keys::chain(keys.send_chain.as_ref().ok_or(Error::NotReady)?)?;
        let header_key = keys.send_header.as_ref().ok_or(Error::NotReady)?;
        let message_nonce = keys::nonce(&message_key)?;
        let header_nonce = keys::nonce(header_key)?;
        let header = AxHeader {
            sent: number,
            previous_sent: previous,
            ratchet_key: ratchet_public,
        };
        let encoded = &mut output[..total];
        let result = (|| {
            outer.encode(encoded)?;
            let (prefix, body) = encoded.split_at_mut(ENCRYPTED_PREFIX);
            prefix[4..8].fill(0);
            prefix[8..40].copy_from_slice(&connection);
            let (ciphertext, mac) = body.split_at_mut(plaintext.len());
            ciphertext.copy_from_slice(plaintext);
            let tag = xchacha20poly1305_seal(&message_key, &message_nonce, &[], ciphertext)?;
            mac.copy_from_slice(&tag);
            header.encode(&mut prefix[56..96])?;
            let tag = xchacha20poly1305_seal(header_key, &header_nonce, body, &mut prefix[56..96])?;
            prefix[40..56].copy_from_slice(&tag);
            Ok::<(), Error>(())
        })();
        if let Err(error) = result {
            encoded.zeroize();
            return Err(error);
        }
        keys.send_chain = Some(next_chain);
        self.keys = keys;
        self.sent = next_number;
        self.previous_sent = previous;
        if let Some(fresh) = new_ratchet {
            self.local_ratchet = fresh;
            self.local_ratchet_public = ratchet_public;
            self.ratchet_pending = false;
            self.ratchet_allowed = false;
        }
        scope.statistics().bytes(
            crate::statistics::Metric::EncryptedBytes,
            plaintext.len() + MAC_LEN,
        );
        Ok(Sealed {
            scope,
            bytes: encoded,
            header,
        })
    }

    /// Authenticate both exact detached tags and only then commit chains/cache.
    /// Authentication failure zeroizes the attempted plaintext prefix. Length,
    /// source and capacity refusals leave caller output/state unchanged.
    pub fn open<'out>(
        &mut self,
        scope: Scope<'id>,
        wire: &[u8],
        output: &'out mut [u8],
    ) -> Result<Opened<'id, 'out>, Error> {
        let (size, header) = self.authenticate(scope, wire, output)?;
        Ok(Opened {
            scope,
            bytes: &output[..size],
            header,
        })
    }
    // Return only copied authenticated metadata so a controller can try its
    // working session and then candidate without creating speculative borrowed
    // plaintext capabilities or aliasing its caller-owned output.
    fn authenticate(
        &mut self,
        scope: Scope<'id>,
        wire: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, AxHeader), Error> {
        self.authorize(scope)?;
        let PeerMessage::Encrypted {
            header_mac,
            encrypted_header,
            body,
            ..
        } = PeerMessage::decode(wire)?
        else {
            return Err(Error::Unsupported);
        };
        let size = body.ciphertext().len();
        if size > self.limits.plaintext_bytes || output.len() < size {
            return Err(Error::Capacity);
        }
        let result = self.open_checked(&header_mac, &encrypted_header, body, &mut output[..size]);
        if result.is_err() {
            self.clear_staging();
        }
        if matches!(result, Err(Error::Authentication)) {
            output[..size].zeroize();
        }
        let header = result?;
        if matches!(
            ChannelMessage::decode(&output[..size]),
            Ok(ChannelMessage::KeepAlive)
        ) {
            scope
                .statistics()
                .add(crate::statistics::Metric::KeepaliveReceived, 1);
        }
        Ok((size, header))
    }
    fn open_checked(
        &mut self,
        mac: &[u8; 16],
        encrypted_header: &[u8; 40],
        body: EncryptedBody<'_>,
        out: &mut [u8],
    ) -> Result<AxHeader, Error> {
        if let Some(current) = self.keys.receive_header.as_ref()
            && let Ok(header) = decrypt_header(current, mac, encrypted_header, body)
        {
            if header.ratchet_key != *self.remote_ratchet.as_bytes() {
                return Err(Error::Authentication);
            }
            if header.sent < self.received {
                let current = keys::copy(current);
                return self.open_saved(Some((&current, header)), mac, encrypted_header, body, out);
            }
            return self.open_live(header, false, body, out);
        }
        if let Ok(header) =
            decrypt_header(&self.keys.next_receive_header, mac, encrypted_header, body)
        {
            return self.open_live(header, true, body, out);
        }
        self.open_saved(None, mac, encrypted_header, body, out)
    }

    fn open_saved(
        &mut self,
        known: Option<(&Secret, AxHeader)>,
        mac: &[u8; 16],
        encrypted_header: &[u8; 40],
        body: EncryptedBody<'_>,
        out: &mut [u8],
    ) -> Result<AxHeader, Error> {
        for index in 0..self.storage.skipped.len() {
            let Some(saved) = self.storage.skipped[index].value.as_ref() else {
                continue;
            };
            let header = if let Some((key, header)) = known {
                if !bool::from(key.ct_eq(&saved.header[..])) {
                    continue;
                }
                header
            } else {
                let Ok(header) = decrypt_header(&saved.header, mac, encrypted_header, body) else {
                    continue;
                };
                header
            };
            if header.sent != saved.number || header.ratchet_key != saved.ratchet {
                continue;
            }
            decrypt_body(&saved.message, body, out)?;
            self.context
                .statistics()
                .bytes(crate::statistics::Metric::DecryptedBytes, out.len());
            validate_plaintext(out)?;
            self.storage.skipped[index].clear();
            self.peer_confirmed = true;
            return Ok(header);
        }
        Err(if known.is_some() {
            Error::Replay
        } else {
            Error::Authentication
        })
    }

    fn open_live(
        &mut self,
        header: AxHeader,
        advanced: bool,
        body: EncryptedBody<'_>,
        out: &mut [u8],
    ) -> Result<AxHeader, Error> {
        let next_received = header.sent.checked_add(1).ok_or(Error::Overflow)?;
        let mut keys = self.keys.clone();
        let mut received = self.received;
        let mut remote = self.remote_ratchet;
        if advanced {
            if header.ratchet_key == *remote.as_bytes() {
                return Err(Error::Replay);
            }
            if header.previous_sent < received {
                return Err(Error::Replay);
            }
            if header.previous_sent > received {
                let old_header = keys::copy(keys.receive_header.as_ref().ok_or(Error::Malformed)?);
                self.stage_gap(
                    &mut keys,
                    &mut received,
                    header.previous_sent,
                    &old_header,
                    *remote.as_bytes(),
                )?;
            }
            let next_header = keys::copy(&keys.next_receive_header);
            remote = EcdhePublic::from_bytes(header.ratchet_key);
            let (root, following_header, chain) =
                keys::ratchet(&keys.root, &self.local_ratchet, remote)?;
            keys.root = root;
            keys.receive_header = Some(next_header);
            keys.next_receive_header = following_header;
            keys.receive_chain = Some(chain);
            received = 0;
        }
        let header_key = keys::copy(keys.receive_header.as_ref().ok_or(Error::NotReady)?);
        self.stage_gap(
            &mut keys,
            &mut received,
            header.sent,
            &header_key,
            *remote.as_bytes(),
        )?;
        let (message_key, next_chain) =
            keys::chain(keys.receive_chain.as_ref().ok_or(Error::NotReady)?)?;
        decrypt_body(&message_key, body, out)?;
        self.context
            .statistics()
            .bytes(crate::statistics::Metric::DecryptedBytes, out.len());
        validate_plaintext(out)?;
        keys.receive_chain = Some(next_chain);
        // Every staged key was preflighted against currently empty committed
        // slots. Exclusive slice borrows prevent changes before this infallible
        // transfer; no crypto or allocation can fail after the first commit.
        for (target, staged) in self
            .storage
            .skipped
            .iter_mut()
            .filter(|s| s.value.is_none())
            .zip(
                self.storage
                    .staging
                    .iter_mut()
                    .filter(|s| s.value.is_some()),
            )
        {
            target.value = staged.value.take();
        }
        self.keys = keys;
        self.received = next_received;
        self.remote_ratchet = remote;
        if advanced {
            self.ratchet_allowed = true;
        }
        self.peer_confirmed = true;
        Ok(header)
    }

    fn stage_gap(
        &mut self,
        keys: &mut Keys,
        received: &mut u32,
        target: u32,
        header: &Secret,
        ratchet: [u8; 32],
    ) -> Result<(), Error> {
        let gap = target.checked_sub(*received).ok_or(Error::Replay)?;
        if gap > self.limits.maximum_gap {
            return Err(Error::Capacity);
        }
        let staged = self
            .storage
            .staging
            .iter()
            .filter(|s| s.value.is_some())
            .count();
        let free = self
            .storage
            .skipped
            .iter()
            .filter(|s| s.value.is_none())
            .count();
        let available = free.checked_sub(staged).ok_or(Error::Capacity)?;
        let gap = usize::try_from(gap).map_err(|_| Error::Overflow)?;
        if gap > available {
            return Err(Error::Capacity);
        }
        let end = staged.checked_add(gap).ok_or(Error::Overflow)?;
        // Staging begins empty; each successful range is a contiguous prefix.
        // Index the next range once rather than repeatedly scanning all slots.
        let slots = self
            .storage
            .staging
            .get_mut(staged..end)
            .ok_or(Error::Capacity)?;
        for slot in slots {
            let (message, next) =
                keys::chain(keys.receive_chain.as_ref().ok_or(Error::Malformed)?)?;
            slot.value = Some(Skipped {
                header: keys::copy(header),
                message,
                ratchet,
                number: *received,
            });
            keys.receive_chain = Some(next);
            *received += 1;
        }
        Ok(())
    }
    fn clear_staging(&mut self) {
        for slot in self.storage.staging.iter_mut() {
            slot.clear();
        }
    }
}
impl Drop for Session<'_, '_> {
    fn drop(&mut self) {
        for slot in self.storage.skipped.iter_mut() {
            slot.clear();
        }
        self.clear_staging();
        if self.owns_lease {
            self.context.revoke();
        }
    }
}

fn decrypt_header(
    key: &Secret,
    mac: &[u8; 16],
    encrypted: &[u8; 40],
    body: EncryptedBody<'_>,
) -> Result<AxHeader, Error> {
    let nonce = keys::nonce(key)?;
    let mut plaintext = Zeroizing::new(*encrypted);
    xchacha20poly1305_open(key, &nonce, body.bytes(), plaintext.as_mut(), mac)?;
    AxHeader::decode(plaintext.as_ref())
}
fn decrypt_body(key: &Secret, body: EncryptedBody<'_>, output: &mut [u8]) -> Result<(), Error> {
    let nonce = keys::nonce(key)?;
    let mac: &[u8; 16] = body.mac().try_into().map_err(|_| Error::Malformed)?;
    output.copy_from_slice(body.ciphertext());
    xchacha20poly1305_open(key, &nonce, &[], output, mac)
}

fn validate_plaintext(output: &mut [u8]) -> Result<(), Error> {
    if let Err(error) = Frame::decode(output) {
        output.zeroize();
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
