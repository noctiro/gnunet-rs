use crate::{slots::Slots, *};
use alloc::{collections::VecDeque, vec::Vec};
use core::fmt;
use gnunet_messenger::{
    crypto::{AeadKey, EcdheSecret},
    wire::{self, envelope::Kind, profile::Profile},
};
use gnunet_types::Error as Fault;
use zeroize::Zeroizing;
/// Exclusive zeroizing ownership of original message or draft bytes. No Clone,
/// Hash or revealing Debug; native owners can transfer this without a copy.
pub struct OwnedBytes(Zeroizing<Vec<u8>>);
impl fmt::Debug for OwnedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedBytes([REDACTED])")
            .field("length", &self.0.len())
            .finish()
    }
}
impl OwnedBytes {
    /// Adopt exclusively owned sensitive storage. The caller must separately
    /// erase any other copies. This performs no crypto, native or file operation.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
    /// Copy once into fallibly allocated erased storage.
    pub fn copy_from(bytes: &[u8]) -> Result<Self, Error> {
        let mut v = Vec::new();
        v.try_reserve_exact(bytes.len())
            .map_err(|_| Fault::Capacity)?;
        v.extend_from_slice(bytes);
        Ok(Self(Zeroizing::new(v)))
    }
    /// Explicit original sensitive bytes, never an implicit diagnostic.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    /// Actual retained allocation, used by the owning core's memory accounting.
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}
/// Failed admission retains the original owned bytes for bounded caller retry.
pub struct RejectedInput {
    /// Actual original failure, without synthesized successful progress.
    pub error: Error,
    /// Exclusively owned original bytes retained for a bounded caller retry.
    pub input: OwnedBytes,
}
impl fmt::Debug for RejectedInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectedInput")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
/// Caller-port operation state. Written is only an actual complete local write;
/// active SEND has no invented wire ACK or remote delivery transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPhase {
    /// Original finite work is admitted but has not been taken.
    Prepared,
    /// Original work ownership was transferred to its actual provider.
    Taken,
    /// Actual original whole local write; no remote delivery ACK exists.
    Written,
    /// Actual original result or notification has completed this operation.
    Complete,
    /// The original owner has observed a physical cancellation.
    Cancelled,
    /// The original provider or source has actually failed.
    Failed,
}
/// Native operation purpose, using only actual active official message families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    /// Exact official MESSENGER IPC framing.
    Ipc,
    /// Exact official raw signed peer-message framing.
    PeerMessage,
}
/// Exact official operation family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePurpose {
    /// Actual connection CREATE.
    Create,
    /// Actual connection DESTROY.
    Destroy,
    /// Actual OPEN notification has been received.
    Open,
    /// Actual room ENTRY.
    Enter,
    /// Actual room CLOSE.
    Close,
    /// Actual room SYNC.
    Sync,
    /// Actual signed-message submission.
    Send,
    /// Actual message GET under its original hash.
    Get,
}
/// Internal original job binding. Its fields are immutable and issued by Core.
#[derive(Clone, Copy)]
pub struct Binding<'id> {
    pub(crate) operation: Operation<'id>,
    pub(crate) source: Source<'id>,
    pub(crate) member: Option<MemberSession<'id>>,
    pub(crate) message: Hash,
    pub(crate) epoch: Hash,
    pub(crate) identifier: ShortHash,
    pub(crate) epoch_revision: u64,
}
impl fmt::Debug for Binding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerBinding")
            .field("operation", &self.operation)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}
impl<'id> Binding<'id> {
    /// Original local operation generation.
    pub const fn operation(&self) -> Operation<'id> {
        self.operation
    }
    /// Original physical source generation.
    pub const fn source(&self) -> Source<'id> {
        self.source
    }
    /// Original member session, if this job has a member owner.
    pub const fn member(&self) -> Option<MemberSession<'id>> {
        self.member
    }
    /// Borrow one actual retained message or immutable deletion tombstone.
    pub const fn message(&self) -> &Hash {
        &self.message
    }
    /// Exact original epoch hash; its presence alone grants no authority.
    pub const fn epoch(&self) -> &Hash {
        &self.epoch
    }
    /// Exact original group identifier; no key material is exposed.
    pub const fn identifier(&self) -> &ShortHash {
        &self.identifier
    }
}
/// Owned immutable diagnostic copy of one original binding. It cannot admit a
/// callback, select an operation or reconstruct any live source/member handle.
#[derive(Clone, Copy)]
pub struct BindingObservation {
    operation: HandleObservation,
    source: HandleObservation,
    member: Option<HandleObservation>,
    message: Hash,
    epoch: Hash,
    identifier: ShortHash,
    epoch_revision: u64,
}
impl fmt::Debug for BindingObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerBindingObservation([REDACTED], diagnostic only)")
            .field("operation", &self.operation)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}
impl BindingObservation {
    /// Original operation coordinates without current authority.
    pub const fn operation(self) -> HandleObservation {
        self.operation
    }
    /// Original source coordinates without current authority.
    pub const fn source(self) -> HandleObservation {
        self.source
    }
    /// Original member coordinates without current authority.
    pub const fn member(self) -> Option<HandleObservation> {
        self.member
    }
    /// Original retained message hash; not a current callback capability.
    pub const fn message(&self) -> &Hash {
        &self.message
    }
    /// Original retained epoch hash, not epoch membership.
    pub const fn epoch(&self) -> &Hash {
        &self.epoch
    }
    /// Original raw identifier, not key possession.
    pub const fn identifier(&self) -> &ShortHash {
        &self.identifier
    }
    /// Original checked revision observed for this binding.
    pub const fn epoch_revision(self) -> u64 {
        self.epoch_revision
    }
}
impl Binding<'_> {
    /// Preserve original binding diagnostics independently of the live owner.
    pub fn observation(self) -> BindingObservation {
        BindingObservation {
            operation: self.operation.observation(),
            source: self.source.observation(),
            member: self.member.map(MemberSession::observation),
            message: self.message,
            epoch: self.epoch,
            identifier: self.identifier,
            epoch_revision: self.epoch_revision,
        }
    }
}
/// Actual mutation observations, emitted after the corresponding in-memory
/// transition. Flags summarize changes and never replace the retained tables.
#[derive(Clone, Copy)]
pub enum Event<'id> {
    /// An actual original source generation was attached.
    SourceAttached(Source<'id>),
    /// An original source was physically stopped.
    SourceLost(Source<'id>),
    /// An actual room lifecycle transition occurred.
    RoomChanged(Room<'id>, RoomPhase),
    /// An actual member-session transition occurred.
    MemberChanged(MemberSession<'id>, SessionPhase),
    /// An actual contact key/name transition occurred.
    ContactChanged(Contact<'id>),
    /// An actual original message transition occurred.
    MessageChanged(Room<'id>, Hash, MessagePhase),
    /// No admitted key capability is present.
    Missing(Room<'id>, Hash),
    /// An actual member-lineage discourse interval changed.
    SubscriptionChanged(Room<'id>, Contact<'id>, ShortHash),
    /// An actual immutable membership snapshot became available.
    EpochChanged(Room<'id>, Hash),
    /// An actual epoch/group key state changed.
    KeyChanged(Room<'id>, Hash, ShortHash, KeyPhase),
    /// An original local operation changed phase.
    OperationChanged(Operation<'id>, OperationPhase),
    /// Actual protocol, authorization or cryptographic failure.
    Rejected(Room<'id>, Hash, Error),
    /// Actual scoped provider failure, preserving its entire original binding.
    ProviderFailed(Binding<'id>, Error),
}
impl fmt::Debug for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::SourceAttached(_) => "SourceAttached",
            Self::SourceLost(_) => "SourceLost",
            Self::RoomChanged(..) => "RoomChanged",
            Self::MemberChanged(..) => "MemberChanged",
            Self::ContactChanged(_) => "ContactChanged",
            Self::MessageChanged(..) => "MessageChanged",
            Self::Missing(..) => "Missing",
            Self::SubscriptionChanged(..) => "SubscriptionChanged",
            Self::EpochChanged(..) => "EpochChanged",
            Self::KeyChanged(..) => "KeyChanged",
            Self::OperationChanged(..) => "OperationChanged",
            Self::Rejected(..) => "Rejected",
            Self::ProviderFailed(..) => "ProviderFailed",
        };
        f.debug_tuple("MessengerEvent([REDACTED])")
            .field(&kind)
            .finish()
    }
}
/// Owned diagnostic event, preserving original observations after the live
/// owner ends. Its snapshots cannot be passed to any Core authority API.
#[derive(Clone, Copy)]
pub enum EventObservation {
    /// An actual original source generation was attached.
    SourceAttached(HandleObservation),
    /// An original source was physically stopped.
    SourceLost(HandleObservation),
    /// An actual room lifecycle transition occurred.
    RoomChanged(HandleObservation, RoomPhase),
    /// An actual member-session transition occurred.
    MemberChanged(HandleObservation, SessionPhase),
    /// An actual contact key/name transition occurred.
    ContactChanged(HandleObservation),
    /// An actual original message transition occurred.
    MessageChanged(HandleObservation, Hash, MessagePhase),
    /// No admitted key capability is present.
    Missing(HandleObservation, Hash),
    /// An actual member-lineage discourse interval changed.
    SubscriptionChanged(HandleObservation, HandleObservation, ShortHash),
    /// An actual immutable membership snapshot became available.
    EpochChanged(HandleObservation, Hash),
    /// An actual epoch/group key state changed.
    KeyChanged(HandleObservation, Hash, ShortHash, KeyPhase),
    /// An original local operation changed phase.
    OperationChanged(HandleObservation, OperationPhase),
    /// Actual protocol, authorization or cryptographic failure.
    Rejected(HandleObservation, Hash, Error),
    /// Actual scoped provider failure, preserving its entire original binding.
    ProviderFailed(BindingObservation, Error),
}
impl fmt::Debug for EventObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::SourceAttached(_) => "SourceAttached",
            Self::SourceLost(_) => "SourceLost",
            Self::RoomChanged(..) => "RoomChanged",
            Self::MemberChanged(..) => "MemberChanged",
            Self::ContactChanged(_) => "ContactChanged",
            Self::MessageChanged(..) => "MessageChanged",
            Self::Missing(..) => "Missing",
            Self::SubscriptionChanged(..) => "SubscriptionChanged",
            Self::EpochChanged(..) => "EpochChanged",
            Self::KeyChanged(..) => "KeyChanged",
            Self::OperationChanged(..) => "OperationChanged",
            Self::Rejected(..) => "Rejected",
            Self::ProviderFailed(..) => "ProviderFailed",
        };
        f.debug_tuple("MessengerEvent([REDACTED])")
            .field(&kind)
            .finish()
    }
}
impl Event<'_> {
    /// Preserve this original event and errors without retaining live authority.
    pub fn observation(self) -> EventObservation {
        match self {
            Self::SourceAttached(s) => EventObservation::SourceAttached(s.observation()),
            Self::SourceLost(s) => EventObservation::SourceLost(s.observation()),
            Self::RoomChanged(r, p) => EventObservation::RoomChanged(r.observation(), p),
            Self::MemberChanged(m, p) => EventObservation::MemberChanged(m.observation(), p),
            Self::ContactChanged(c) => EventObservation::ContactChanged(c.observation()),
            Self::MessageChanged(r, h, p) => {
                EventObservation::MessageChanged(r.observation(), h, p)
            }
            Self::Missing(r, h) => EventObservation::Missing(r.observation(), h),
            Self::SubscriptionChanged(r, c, d) => {
                EventObservation::SubscriptionChanged(r.observation(), c.observation(), d)
            }
            Self::EpochChanged(r, h) => EventObservation::EpochChanged(r.observation(), h),
            Self::KeyChanged(r, h, i, p) => EventObservation::KeyChanged(r.observation(), h, i, p),
            Self::OperationChanged(o, p) => EventObservation::OperationChanged(o.observation(), p),
            Self::Rejected(r, h, e) => EventObservation::Rejected(r.observation(), h, e),
            Self::ProviderFailed(b, e) => EventObservation::ProviderFailed(b.observation(), e),
        }
    }
}
pub(crate) struct ContactRow {
    /// Original key value.
    pub key: PublicKey,
    /// Original name value.
    pub name: Option<OwnedBytes>,
    /// Original anonymous context value.
    pub anonymous_context: Option<Hash>,
    /// Original local value.
    pub local: bool,
    /// Original canonical value.
    pub canonical: bool,
    /// Maximum live room generations.
    pub rooms: usize,
}
pub(crate) struct SessionRow<'id> {
    /// Original contact value.
    pub contact: Contact<'id>,
    /// Original id value.
    pub id: ShortHash,
    /// Original authorized public signing key; no secret key is returned.
    pub public: PublicKey,
    /// Original hpke value.
    pub hpke: PublicKey,
    /// Original lineage value.
    pub lineage: u64,
    /// Original generation value.
    pub generation: u64,
    /// Original known from value.
    pub known_from: u64,
    /// Original phase value.
    pub phase: SessionPhase,
    /// Original first bound value.
    pub first_bound: Hash,
    /// Original last bound value.
    pub last_bound: Hash,
    /// Original successor value.
    pub successor: Option<Slot>,
    /// Original completed at value.
    pub completed_at: Option<u64>,
    /// Restored history is not a current authenticated session.
    pub archived: bool,
    /// Actual phase accepted in the committed historical image.
    pub historical_phase: SessionPhase,
}
impl<'id> SessionRow<'id> {
    /// Historical closing ancestry can finish without restoring a live member.
    pub(crate) fn needs_completion(&self) -> bool {
        self.phase == SessionPhase::Closing
            || self.archived && self.historical_phase == SessionPhase::Closing
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Owner<'id> {
    /// Original contact value.
    pub contact: Contact<'id>,
    /// Original lineage value.
    pub lineage: u64,
    /// Original generation value.
    pub generation: u64,
}
#[derive(Clone, Copy)]
pub(crate) enum RecipientKeyOrigin<'id> {
    Member {
        owner: Owner<'id>,
        public: PublicKey,
    },
    Zone(PublicKey),
    Ambiguous,
}
pub(crate) struct RecipientKey<'id> {
    pub secret: EcdheSecret,
    pub origin: RecipientKeyOrigin<'id>,
}
#[derive(Clone, Copy)]
pub(crate) struct Authentication<'id> {
    /// Original owner value.
    pub owner: Option<Owner<'id>>,
    /// Original session value.
    pub session: Option<Slot>,
    /// Original authorized public signing key; no secret key is returned.
    pub public: PublicKey,
    /// Original peer value.
    pub peer: Option<[u8; 32]>,
}
pub(crate) struct Node<'id> {
    /// Original hash value.
    pub hash: Hash,
    /// Original origin value.
    pub origin: MessageOrigin<'id>,
    /// Actual original accepted owner facts, retained after physical retirement.
    pub provenance: SourceObservation,
    /// Actual new signature is accepted but historical scope is not yet rebound.
    pub resume_pending: bool,
    /// Original meta value.
    pub meta: ReceiveMeta,
    /// Original phase value.
    pub phase: MessagePhase,
    /// Original exclusively owned zeroizing encoded frame.
    pub frame: Option<OwnedBytes>,
    /// Original plaintext value.
    pub plaintext: Option<OwnedBytes>,
    /// Original auth value.
    pub auth: Option<Authentication<'id>>,
    /// Original padding value.
    pub padding: wire::padding::Decode,
    /// Original signed body layout and separately declared outer encoder.
    pub layout: OriginalLayout,
    /// Immutable declared producer of the actual encrypted/transcript short.
    pub cipher_layout: Option<ShortLayout>,
    /// Producer of installed plaintext, which can come from a bound TRANSCRIPT.
    pub plain_layout: Option<ShortLayout>,
    /// Original inner short carried by a TRANSCRIPT inside this message.
    pub transcript_layout: Option<ShortLayout>,
    /// Optional original creator order for a newly introduced identifier.
    pub identifier_order: Option<wire::profile::Endian>,
    /// Original plain padding value.
    pub plain_padding: wire::padding::Decode,
    /// Original semantic applied value.
    pub semantic_applied: bool,
    /// Original complete value.
    pub complete: bool,
    /// Original parents value.
    pub parents: [Hash; 2],
    /// Original references value.
    pub references: [Hash; 3],
    /// Original frontier applied value.
    pub frontier_applied: bool,
    /// Original epoch value.
    pub epoch: Hash,
    /// Actual authenticated SERVICE first-write epoch indexing was applied.
    pub epoch_indexed: bool,
    /// Actual official body kind to sign.
    pub kind: Kind,
    /// Original semantic kind value.
    pub semantic_kind: Kind,
    /// Original absolute microsecond signing timestamp.
    pub timestamp: u64,
    /// Original sequence value.
    pub sequence: u64,
    /// Original queued value.
    pub queued: bool,
    /// Original requested value.
    pub requested: bool,
    /// Original delete at value.
    pub delete_at: Option<u64>,
    /// Original deleted by value.
    pub deleted_by: Option<Hash>,
    /// Original discourse value.
    pub discourse: Option<ShortHash>,
    /// Original local sent value.
    pub local_sent: bool,
    /// Original transcript value.
    pub transcript: Option<Hash>,
    /// Original private recipient value.
    pub private_recipient: Option<PublicKey>,
    /// Actual recipient-key/own-intent association, never the sender owner.
    pub recipient: Option<RecipientAttribution<'id>>,
    /// Original visit value.
    pub visit: u64,
}
impl<'id> Node<'id> {
    /// Return the original input allocation on rejected insertion; remaining
    /// temporary node state drops normally without boxing a large error value.
    pub(crate) fn into_original(mut self) -> OwnedBytes {
        self.frame
            .take()
            .unwrap_or_else(|| OwnedBytes::new(Zeroizing::new(Vec::new())))
    }

    /// Actual payload bytes observation or bounded operation.
    pub fn payload_bytes(&self) -> usize {
        self.frame.as_ref().map_or(0, OwnedBytes::capacity)
            + self.plaintext.as_ref().map_or(0, OwnedBytes::capacity)
    }
    /// Borrow one actual retained message or immutable deletion tombstone.
    pub fn message(&self, _profile: Profile) -> Result<wire::message::Message<'_>, Error> {
        Ok(wire::message::Message::decode_with_profiles(
            self.frame.as_ref().ok_or(Fault::NotReady)?.expose(),
            self.layout.body_profile(self.kind)?,
            self.layout.padding,
            self.padding,
        )?)
    }
    /// Borrow actual typed original or authenticated decrypted content.
    pub fn body(&self, _profile: Profile) -> Result<wire::body::Body<'_>, Error> {
        if let Some(plain) = &self.plaintext {
            Ok(wire::message::Short::decode_with_profiles(
                plain.expose(),
                self.plain_layout.ok_or(Fault::NotReady)?.body,
                self.plain_layout.ok_or(Fault::NotReady)?.padding,
                self.plain_padding,
            )?
            .body())
        } else {
            Ok(self.message(_profile)?.body())
        }
    }
}
pub(crate) struct SourceRow {
    /// Original role value.
    pub role: SourceRole,
    /// Original attached value.
    pub attached: bool,
    /// Original padding value.
    pub padding: wire::padding::Decode,
    /// Original create written value.
    pub create_written: bool,
    /// Original authorized public signing key; no secret key is returned.
    pub public: Option<PublicKey>,
    /// Original member id value.
    pub member_id: Option<ShortHash>,
    /// Original pending member id value.
    pub pending_member_id: Option<ShortHash>,
    /// Original join required value.
    pub join_required: bool,
}
pub(crate) struct PeerRow {
    /// Original peer value.
    pub peer: [u8; 32],
    /// Original announced value.
    pub announced: bool,
    /// Retained signed PEER candidate, never a current announcement or source.
    pub historical_candidate: bool,
    /// Original connection amount value.
    pub connection_amount: u32,
    /// Original connection flags value.
    pub connection_flags: u32,
}
pub(crate) struct Subscription<'id> {
    /// Original contact value.
    pub contact: Contact<'id>,
    /// Original discourse value.
    pub discourse: ShortHash,
    /// Original lineage value.
    pub lineage: u64,
    /// Original start value.
    pub start: u64,
    /// Original end value.
    pub end: u64,
    /// Original keep alive value.
    pub keep_alive: bool,
    /// Original duration value.
    pub duration: u64,
    /// Original renew at value.
    pub renew_at: Option<u64>,
    /// Original renew operation value.
    pub renew_operation: Option<Slot>,
}
pub(crate) struct Confirmation<'id> {
    /// Original contact value.
    pub contact: Contact<'id>,
    /// Original message value.
    pub message: Hash,
    /// Original verified mac value.
    pub verified_mac: bool,
}
pub(crate) struct GroupRow<'id> {
    /// Original identifier value.
    pub identifier: ShortHash,
    /// Immutable native bitfield creator order; later authors do not replace it.
    pub identifier_order: wire::profile::Endian,
    /// Original target value.
    pub target: usize,
    /// Original valid value.
    pub valid: bool,
    /// Original phase value.
    pub phase: KeyPhase,
    /// Original key value.
    pub key: Option<AeadKey>,
    /// Original confirmations value.
    pub confirmations: Vec<Confirmation<'id>>,
    /// Original expires value.
    pub expires: u64,
    /// Original appeal value.
    pub appeal: Option<Hash>,
    pub appeal_until: u64,
    /// Original proposal value.
    pub proposal: Option<Hash>,
    /// Original generation value.
    pub generation: u64,
    /// Original derived from value.
    pub derived_from: Option<(Hash, ShortHash)>,
}
pub(crate) struct EpochRow<'id> {
    /// Original hash value.
    pub hash: Hash,
    /// Original parents value.
    pub parents: [Hash; 2],
    /// Original mutation value.
    pub mutation: crate::epoch::EpochMutation<'id>,
    /// Original members value.
    pub members: Vec<Contact<'id>>,
    /// Original complete value.
    pub complete: bool,
    /// Original groups value.
    pub groups: Slots<GroupRow<'id>>,
    /// Original nonces value.
    pub nonces: Vec<crate::epoch::Nonce>,
    /// Original revision value.
    pub revision: u64,
    /// Original ephemeral value.
    pub ephemeral: Option<EcdheSecret>,
    /// Original ephemeral until value.
    pub ephemeral_until: u64,
    /// Original best announcement value.
    pub best_announcement: Option<Slot>,
    /// Original best group value.
    pub best_group: Option<Slot>,
}
pub(crate) struct MissingRow<'id> {
    /// Original hash value.
    pub hash: Hash,
    /// Original source value.
    pub source: Source<'id>,
    /// Original operation value.
    pub operation: Option<Slot>,
    /// Original retry at value.
    pub retry_at: u64,
    /// Original absent value.
    pub absent: bool,
}
pub(crate) enum Job {
    Wire {
        purpose: NativePurpose,
        frame: Option<OwnedBytes>,
        length: usize,
        encoding: Encoding,
    },
    Sign {
        body: OwnedBytes,
        kind: Kind,
        public: PublicKey,
        sender: ShortHash,
        previous: Hash,
        timestamp: u64,
    },
    SharedKey,
    EpochRecord {
        public: PublicKey,
    },
    EphemeralKey {
        valid_until: u64,
    },
}
pub(crate) struct OperationRow<'id> {
    /// Immutable original operation/source/member/message scope.
    pub binding: Binding<'id>,
    /// Immutable original recipient for a real locally prepared PRIVATE send.
    pub recipient: Option<RecipientAttribution<'id>>,
    /// Original job value.
    pub job: Job,
    /// Original phase value.
    pub phase: OperationPhase,
    /// Original deadline value.
    pub deadline: u64,
    /// Original written value.
    pub written: usize,
    /// Original charged bytes value.
    pub charged_bytes: usize,
}
/// Fixed bounded hash index; original first-write value survives late nodes.
pub(crate) struct EpochAlias {
    pub key: Hash,
    pub epoch: Hash,
}
pub(crate) struct RoomRow<'id> {
    /// Original key value.
    pub key: Hash,
    /// Explicit room-capability bitfield producer profile.
    pub profile: Profile,
    /// Original phase value.
    pub phase: RoomPhase,
    /// Original local public value.
    pub local_public: Option<PublicKey>,
    /// Original local id value.
    pub local_id: Option<ShortHash>,
    /// Original joined value.
    pub joined: bool,
    /// Original current epoch value.
    pub current_epoch: Hash,
    pub sync_phase: Option<RoomPhase>,
    /// Original last message value.
    pub last_message: Hash,
    /// Original sources value.
    pub sources: Slots<SourceRow>,
    /// Original sessions value.
    pub sessions: Slots<SessionRow<'id>>,
    /// Original nodes value.
    pub nodes: Slots<Node<'id>>,
    /// Original index value.
    pub index: Vec<Slot>,
    /// Original frontier value.
    pub frontier: Vec<Hash>,
    /// SERVICE-only lazily admitted fixed alias buckets, charged before publish.
    pub epoch_aliases: Vec<Option<EpochAlias>>,
    /// Number of occupied first-write buckets.
    pub epoch_alias_count: usize,
    /// Original ready value.
    pub ready: VecDeque<Slot>,
    /// Original epochs value.
    pub epochs: Slots<EpochRow<'id>>,
    /// Original subscriptions value.
    pub subscriptions: Slots<Subscription<'id>>,
    /// Original operations value.
    pub operations: Slots<OperationRow<'id>>,
    /// Original missing value.
    pub missing: Slots<MissingRow<'id>>,
    /// Original peers value.
    pub peers: Vec<PeerRow>,
    /// Original hpke keys value.
    pub hpke_keys: Vec<RecipientKey<'id>>,
    /// Original sequence value.
    pub sequence: u64,
    /// Original lineage value.
    pub lineage: u64,
    /// Original visit value.
    pub visit: u64,
    /// Original private value.
    pub private: bool,
    /// Original group room value.
    pub group_room: bool,
    /// Original feed value.
    pub feed: bool,
    /// Original completion queue value.
    pub completion_queue: VecDeque<Slot>,
    /// Original completion stack value.
    pub completion_stack: Vec<Slot>,
    /// Original completion session value.
    pub completion_session: Option<Slot>,
    /// Original completion target value.
    pub completion_target: Hash,
}
impl<'id> RoomRow<'id> {
    /// Construct finite caller-owned state without hidden native I/O.
    pub fn new(
        key: Hash,
        public: Option<PublicKey>,
        limits: Limits,
        profile: Profile,
    ) -> Result<Self, Error> {
        let mut index = Vec::new();
        index
            .try_reserve_exact(limits.messages_per_room)
            .map_err(|_| Fault::Capacity)?;
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(limits.messages_per_room)
            .map_err(|_| Fault::Capacity)?;
        let mut ready = VecDeque::new();
        ready
            .try_reserve_exact(limits.messages_per_room)
            .map_err(|_| Fault::Capacity)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.sources_per_room)
            .map_err(|_| Fault::Capacity)?;
        let mut hpke_keys = Vec::new();
        hpke_keys
            .try_reserve_exact(limits.sessions_per_room)
            .map_err(|_| Fault::Capacity)?;
        let mut completion_queue = VecDeque::new();
        completion_queue
            .try_reserve_exact(limits.sessions_per_room)
            .map_err(|_| Fault::Capacity)?;
        let mut completion_stack = Vec::new();
        completion_stack
            .try_reserve_exact(limits.messages_per_room)
            .map_err(|_| Fault::Capacity)?;
        let bits = match profile.endian {
            wire::profile::Endian::Little => key[0],
            wire::profile::Endian::Big => key[0].reverse_bits(),
        };
        Ok(Self {
            key,
            profile,
            phase: RoomPhase::Detached,
            local_public: public,
            local_id: None,
            joined: false,
            current_epoch: [0; 64],
            sync_phase: None,
            last_message: [0; 64],
            sources: Slots::new(limits.sources_per_room)?,
            sessions: Slots::new(limits.sessions_per_room)?,
            nodes: Slots::new(limits.messages_per_room)?,
            index,
            frontier,
            epoch_aliases: Vec::new(),
            epoch_alias_count: 0,
            ready,
            epochs: Slots::new(limits.epochs_per_room)?,
            subscriptions: Slots::new(limits.subscriptions_per_room)?,
            operations: Slots::new(limits.operations_per_room)?,
            missing: Slots::new(limits.missing_per_room)?,
            peers,
            hpke_keys,
            sequence: 0,
            lineage: 0,
            visit: 0,
            private: bits & 1 == 0,
            group_room: bits & 2 != 0,
            feed: bits & 4 != 0,
            completion_queue,
            completion_stack,
            completion_session: None,
            completion_target: [0; 64],
        })
    }
    /// Actual metadata bytes observation or bounded operation.
    pub fn metadata_bytes(&self) -> Result<usize, Error> {
        let fixed = [
            self.sources.bytes()?,
            self.sessions.bytes()?,
            self.nodes.bytes()?,
            self.epochs.bytes()?,
            self.subscriptions.bytes()?,
            self.operations.bytes()?,
            self.missing.bytes()?,
        ];
        let mut bytes = fixed
            .into_iter()
            .try_fold(0usize, |a, b| a.checked_add(b).ok_or(Fault::Overflow))?;
        for (capacity, width) in [
            (self.index.capacity(), core::mem::size_of::<Slot>()),
            (self.frontier.capacity(), 64),
            (
                self.epoch_aliases.capacity(),
                core::mem::size_of::<Option<EpochAlias>>(),
            ),
            (self.ready.capacity(), core::mem::size_of::<Slot>()),
            (self.peers.capacity(), core::mem::size_of::<PeerRow>()),
            (
                self.hpke_keys.capacity(),
                core::mem::size_of::<RecipientKey<'id>>(),
            ),
            (
                self.completion_queue.capacity(),
                core::mem::size_of::<Slot>(),
            ),
            (
                self.completion_stack.capacity(),
                core::mem::size_of::<Slot>(),
            ),
        ] {
            bytes = bytes
                .checked_add(capacity.checked_mul(width).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
        }
        Ok(bytes)
    }
    /// Actual find node observation or bounded operation.
    pub fn find_node(&self, hash: &Hash) -> Option<Slot> {
        self.index
            .binary_search_by(|slot| {
                self.nodes
                    .get(*slot)
                    .map_or(core::cmp::Ordering::Less, |n| n.hash.cmp(hash))
            })
            .ok()
            .map(|i| self.index[i])
    }
    /// Actual find epoch observation or bounded operation.
    pub fn find_epoch(&self, hash: &Hash) -> Option<Slot> {
        self.epochs
            .iter()
            .find_map(|(s, e)| (e.hash == *hash).then_some(s))
    }
    /// Actual local session observation or bounded operation.
    pub fn local_session(&self) -> Option<Slot> {
        self.sessions.iter().find_map(|(s, m)| {
            (Some(m.id) == self.local_id
                && Some(m.public) == self.local_public
                && m.phase == SessionPhase::Active)
                .then_some(s)
        })
    }
    /// Actual insert node observation or bounded operation.
    pub fn insert_node(&mut self, node: Node<'id>) -> Result<Slot, RejectedInput> {
        let position = match self.index.binary_search_by(|s| {
            self.nodes
                .get(*s)
                .map_or(core::cmp::Ordering::Less, |n| n.hash.cmp(&node.hash))
        }) {
            Ok(_) => {
                return Err(RejectedInput {
                    error: Fault::Conflict.into(),
                    input: node.into_original(),
                });
            }
            Err(i) => i,
        };
        let slot = self
            .nodes
            .insert(node)
            .map_err(|(error, node)| RejectedInput {
                error,
                input: node.into_original(),
            })?;
        self.index.insert(position, slot);
        Ok(slot)
    }
}
impl<'id> RoomRow<'id> {
    /// Actual required bytes observation or bounded operation.
    pub fn required_bytes(l: Limits) -> Result<usize, Error> {
        let tables = [
            Slots::<SourceRow>::required_bytes(l.sources_per_room)?,
            Slots::<SessionRow<'id>>::required_bytes(l.sessions_per_room)?,
            Slots::<Node<'id>>::required_bytes(l.messages_per_room)?,
            Slots::<EpochRow<'id>>::required_bytes(l.epochs_per_room)?,
            Slots::<Subscription<'id>>::required_bytes(l.subscriptions_per_room)?,
            Slots::<OperationRow<'id>>::required_bytes(l.operations_per_room)?,
            Slots::<MissingRow<'id>>::required_bytes(l.missing_per_room)?,
        ];
        let mut n = tables
            .into_iter()
            .try_fold(0usize, |a, b| a.checked_add(b).ok_or(Fault::Overflow))?;
        for (count, width) in [
            (l.messages_per_room, core::mem::size_of::<Slot>() * 3 + 64),
            (l.sources_per_room, core::mem::size_of::<PeerRow>()),
            (
                l.sessions_per_room,
                core::mem::size_of::<RecipientKey<'id>>() + core::mem::size_of::<Slot>(),
            ),
        ] {
            n = n
                .checked_add(count.checked_mul(width).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
        }
        Ok(n)
    }
    /// Actual retained bytes observation or bounded operation.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let mut n = self.metadata_bytes()?;
        for (_, node) in self.nodes.iter() {
            n = n.checked_add(node.payload_bytes()).ok_or(Fault::Overflow)?;
        }
        for (_, op) in self.operations.iter() {
            n = n.checked_add(op.charged_bytes).ok_or(Fault::Overflow)?;
        }
        for (_, e) in self.epochs.iter() {
            n = n
                .checked_add(
                    e.members
                        .capacity()
                        .checked_mul(core::mem::size_of::<Contact<'id>>())
                        .ok_or(Fault::Overflow)?,
                )
                .and_then(|n| {
                    e.nonces
                        .capacity()
                        .checked_mul(core::mem::size_of::<crate::epoch::Nonce>())
                        .and_then(|b| n.checked_add(b))
                })
                .and_then(|n| e.groups.bytes().ok().and_then(|b| n.checked_add(b)))
                .ok_or(Fault::Overflow)?;
            for (_, g) in e.groups.iter() {
                n = n
                    .checked_add(
                        g.confirmations
                            .capacity()
                            .checked_mul(core::mem::size_of::<Confirmation<'id>>())
                            .ok_or(Fault::Overflow)?,
                    )
                    .ok_or(Fault::Overflow)?;
            }
        }
        Ok(n)
    }
}
