use crate::{
    archive::ArchiveOriginalRange,
    epoch::members::{MemberArena, Snapshot},
    room_history::{HistoryIndex, HistoryNodeCell, HistoryNodes, HistoryQueue, RoomHistory},
    room_queues::RoomQueues,
    room_storage::{FixedRoomCapacities, RoomPartition, RoomParts},
    room_tables::{
        EpochCell, MissingCell, OperationCell, RoomTable, RoomTables, SessionCell, SourceCell,
        SubscriptionCell,
    },
    *,
};
use core::{fmt, num::NonZeroU64};
use gnunet_messenger::wire::{self, envelope::Kind, profile::Profile};
use gnunet_types::Error as Fault;
#[cfg(feature = "alloc")]
use {
    crate::{recipient::MemberRecipient, slots::Slots},
    alloc::vec::Vec,
    gnunet_messenger::crypto::{AeadKey, EcdhePublic, EcdheSecret},
};

mod alias_storage;
pub(crate) use alias_storage::AliasBuckets;
pub use alias_storage::EpochAliasCell;
mod contact_table;
pub use contact_table::ContactCell;
pub(crate) use contact_table::ContactTable;
mod event;
pub(crate) use event::QueuedEvent;
mod event_queue;
pub use event_queue::EventCell;
pub(crate) use event_queue::EventQueue;
mod signer_table;
pub(crate) use signer_table::SignerTable;
mod frames;
pub(crate) use frames::{ByteStore, FrameStore, IncomingFrame, RetainedFrame};
#[cfg(feature = "alloc")]
mod payload;
#[cfg(feature = "alloc")]
pub(crate) use payload::Plaintext;

/// Failed admission retains the original owned bytes for bounded caller retry.
#[cfg(feature = "alloc")]
pub struct RejectedInput {
    /// Actual original failure, without synthesized successful progress.
    pub error: Error,
    /// Exclusively owned original bytes retained for a bounded caller retry.
    pub input: OwnedBytes,
}
#[cfg(feature = "alloc")]
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
/// Original job authority issued by Core with its exact room and instance.
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
    /// Project coordinates after the owner validates the branded handles.
    pub(crate) const fn coordinates(self) -> OperationBinding {
        OperationBinding {
            source: self.source.slot,
            member: match self.member {
                Some(member) => Some(member.slot),
                None => None,
            },
            message: self.message,
            epoch: self.epoch,
            identifier: self.identifier,
            epoch_revision: self.epoch_revision,
        }
    }

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
    /// A newly accepted remote `MISS` was applied in service mode. Requested
    /// history, archive replays and local signatures do not emit this event.
    ServicePeerMiss {
        /// Original room generation in which the report was applied.
        room: Room<'id>,
        /// Current signed `PEER` announcements immediately before application.
        members_before: usize,
    },
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
            Self::ServicePeerMiss { .. } => "ServicePeerMiss",
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
    /// A newly accepted remote `MISS` was applied in service mode.
    ServicePeerMiss {
        /// Snapshot of the original room generation.
        room: HandleObservation,
        /// Current signed `PEER` announcements immediately before application.
        members_before: usize,
    },
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
            Self::ServicePeerMiss { .. } => "ServicePeerMiss",
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
            Self::ServicePeerMiss {
                room,
                members_before,
            } => EventObservation::ServicePeerMiss {
                room: room.observation(),
                members_before,
            },
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
    pub name: Option<RetainedFrame>,
    /// Original anonymous context value.
    pub anonymous_context: Option<Hash>,
    /// Original local value.
    #[cfg(feature = "alloc")]
    pub local: bool,
    /// Original canonical value.
    pub canonical: bool,
    /// Maximum live room generations.
    pub rooms: usize,
}
pub(crate) struct SessionRow {
    /// Exact original contact slot generation.
    pub contact: Slot,
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
impl SessionRow {
    pub(crate) fn has_live_authority(&self) -> bool {
        !self.archived && matches!(self.phase, SessionPhase::Active | SessionPhase::Closing)
    }

    /// Historical closing ancestry can finish without restoring a live member.
    pub(crate) fn needs_completion(&self) -> bool {
        self.phase == SessionPhase::Closing
            || self.archived && self.historical_phase == SessionPhase::Closing
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Owner {
    /// Exact original contact slot generation.
    pub contact: Slot,
    /// Original lineage value.
    pub lineage: u64,
    /// Original generation value.
    pub generation: u64,
}
#[derive(Clone, Copy)]
#[cfg(feature = "alloc")]
pub(crate) enum RecipientKeyOrigin {
    Member(MemberRecipient),
    Zone(PublicKey),
    Ambiguous,
}
#[cfg(feature = "alloc")]
pub(crate) struct RecipientKey {
    pub secret: EcdheSecret,
    pub origin: RecipientKeyOrigin,
}
#[derive(Clone, Copy)]
pub(crate) struct Authentication {
    /// Original owner value.
    pub owner: Option<Owner>,
    /// Original session value.
    pub session: Option<Slot>,
    /// Original authorized public signing key; no secret key is returned.
    pub public: PublicKey,
    /// Original peer value.
    pub peer: Option<[u8; 32]>,
}

/// One original source observation. Coordinates captured from live ingress can
/// recover their brand; restored coordinates remain historical.
pub(crate) struct NodeOrigin {
    provenance: SourceObservation,
    custody: OriginCustody,
}

#[derive(Clone, Copy)]
enum OriginCustody {
    FirstReceived,
    Archived(ArchivedFact),
    Reattached,
}

impl NodeOrigin {
    pub(crate) const fn from_source(source: Source<'_>, role: SourceRole) -> Self {
        Self {
            provenance: SourceObservation {
                room: source.room,
                source: source.slot,
                role,
            },
            custody: OriginCustody::FirstReceived,
        }
    }

    pub(crate) const fn archived(fact: ArchivedFact, provenance: SourceObservation) -> Self {
        Self {
            provenance,
            custody: OriginCustody::Archived(fact),
        }
    }

    /// Replace the physical owner while preserving whether this original was
    /// already accepted before recovery.
    pub(crate) fn with_source(&self, source: Source<'_>, role: SourceRole) -> Self {
        let mut next = Self::from_source(source, role);
        if !self.is_first_received() {
            next.custody = OriginCustody::Reattached;
        }
        next
    }

    pub(crate) const fn provenance(&self) -> SourceObservation {
        self.provenance
    }

    pub(crate) const fn is_archived(&self) -> bool {
        matches!(self.custody, OriginCustody::Archived(_))
    }

    pub(crate) const fn is_first_received(&self) -> bool {
        matches!(self.custody, OriginCustody::FirstReceived)
    }

    pub(crate) const fn view<'id>(&self, brand: Brand<'id>) -> MessageOrigin<'id> {
        match self.custody {
            OriginCustody::Archived(fact) => MessageOrigin::Archived(fact),
            OriginCustody::FirstReceived | OriginCustody::Reattached => {
                MessageOrigin::Live(Source {
                    core: brand,
                    room: self.provenance.room,
                    slot: self.provenance.source,
                })
            }
        }
    }

    pub(crate) const fn live<'id>(&self, brand: Brand<'id>) -> Option<Source<'id>> {
        self.view(brand).live()
    }

    pub(crate) fn require_live<'id>(&self, brand: Brand<'id>) -> Result<Source<'id>, Error> {
        self.live(brand)
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
}

pub(crate) struct Node {
    /// Original hash value.
    pub hash: Hash,
    /// Actual accepted source facts, retained after physical retirement.
    pub origin: NodeOrigin,
    /// Actual new signature is accepted but historical scope is not yet rebound.
    pub resume_pending: bool,
    /// Original meta value.
    pub meta: ReceiveMeta,
    /// Original phase value.
    pub phase: MessagePhase,
    /// One signed original, stored in resident bytes or a committed archive.
    /// No original means no frame was installed or the payload was erased.
    pub frame: Option<RetainedFrame>,
    /// Original plaintext value.
    #[cfg(feature = "alloc")]
    pub plaintext: Option<Plaintext>,
    /// Original auth value.
    pub auth: Option<Authentication>,
    /// Original padding value.
    pub padding: wire::padding::Decode,
    /// Original signed body layout and separately declared outer encoder.
    pub layout: OriginalLayout,
    /// Immutable declared producer of the actual encrypted/transcript short.
    pub cipher_layout: Option<ShortLayout>,
    /// Declared plaintext layout retained for the original wire or archive.
    /// Installed plaintext (including a bound TRANSCRIPT) carries its own layout.
    pub plain_layout: Option<ShortLayout>,
    /// Original inner short carried by a TRANSCRIPT inside this message.
    pub transcript_layout: Option<ShortLayout>,
    /// Optional original creator order for a newly introduced identifier.
    pub identifier_order: Option<wire::profile::Endian>,
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
    /// Actual live RECENT observation, separate from original GET provenance.
    pub frontier_recent: bool,
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
    /// History-only projection. In SERVICE, reattached route controls also
    /// set this; only meta.requested witnesses the actual current response.
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
    #[cfg(feature = "alloc")]
    pub recipient: Option<RecipientAttribution>,
}
impl Node {
    /// Resident payload charged to the Core memory budget.
    pub fn payload_bytes(&self) -> usize {
        let bytes = self.frame.as_ref().map_or(0, RetainedFrame::capacity);
        #[cfg(feature = "alloc")]
        let bytes = bytes + self.plaintext.as_ref().map_or(0, Plaintext::capacity);
        bytes
    }
    pub const fn has_original(&self) -> bool {
        self.frame.is_some()
    }

    pub const fn original_is_archived(&self) -> bool {
        matches!(self.frame, Some(RetainedFrame::Archived(_)))
    }

    pub const fn archived_original(&self) -> Option<ArchiveOriginalRange> {
        match self.frame.as_ref() {
            Some(frame) => frame.archived_original(),
            None => None,
        }
    }

    /// Whether the accepted graph facts are settled independently of original
    /// custody. Also applies before recovery installs the original bytes.
    pub(crate) fn graph_row_is_settled(&self) -> bool {
        #[cfg(feature = "alloc")]
        if self.plaintext.is_some() || self.recipient.is_some() {
            return false;
        }
        self.auth.is_some()
            && self.semantic_applied
            && self.complete
            && self.epoch_indexed
            && self.sequence != 0
            && !self.queued
            && !self.resume_pending
            && self.kind == self.semantic_kind
            && self.discourse.is_none()
            && self.transcript.is_none()
            && self.private_recipient.is_none()
    }

    /// Only complete public member data can borrow its bytes from the working
    /// checkpoint. Peer control originals move with their detached graph row.
    pub fn can_archive_original(&self) -> bool {
        self.phase == MessagePhase::Applied
            && matches!(self.kind, Kind::TEXT | Kind::FILE)
            && self.graph_row_is_settled()
    }

    /// Borrow resident signed bytes. An archived original has no such slice.
    pub fn original<'a>(&'a self, frames: &'a FrameStore<'_>) -> Result<Option<&'a [u8]>, Error> {
        self.frame
            .as_ref()
            .filter(|frame| frame.is_resident())
            .map(|frame| frames.expose(frame))
            .transpose()
    }

    /// Borrow one actual retained signed message.
    #[cfg(feature = "alloc")]
    pub fn message<'a>(
        &'a self,
        frames: &'a FrameStore<'_>,
    ) -> Result<wire::message::Message<'a>, Error> {
        self.decode_original(self.original(frames)?.ok_or(Fault::NotReady)?)
    }

    /// Interpret retained full frame bytes using their admitted encoder metadata.
    /// The bytes can be checked out of the room while state is being advanced.
    pub fn decode_original<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<wire::message::Message<'a>, Error> {
        Ok(wire::message::Message::decode_with_profiles(
            bytes,
            self.layout.body_profile(self.kind)?,
            self.layout.padding,
            self.padding,
        )?)
    }
    /// Borrow actual typed original or authenticated decrypted content.
    pub fn body<'a>(&'a self, frames: &'a FrameStore<'_>) -> Result<wire::body::Body<'a>, Error> {
        #[cfg(feature = "alloc")]
        if let Some(plain) = &self.plaintext {
            return plain.body();
        }
        Ok(self
            .decode_original(self.original(frames)?.ok_or(Fault::NotReady)?)?
            .body())
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
    /// Exact current source-owned JOIN operation, including slot generation.
    pub join_operation: Option<Slot>,
}
#[derive(Clone, Copy)]
pub(crate) struct PeerAnnouncement {
    pub(crate) hash: Hash,
    pub(crate) sequence: NonZeroU64,
}

struct LivePeer {
    announcement: PeerAnnouncement,
    connection: ServiceConnection,
}

pub(crate) struct PeerRow {
    pub(crate) peer: ShortHash,
    /// A recovered candidate can seed a dial without joining the live ring.
    live: Option<LivePeer>,
}

impl PeerRow {
    pub(crate) const fn candidate(peer: ShortHash) -> Self {
        Self { peer, live: None }
    }

    pub(crate) const fn is_announced(&self) -> bool {
        self.live.is_some()
    }

    pub(crate) fn announcement(&self) -> Option<&PeerAnnouncement> {
        self.live.as_ref().map(|live| &live.announcement)
    }

    pub(crate) fn connection(&self) -> Option<ServiceConnection> {
        self.live.as_ref().map(|live| live.connection)
    }

    pub(crate) fn announce(&mut self, announcement: PeerAnnouncement) {
        if let Some(live) = &mut self.live {
            live.announcement = announcement;
        } else {
            self.live = Some(LivePeer {
                announcement,
                connection: ServiceConnection::default(),
            });
        }
    }

    pub(crate) fn record_connection(&mut self, connection: ServiceConnection) {
        if let Some(live) = &mut self.live {
            live.connection = connection;
        }
    }
}
pub(crate) struct Subscription {
    /// Exact generation of the author in the Core's contact table.
    pub contact: Slot,
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
#[cfg(feature = "alloc")]
pub(crate) struct Confirmation {
    /// Exact contact generation that signed the original confirmation.
    pub contact: Slot,
    /// Original message value.
    pub message: Hash,
    /// Original verified mac value.
    pub verified_mac: bool,
}
#[cfg(feature = "alloc")]
pub(crate) struct GroupRow {
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
    pub key_custody: GroupKeyCustody,
    /// Original confirmations value.
    pub confirmations: Vec<Confirmation>,
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
/// Discard a locally generated proposal key only before any original output or
/// authenticated remote proof establishes possible external possession.
#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg(feature = "alloc")]
pub(crate) enum GroupKeyCustody {
    Provisional,
    Retained,
}
#[cfg(feature = "alloc")]
impl GroupRow {
    pub fn historical(&self) -> bool {
        self.phase == KeyPhase::Revoked || self.proposal.is_some() && self.expires == u64::MAX
    }
}
pub(crate) struct EpochRow {
    /// Original hash value.
    pub hash: Hash,
    /// Original parents value.
    pub parents: [Hash; 2],
    /// Original mutation value.
    pub mutation: crate::epoch::EpochMutation,
    /// Contacts in this snapshot, including their original slot generations.
    pub members: Snapshot,
    /// Original complete value.
    pub complete: bool,
    /// Original groups value.
    #[cfg(feature = "alloc")]
    pub groups: Slots<GroupRow>,
    /// Stored group rows that no longer occupy the active admission quota.
    #[cfg(feature = "alloc")]
    pub historical_groups: usize,
    /// Original nonces value.
    #[cfg(feature = "alloc")]
    pub nonces: Vec<crate::epoch::Nonce>,
    /// Original revision value.
    pub revision: u64,
    /// Original ephemeral recipient and advertised lifetime.
    #[cfg(feature = "alloc")]
    pub ephemeral: Option<EphemeralRecipient>,
    /// Original best announcement value.
    #[cfg(feature = "alloc")]
    pub best_announcement: Option<Slot>,
    /// Original best group value.
    #[cfg(feature = "alloc")]
    pub best_group: Option<Slot>,
}
impl EpochRow {
    pub(crate) fn hosted(
        hash: Hash,
        parents: [Hash; 2],
        mutation: crate::epoch::EpochMutation,
        members: Snapshot,
        complete: bool,
        revision: u64,
    ) -> Self {
        Self {
            hash,
            parents,
            mutation,
            members,
            complete,
            revision,
            #[cfg(feature = "alloc")]
            groups: Slots::empty(),
            #[cfg(feature = "alloc")]
            historical_groups: 0,
            #[cfg(feature = "alloc")]
            nonces: Vec::new(),
            #[cfg(feature = "alloc")]
            ephemeral: None,
            #[cfg(feature = "alloc")]
            best_announcement: None,
            #[cfg(feature = "alloc")]
            best_group: None,
        }
    }

    pub(crate) fn has_client_secrets(&self) -> bool {
        #[cfg(feature = "alloc")]
        {
            self.groups.len() != 0 || !self.nonces.is_empty() || self.ephemeral.is_some()
        }
        #[cfg(not(feature = "alloc"))]
        {
            false
        }
    }

    #[cfg(feature = "alloc")]
    pub fn active_group_count(&self) -> usize {
        self.groups.len() - self.historical_groups
    }

    #[cfg(feature = "alloc")]
    pub fn ephemeral_at(&self, now: u64) -> Option<&EphemeralRecipient> {
        self.ephemeral.as_ref().filter(|key| now < key.valid_until)
    }
}
#[cfg(feature = "alloc")]
pub(crate) struct EphemeralRecipient {
    pub secret: EcdheSecret,
    pub public: EcdhePublic,
    pub valid_until: u64,
}
pub(crate) struct MissingRow {
    /// Original hash value.
    pub hash: Hash,
    /// Original source generation in the containing room.
    pub source: Slot,
    /// Original operation value.
    #[cfg(feature = "alloc")]
    pub operation: Option<Slot>,
    /// First requested deadline; preserved after the operation retires.
    pub retry_at: u64,
    /// Original absent value.
    pub absent: bool,
}
pub(crate) enum Job {
    Wire {
        purpose: NativePurpose,
        frame: Option<RetainedFrame>,
        length: usize,
        encoding: Encoding,
    },
    Sign {
        body: Option<RetainedFrame>,
        kind: Kind,
        public: PublicKey,
        sender: ShortHash,
        previous: Hash,
        timestamp: u64,
    },
    #[cfg(feature = "alloc")]
    SharedKey,
    #[cfg(feature = "alloc")]
    EpochRecord {
        public: PublicKey,
        identifier_order: wire::profile::Endian,
    },
    #[cfg(feature = "alloc")]
    EphemeralKey { valid_until: u64 },
}
impl Job {
    pub fn payload(&self) -> Option<&RetainedFrame> {
        match self {
            Self::Wire { frame, .. } => frame.as_ref(),
            Self::Sign { body, .. } => body.as_ref(),
            #[cfg(feature = "alloc")]
            _ => None,
        }
    }

    pub fn take_payload(&mut self) -> Option<RetainedFrame> {
        match self {
            Self::Wire { frame, .. } => frame.take(),
            Self::Sign { body, .. } => body.take(),
            #[cfg(feature = "alloc")]
            _ => None,
        }
    }
}
/// Immutable admission credit; resolving missing metadata never reclassifies
/// an already owned original operation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum OperationClass {
    Ordinary,
    #[cfg(feature = "alloc")]
    Sync,
    Dependency,
}
/// Job scope relative to its original room. The room and operation generations
/// are carried by the enclosing table keys, and never by a second copy here.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct OperationBinding {
    pub source: Slot,
    pub member: Option<Slot>,
    pub message: Hash,
    pub epoch: Hash,
    pub identifier: ShortHash,
    pub epoch_revision: u64,
}
impl OperationBinding {
    pub(crate) fn bind<'id>(self, brand: Brand<'id>, room: Slot, operation: Slot) -> Binding<'id> {
        Binding {
            operation: brand.operation_id(room, operation),
            source: brand.source_id(room, self.source),
            member: self.member.map(|slot| brand.member_id(room, slot)),
            message: self.message,
            epoch: self.epoch,
            identifier: self.identifier,
            epoch_revision: self.epoch_revision,
        }
    }
}

pub(crate) struct OperationRow {
    pub class: OperationClass,
    /// Authenticated echo observed for this original taken JOIN effect.
    #[cfg(feature = "alloc")]
    pub join_echo: bool,
    /// Immutable original operation/source/member/message scope.
    pub binding: OperationBinding,
    /// Original signed body family, retained when signing becomes wire work.
    #[cfg(feature = "alloc")]
    pub signed_kind: Option<Kind>,
    /// Exact cohort slot generations used by this draft in its binding's epoch.
    #[cfg(feature = "alloc")]
    pub group_keys: [Option<Slot>; 2],
    /// Original PRIVATE target, promoted only by the exact written send echo.
    #[cfg(feature = "alloc")]
    pub recipient: Option<MemberRecipient>,
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
/// Original automated GROUP attempt held through native retirement or echo.
#[derive(Clone, Copy)]
#[cfg(feature = "alloc")]
pub(crate) struct AutomaticProposal {
    pub operation: Slot,
    pub epoch: Hash,
    pub event: Hash,
    pub level: u32,
    /// Local retry bound, shortened by the exact original echo.
    pub expires: u64,
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
    /// Original historical key-control effect awaiting real frontier SYNC.
    pub frontier_control: Option<Slot>,
    pub frontier_base: Option<Hash>,
    pub frontier_control_hash: Option<Hash>,
    pub frontier_version: u64,
    #[cfg(feature = "alloc")]
    pub frontier_validation: Option<crate::graph::synchronization::Validation>,
    #[cfg(feature = "alloc")]
    pub frontier_validation_turn: bool,
    pub frontier_reset: bool,
    /// Original joined value.
    pub joined: bool,
    /// Original current epoch value.
    pub current_epoch: Hash,
    pub sync_phase: Option<RoomPhase>,
    /// Original last message value.
    pub last_message: Hash,
    /// Original sources value.
    pub sources: RoomTable<'id, SourceRow, SourceCell>,
    /// Original sessions value.
    pub sessions: RoomTable<'id, SessionRow, SessionCell>,
    /// Original nodes value.
    pub nodes: HistoryNodes<'id>,
    /// Message slots ordered by their retained node's exact original hash.
    pub index: HistoryIndex<'id>,
    /// Original frontier, peer/recipient state and completion work.
    pub queues: RoomQueues<'id>,
    /// SERVICE aliases use fixed cells or grow once on the owned path.
    pub epoch_aliases: AliasBuckets<'id>,
    /// Number of occupied first-write buckets.
    pub epoch_alias_count: usize,
    /// Ready message slots, with at most one entry per live node.
    pub ready: HistoryQueue<'id>,
    /// Original epochs value.
    pub epochs: RoomTable<'id, EpochRow, EpochCell>,
    pub member_arena: MemberArena<'id>,
    #[cfg(feature = "alloc")]
    pub automatic_proposal: Option<AutomaticProposal>,
    /// Identifier ownership survives retirement of the key/cohort row.
    #[cfg(feature = "alloc")]
    pub group_proposals: Vec<crate::epoch::GroupProposalBinding>,
    /// Allocation-free bounded propagation of actual late parent keys.
    #[cfg(feature = "alloc")]
    pub derivation: crate::epoch::derivation::DerivationCursor,
    /// Original subscriptions value.
    pub subscriptions: RoomTable<'id, Subscription, SubscriptionCell>,
    /// Original operations value.
    pub operations: RoomTable<'id, OperationRow, OperationCell>,
    /// Original missing value.
    pub missing: RoomTable<'id, MissingRow, MissingCell>,
    /// Original sequence value.
    pub sequence: u64,
    /// Original lineage value.
    pub lineage: u64,
    /// Original room capability flags in their declared creator layout.
    pub capabilities: RoomCapabilities,
}
impl<'id> RoomRow<'id> {
    #[cfg(test)]
    #[cfg(feature = "alloc")]
    pub fn new(
        key: Hash,
        public: Option<PublicKey>,
        limits: Limits,
        profile: Profile,
    ) -> Result<Self, Error> {
        Ok(Self::from_parts(
            key,
            public,
            profile,
            RoomParts::owned(limits)?,
        ))
    }

    /// Bind the same room state to its already reserved storage.
    pub fn from_parts(
        key: Hash,
        public: Option<PublicKey>,
        profile: Profile,
        parts: RoomParts<'id>,
    ) -> Self {
        let RoomParts {
            history:
                RoomHistory {
                    nodes,
                    index,
                    ready,
                },
            tables:
                RoomTables {
                    sources,
                    sessions,
                    epochs,
                    subscriptions,
                    operations,
                    missing,
                },
            queues,
            aliases,
            member_arena,
        } = parts;
        Self {
            key,
            profile,
            phase: RoomPhase::Detached,
            local_public: public,
            local_id: None,
            frontier_control: None,
            frontier_base: None,
            frontier_control_hash: None,
            frontier_version: 0,
            #[cfg(feature = "alloc")]
            frontier_validation: None,
            #[cfg(feature = "alloc")]
            frontier_validation_turn: false,
            frontier_reset: false,
            joined: false,
            current_epoch: [0; 64],
            sync_phase: None,
            last_message: [0; 64],
            sources,
            sessions,
            nodes,
            index,
            queues,
            epoch_aliases: aliases,
            epoch_alias_count: 0,
            ready,
            epochs,
            member_arena,
            #[cfg(feature = "alloc")]
            automatic_proposal: None,
            #[cfg(feature = "alloc")]
            group_proposals: Vec::new(),
            #[cfg(feature = "alloc")]
            derivation: crate::epoch::derivation::DerivationCursor::default(),
            subscriptions,
            operations,
            missing,
            sequence: 0,
            lineage: 0,
            capabilities: RoomCapabilities::decode(&key, profile.endian),
        }
    }

    pub fn into_partition(self) -> Result<RoomPartition<'id>, Error> {
        RoomParts {
            history: RoomHistory {
                nodes: self.nodes,
                index: self.index,
                ready: self.ready,
            },
            tables: RoomTables {
                sources: self.sources,
                sessions: self.sessions,
                epochs: self.epochs,
                subscriptions: self.subscriptions,
                operations: self.operations,
                missing: self.missing,
            },
            queues: self.queues,
            aliases: self.epoch_aliases,
            member_arena: self.member_arena,
        }
        .into_partition()
    }

    /// Actual metadata bytes observation or bounded operation.
    pub fn metadata_bytes(&self) -> Result<usize, Error> {
        let fixed = [
            self.sources.bytes()?,
            self.sessions.bytes()?,
            self.epochs.bytes()?,
            self.subscriptions.bytes()?,
            self.operations.bytes()?,
            self.missing.bytes()?,
            self.queues.bytes()?,
            AliasBuckets::required_bytes(self.epoch_aliases.capacity())?,
            self.member_arena.bytes()?,
        ];
        let mut bytes = fixed
            .into_iter()
            .try_fold(0usize, |a, b| a.checked_add(b).ok_or(Fault::Overflow))?;
        for (capacity, width) in [
            (
                self.nodes.storage().capacity(),
                core::mem::size_of::<HistoryNodeCell>(),
            ),
            (self.index.capacity(), core::mem::size_of::<Slot>()),
            (self.ready.capacity(), core::mem::size_of::<Slot>()),
        ] {
            bytes = bytes
                .checked_add(capacity.checked_mul(width).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
        }
        #[cfg(feature = "alloc")]
        {
            let proposals = self
                .group_proposals
                .capacity()
                .checked_mul(core::mem::size_of::<crate::epoch::GroupProposalBinding>())
                .ok_or(Fault::Overflow)?;
            bytes = bytes.checked_add(proposals).ok_or(Fault::Overflow)?;
        }
        #[cfg(feature = "alloc")]
        if let Some(validation) = &self.frontier_validation {
            bytes = bytes
                .checked_add(validation.bytes())
                .ok_or(Fault::Overflow)?;
        }
        Ok(bytes)
    }
    /// Actual find node observation or bounded operation.
    pub fn find_node(&self, hash: &Hash) -> Option<Slot> {
        self.index
            .find(hash, |slot| self.nodes.get(slot).map(|node| &node.hash))
    }
    /// Actual find epoch observation or bounded operation.
    pub fn find_epoch(&self, hash: &Hash) -> Option<Slot> {
        self.epochs
            .iter()
            .find_map(|(s, e)| (e.hash == *hash).then_some(s))
    }

    pub fn epoch_members<'a>(
        &'a self,
        epoch: &'a EpochRow,
    ) -> impl ExactSizeIterator<Item = Slot> + DoubleEndedIterator + Clone + 'a {
        self.member_arena
            .cells(&epoch.members)
            .iter()
            .map(|cell| cell.contact())
    }

    #[cfg(feature = "alloc")]
    pub fn epoch_member_count(&self, epoch: &EpochRow) -> usize {
        self.member_arena.cells(&epoch.members).len()
    }

    pub fn epoch_has_member(&self, epoch: &EpochRow, contact: Slot) -> bool {
        self.epoch_members(epoch).any(|member| member == contact)
    }
    /// Actual local session observation or bounded operation.
    #[cfg(feature = "alloc")]
    pub fn local_session(&self) -> Option<Slot> {
        self.sessions.iter().find_map(|(s, m)| {
            (Some(m.id) == self.local_id
                && Some(m.public) == self.local_public
                && m.phase == SessionPhase::Active)
                .then_some(s)
        })
    }
    #[cfg(all(test, feature = "alloc"))]
    pub fn insert_node(&mut self, node: Node) -> Result<Slot, Error> {
        let entry = self.index.vacant(&node.hash, |slot| {
            self.nodes.get(slot).map(|node| &node.hash)
        })?;
        let slot = self.nodes.vacant()?.insert(node);
        entry.insert(slot);
        Ok(slot)
    }

    pub fn restore_node(&mut self, slot: Slot, node: Node) -> Result<(), Error> {
        let entry = self.index.vacant(&node.hash, |slot| {
            self.nodes.get(slot).map(|node| &node.hash)
        })?;
        self.nodes
            .restore_entry(slot.index, slot.generation, node)?;
        entry.insert(slot);
        Ok(())
    }
}
impl RoomRow<'_> {
    pub(crate) fn current_peer_announcement(
        &self,
        peer: &ShortHash,
        hash: &Hash,
    ) -> Option<NonZeroU64> {
        let announcement = self.queues.peers.announcement(peer)?;
        (&announcement.hash == hash).then_some(announcement.sequence)
    }

    /// Actual required bytes observation or bounded operation.
    pub fn required_bytes(
        limits: Limits,
        fixed: Option<FixedRoomCapacities>,
    ) -> Result<usize, Error> {
        let history = limits
            .messages_per_room
            .checked_mul(core::mem::size_of::<HistoryNodeCell>() + core::mem::size_of::<Slot>() * 2)
            .ok_or(Fault::Overflow)?;
        let aliases = if fixed.is_some() {
            AliasBuckets::required_bytes(AliasBuckets::bucket_count(limits.messages_per_room)?)?
        } else {
            0
        };
        let queues =
            RoomQueues::required_bytes(limits, fixed.map(|storage| storage.completion_marks))?;
        let members =
            MemberArena::required_bytes(fixed.map_or(0, |storage| storage.epoch_members))?;
        RoomTables::required_bytes(limits)?
            .checked_add(queues)
            .and_then(|n| n.checked_add(history))
            .and_then(|n| n.checked_add(aliases))
            .and_then(|n| n.checked_add(members))
            .ok_or_else(|| Fault::Overflow.into())
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
                .checked_add(e.members.owned_bytes()?)
                .ok_or(Fault::Overflow)?;
            #[cfg(feature = "alloc")]
            {
                let nonces = e
                    .nonces
                    .capacity()
                    .checked_mul(core::mem::size_of::<crate::epoch::Nonce>())
                    .ok_or(Fault::Overflow)?;
                n = n
                    .checked_add(nonces)
                    .and_then(|n| e.groups.bytes().ok().and_then(|b| n.checked_add(b)))
                    .ok_or(Fault::Overflow)?;
                for (_, g) in e.groups.iter() {
                    n = n
                        .checked_add(
                            g.confirmations
                                .capacity()
                                .checked_mul(core::mem::size_of::<Confirmation>())
                                .ok_or(Fault::Overflow)?,
                        )
                        .ok_or(Fault::Overflow)?;
                }
            }
        }
        Ok(n)
    }
}
