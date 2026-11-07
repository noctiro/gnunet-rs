use core::fmt;
use gnunet_types::Error as Fault;
/// Caller-owned live identity domain. This nonzero-sized, non-cloneable value
/// must outlive its Core and every issued handle. Construction borrows it
/// exclusively; old handles keep that borrow alive even after the Core drops.
/// It contains no global counter, allocator, runtime or platform atomic.
pub struct Instance {
    _storage: u8,
}
impl Instance {
    /// Create an unborrowed domain; starts no protocol or cryptographic work.
    pub const fn new() -> Self {
        Self { _storage: 0 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Brand<'id> {
    original: &'id Instance,
}
#[cfg(feature = "alloc")]
impl<'id> Brand<'id> {
    pub(crate) const fn new(instance: &'id mut Instance) -> Self {
        Self { original: instance }
    }
}
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.original, other.original)
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessengerInstance([REDACTED])")
    }
}
/// Kind of an observed local handle, without a live identity-domain capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleKind {
    /// Original room slot.
    Room,
    /// Original source slot.
    Source,
    /// Original member-session slot.
    MemberSession,
    /// Original contact slot.
    Contact,
    /// Original operation slot.
    Operation,
}
/// Owned terminal diagnostics only. Coordinates are local to the reporting task
/// and are not unique across instances. No Core API accepts this snapshot or can
/// turn it back into a live handle. No address or identity brand is retained.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HandleObservation {
    kind: HandleKind,
    room_index: usize,
    room_generation: u64,
    index: usize,
    generation: u64,
}
impl fmt::Debug for HandleObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerHandleObservation([REDACTED], diagnostic only)")
            .field("kind", &self.kind)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl HandleObservation {
    /// Original local handle family, not a live capability.
    pub const fn kind(self) -> HandleKind {
        self.kind
    }
    /// Original local containing-room index; not an instance identity.
    pub const fn room_index(self) -> usize {
        self.room_index
    }
    /// Original containing-room generation observed by the reporting task.
    pub const fn room_generation(self) -> u64 {
        self.room_generation
    }
    /// Original local slot index; cannot select a Core operation.
    pub const fn index(self) -> usize {
        self.index
    }
    /// Original slot generation, without present ownership or authority.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}
/// Exact official room/message/epoch hash width; explicit access may reveal
/// private-room metadata. It is never a key-derived private identifier.
pub type Hash = [u8; 64];
/// Exact official room member/discourse/epoch-identifier width.
pub type ShortHash = [u8; 32];
/// Exact supported serialized public key, including the network family tag.
pub type PublicKey = [u8; 36];
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Slot {
    /// Original index value.
    pub index: usize,
    /// Original generation value.
    pub generation: u64,
}
macro_rules! handle {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub struct $name<'id> {
            pub(crate) core: Brand<'id>,
            pub(crate) room: Slot,
            pub(crate) slot: Slot,
        }
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("instance", &self.core)
                    .field("generation", &self.slot.generation)
                    .finish_non_exhaustive()
            }
        }
        impl $name<'_> {
            /// Copy original local coordinates into a non-authority observation.
            /// The snapshot cannot be used for mutation, cancellation or lookup.
            pub const fn observation(self) -> HandleObservation {
                HandleObservation {
                    kind: HandleKind::$name,
                    room_index: self.room.index,
                    room_generation: self.room.generation,
                    index: self.slot.index,
                    generation: self.slot.generation,
                }
            }
        }
    };
}
handle!(
    Room,
    "An original local room generation. Reuse/another Core cannot adopt it."
);
handle!(
    Source,
    "One original physical room-source generation, retired on actual loss."
);
handle!(
    MemberSession,
    "An original room member session; completion invalidates this handle."
);
handle!(
    Contact,
    "One actual contact generation; ordinary key rotation preserves its lineage."
);
handle!(
    Operation,
    "One original caller-port operation, bound to its room/source/job generation."
);
/// Original room lifecycle, driven by actual native events, not queued effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomPhase {
    /// No active native room attachment is acknowledged.
    Detached,
    /// Original OPEN is outstanding.
    Opening,
    /// Original ENTRY is outstanding.
    Entering,
    /// Actual OPEN notification has been received.
    Open,
    /// Actual ENTRY notification has been received.
    Entered,
    /// Original SYNC is outstanding.
    Synchronizing,
    /// Original closure/history completion is outstanding.
    Closing,
}
/// A member session remains available for delayed original history while closing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    /// Self-signed introduction awaits semantic completion.
    Joining,
    /// Authentic session introduction or transition has been applied.
    Active,
    /// Original closure/history completion is outstanding.
    Closing,
    /// The closing bound has a known path to the opening bound.
    Completed,
}
/// Real retained message phase. Deferred states grant no member/epoch permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessagePhase {
    /// No authorized actual signature attribution is available yet.
    AwaitingSender,
    /// Authentic content awaits original ancestor/reference data.
    AwaitingParents,
    /// Authentic outer data awaits epoch, recipient key or inner content.
    AwaitingEpoch,
    /// Actual admitted data is queued for semantic application.
    Ready,
    /// Actual semantic transition and admitted ancestor state are available.
    Applied,
    /// Sensitive payload was erased; immutable hash/author/links remain.
    Deleted,
    /// Actual protocol, authorization or cryptographic failure.
    Rejected,
}
/// Actual epoch/group key validity. Possession alone is not membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPhase {
    /// No admitted key capability is present.
    Missing,
    /// An original actual key-provider job is outstanding.
    Generating,
    /// An actual scoped key capability has been admitted.
    Present,
    /// The key and its dependent ratchets have been invalidated.
    Revoked,
}
/// Exact original source role selected by the caller's real transport owner.
/// A peer value must come from admitted CADET/peer state, never carried chat data.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SourceRole {
    /// Original initialized local IPC client source.
    Client,
    /// Original authenticated peer transport source/public identity.
    Peer([u8; 32]),
    /// Local daemon signer lease tied by the native owner to an actual PILS
    /// identity/epoch. This is not a CADET peer/transport or ready proof. Only
    /// ModeService with the configured exact local peer may attach this role.
    ServiceSigner([u8; 32]),
}
impl fmt::Debug for SourceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Client => "SourceRole::Client",
            Self::Peer(_) => "SourceRole::Peer([REDACTED])",
            Self::ServiceSigner(_) => "SourceRole::ServiceSigner([REDACTED])",
        })
    }
}
/// Explicit source facts carried with one original received message. Unknown
/// flag bits survive storage, but cannot grant caller authority or write facts.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReceiveMeta {
    /// Actual epoch hash from the original receive context.
    pub epoch: Hash,
    /// Exact original flags; Sent must additionally match an original local job.
    pub flags: u32,
    /// Whether this was an actual requested history response (no frontier update).
    pub requested: bool,
    /// Original public sender-hash metadata when supplied by local IPC.
    pub sender_hash: Option<Hash>,
    /// Original context metadata, preserved separately from cryptographic rights.
    pub context: Option<Hash>,
}
impl fmt::Debug for ReceiveMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiveMeta([REDACTED])")
            .field("flags", &self.flags)
            .field("requested", &self.requested)
            .finish_non_exhaustive()
    }
}
/// All capacities are concrete finite limits. Fixed table metadata is charged
/// together with retained frame/name/plaintext capacities before publication.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum locally authorized historical service signing identities.
    /// Remote peer messages never add entries to this lineage.
    pub own_signers: usize,
    /// Maximum live room generations.
    pub rooms: usize,
    /// Maximum retained contact generations.
    pub contacts: usize,
    /// Maximum original physical source slots in one room.
    pub sources_per_room: usize,
    /// Maximum retained member sessions and epoch member capacity.
    pub sessions_per_room: usize,
    /// Maximum retained original message/tombstone slots.
    pub messages_per_room: usize,
    /// Maximum immutable membership epoch slots.
    pub epochs_per_room: usize,
    /// Maximum announcement/group slots in one epoch.
    pub groups_per_epoch: usize,
    /// Maximum member-lineage discourse subscriptions.
    pub subscriptions_per_room: usize,
    /// Maximum retained original provider/native jobs.
    pub operations_per_room: usize,
    /// Bounded state-observation queue; at least eight slots are required.
    pub events: usize,
    /// Maximum original unresolved retrieval rows.
    pub missing_per_room: usize,
    /// Maximum actual MAC-checked nonce records before explicit capacity refusal.
    pub nonce_per_epoch: usize,
    /// Maximum admitted signed-frame length, within the official wire bound.
    pub frame_bytes: usize,
    /// Maximum retained first-NUL NAME content bytes.
    pub name_bytes: usize,
    /// Maximum charged retained capacities, including fixed metadata and original work.
    pub total_bytes: usize,
    /// Maximum selected transitions in each bounded processing phase.
    pub work_per_turn: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            own_signers: 256,
            rooms: 8,
            contacts: 1024,
            sources_per_room: 16,
            sessions_per_room: 128,
            messages_per_room: 4096,
            epochs_per_room: 256,
            groups_per_epoch: 64,
            subscriptions_per_room: 256,
            operations_per_room: 128,
            events: 256,
            missing_per_room: 256,
            nonce_per_epoch: 1024,
            frame_bytes: 65524,
            name_bytes: 4096,
            total_bytes: 64 * 1024 * 1024,
            work_per_turn: 64,
        }
    }
}
impl Limits {
    /// Reject zero, unreasonable wire widths and arithmetic-overflow capacities.
    pub fn validate(self) -> Result<(), Error> {
        let counts = [
            self.own_signers,
            self.rooms,
            self.contacts,
            self.sources_per_room,
            self.sessions_per_room,
            self.messages_per_room,
            self.epochs_per_room,
            self.groups_per_epoch,
            self.subscriptions_per_room,
            self.operations_per_room,
            self.events,
            self.missing_per_room,
            self.nonce_per_epoch,
            self.work_per_turn,
        ];
        if counts.contains(&0)
            || self.frame_bytes < 176
            || self.frame_bytes > 65535
            || self.events < 8
            || self.name_bytes == 0
            || self.name_bytes > self.frame_bytes
            || self.total_bytes == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        for n in counts {
            n.checked_mul(1024).ok_or(Fault::Overflow)?;
        }
        Ok(())
    }
}
/// Actual refusal, without fake cancellation, delivery, authorization or commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Actual bounded protocol/state failure.
    Protocol(Fault),
    /// Actual M3 cryptographic failure.
    Crypto(gnunet_messenger::crypto::Error),
    /// The same hash was attributed to incompatible original author/context.
    AttributionConflict,
    /// Actual key/session owner lacks the requested history or deletion right.
    Permission,
    /// Received AUTHORIZATION cannot establish a key without its omitted MAC.
    AuthorizationMacOmitted,
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_messenger::crypto::Error> for Error {
    fn from(e: gnunet_messenger::crypto::Error) -> Self {
        match e {
            gnunet_messenger::crypto::Error::AuthorizationMacOmitted => {
                Self::AuthorizationMacOmitted
            }
            e => Self::Crypto(e),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Messenger state: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Historical committed acceptance from the explicit trusted owned-store port.
/// It is not a source, signature result, live member or network identity proof.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchivedFact {
    pub(crate) generation: u64,
    pub(crate) sequence: u64,
}
#[cfg(feature = "alloc")]
impl ArchivedFact {
    /// Actual committed image generation, diagnostic only.
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Original accepted node order, diagnostic only.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}
/// Exact live original input versus trusted committed historical acceptance.
/// Recovery never constructs a live Peer Source from disk metadata.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageOrigin<'id> {
    /// Original real source; normal source-generation checks still apply.
    Live(Source<'id>),
    /// Committed owned-store fact, with no current source or signature authority.
    Archived(ArchivedFact),
}
#[cfg(feature = "alloc")]
impl<'id> MessageOrigin<'id> {
    /// Return a real original source only when this is not archive recovery.
    pub const fn live(self) -> Option<Source<'id>> {
        match self {
            Self::Live(s) => Some(s),
            Self::Archived(_) => None,
        }
    }
    pub(crate) fn require_live(self) -> Result<Source<'id>, Error> {
        self.live().ok_or_else(|| Fault::StaleGeneration.into())
    }
}

/// Original room/source slot generations and role recorded by the real owner.
/// These historical coordinates carry no identity domain or address and are not
/// globally unique or a constructible live Source capability.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SourceObservation {
    pub(crate) room: Slot,
    pub(crate) source: Slot,
    pub(crate) role: SourceRole,
}
#[cfg(feature = "alloc")]
impl core::fmt::Debug for SourceObservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SourceObservation([REDACTED], historical only)")
    }
}
#[cfg(feature = "alloc")]
impl SourceObservation {
    /// Original role observation, not current transport/identity authority.
    pub const fn role(self) -> SourceRole {
        self.role
    }
}
