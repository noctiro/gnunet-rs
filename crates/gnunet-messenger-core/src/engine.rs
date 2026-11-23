//! Actual bounded room/source/operation ownership and official IPC lifecycle.
#[cfg(feature = "alloc")]
use crate::room_storage::RoomParts;
use crate::{
    graph::*,
    room_storage::{RoomDirectory, RoomPartition, RoomPartitions},
    state::*,
    *,
};
use core::fmt;
use gnunet_types::Error as Fault;
use wire::{envelope::Kind, padding, profile::Profile};
/// Client state retains its received local view; service state also prunes TALK
/// payload outside all real member subscriptions, preserving deletion links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Original initialized local IPC client source.
    #[cfg(feature = "alloc")]
    Client,
    /// Hosted state with actual subscription pruning; native routing remains external.
    Service,
}
impl Mode {
    pub(crate) const fn is_client(self) -> bool {
        match self {
            #[cfg(feature = "alloc")]
            Self::Client => true,
            Self::Service => false,
        }
    }
}
/// Actual source-bound work prepared by the state core. A taken Wire frame is
/// moved to its original native owner; its allocation remains charged until the
/// real terminal receipt/source stop, not merely until this value is returned.
pub enum Work<'id, Bytes> {
    /// Move actual encoded work to its original native/peer owner.
    Wire {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
        /// Actual official operation family.
        purpose: NativePurpose,
        /// Exact official IPC or raw peer-message framing.
        encoding: Encoding,
        /// Original exclusively owned zeroizing encoded frame.
        frame: Bytes,
    },
    /// Request an actual scoped signature over the original immutable draft.
    Sign {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
        /// Actual official body kind to sign.
        kind: Kind,
        /// Original exclusively owned typed-body encoding, erased on drop.
        body: Bytes,
        /// Original authorized public signing key; no secret key is returned.
        public: PublicKey,
        /// Original room member identifier selected for the signature.
        sender: ShortHash,
        /// Original DAG predecessor selected before signature work was admitted.
        previous: Hash,
        /// Original absolute microsecond signing timestamp.
        timestamp: u64,
    },
    /// Request an actual scoped owned shared-key capability.
    #[cfg(feature = "alloc")]
    SharedKey {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
    },
    /// Request a real original local encrypted-record lookup. This is neither
    /// entropy generation nor successful key recovery; its exact original zone
    /// public key is retained independently of cross-room contact mutations.
    #[cfg(feature = "alloc")]
    EpochRecord {
        /// Immutable original operation/source/member/epoch/identifier scope.
        binding: Binding<'id>,
        /// Exact original private-zone public snapshot selected by this owner.
        public: PublicKey,
    },
    /// Request an actual owned ephemeral key with original finite expiry.
    #[cfg(feature = "alloc")]
    EphemeralKey {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
        /// Original finite ephemeral-key expiration, never reset by a late completion.
        valid_until: u64,
    },
}
impl<Bytes> fmt::Debug for Work<'_, Bytes> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessengerWork([REDACTED], actual result pending)")
    }
}
/// One original SERVICE signing draft. Taking this value never consumes an
/// already signed Wire job or any member/key-provider work in the same room.
pub struct ServiceSignWork<'id, Bytes> {
    /// Immutable original operation/source/member/message scope.
    pub binding: Binding<'id>,
    /// Actual official body kind to sign.
    pub kind: Kind,
    /// Original exclusively owned typed body; no second payload copy is retained.
    pub body: Bytes,
    /// Exact authorized public key snapshot.
    pub public: PublicKey,
    /// Original room sender, predecessor and absolute timestamp.
    pub sender: ShortHash,
    /// Original DAG predecessor.
    pub previous: Hash,
    /// Original absolute signing timestamp.
    pub timestamp: u64,
}
impl<Bytes> fmt::Debug for ServiceSignWork<'_, Bytes> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessengerServiceSignWork([REDACTED], actual result pending)")
    }
}

/// Independent caller-owned memory for admitted history and prepared work.
/// A full history pool does not consume the slots needed to prepare work.
pub struct ServiceBuffers<'id, const ROOMS: usize> {
    history: OriginalPool<'id, 'id>,
    workspace: &'id mut [u8],
    rooms: ServiceRoomStorage<'id>,
    work: OriginalPool<'id, 'id>,
    tables: ServiceTables<'id>,
    ancestry: &'id mut [HistoryCell],
}

impl<'id, const ROOMS: usize> ServiceBuffers<'id, ROOMS> {
    /// Supply independent empty history and work pools, room metadata and one maximum-frame
    /// history workspace. The work pool must hold at least one maximum frame.
    /// The shared ancestry workspace needs one cell per working message slot
    /// in one room, plus one per detached row when applying archived history.
    pub const fn new(
        history: OriginalPool<'id, 'id>,
        workspace: &'id mut [u8],
        rooms: ServiceRoomStorage<'id>,
        work: OriginalPool<'id, 'id>,
        tables: ServiceTables<'id>,
        ancestry: &'id mut [HistoryCell],
    ) -> Self {
        Self {
            history,
            workspace,
            rooms,
            work,
            tables,
            ancestry,
        }
    }
}

/// Fixed service contact, event and historical signer storage. Each slice
/// matches the corresponding limit in [`Limits`]. Contact names have their
/// own byte budget and do not consume history or work slots.
pub struct ServiceTables<'id> {
    contacts: &'id mut [ContactCell],
    names: OriginalPool<'id, 'id>,
    events: &'id mut [EventCell],
    own_signers: &'id mut [[u8; 32]],
}

impl<'id> ServiceTables<'id> {
    /// Supply exclusive metadata and an empty name pool. The pool must have
    /// at least one slot per contact and space for one maximum-length name.
    pub const fn new(
        contacts: &'id mut [ContactCell],
        names: OriginalPool<'id, 'id>,
        events: &'id mut [EventCell],
        own_signers: &'id mut [[u8; 32]],
    ) -> Self {
        Self {
            contacts,
            names,
            events,
            own_signers,
        }
    }
}

#[cfg_attr(
    feature = "alloc",
    expect(
        clippy::large_enum_variant,
        reason = "Construction moves the borrowed fixed buffers without a heap indirection"
    )
)]
enum CoreStorage<'id, const ROOMS: usize> {
    #[cfg(feature = "alloc")]
    Heap {
        frames: FrameStore<'id>,
        history: Option<RoomHistoryStorage<'id>>,
    },
    Fixed(ServiceBuffers<'id, ROOMS>),
}

/// Finite allocation/state owner. Inputs are actual native facts or actual M3
/// cryptographic results. Queuing effects never declares a room/key published.
/// A fixed service owns `ROOMS` room slots in place; the default desktop
/// owner allocates only the number of slots configured in its runtime limits.
pub struct Core<'id, const ROOMS: usize = 0> {
    pub(crate) instance: Brand<'id>,
    pub(crate) limits: Limits,
    pub(crate) profile: Profile,
    pub(crate) mode: Mode,
    pub(crate) rooms: RoomDirectory<'id, ROOMS>,
    pub(crate) contacts: ContactTable<'id>,
    pub(crate) names: ByteStore<'id>,
    pub(crate) events: EventQueue<'id>,
    pub(crate) frames: FrameStore<'id>,
    pub(crate) work: ByteStore<'id>,
    pub(crate) ancestry: Option<HistoryWorkspace<'id>>,
    pub(crate) room_partitions: Option<RoomPartitions<'id, ROOMS>>,
    pub(crate) used: usize,
    pub(crate) anonymous: PublicKey,
    pub(crate) local_peer: Option<[u8; 32]>,
    /// Sorted locally observed signer provenance, distinct from live authority.
    pub(crate) own_signers: SignerTable<'id>,
}
impl<const ROOMS: usize> fmt::Debug for Core<'_, ROOMS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerCore([REDACTED])")
            .field("rooms", &self.rooms.len())
            .field("charged_bytes", &self.used)
            .finish()
    }
}
#[cfg(feature = "alloc")]
impl<'id> Core<'id> {
    /// Construct only bounded state. The sole deterministic crypto initialization
    /// derives the published anonymous public key from its public integer-one
    /// seed; there is no random key, private file, native I/O or hidden actor.
    pub fn new(
        instance: &'id mut Instance,
        mode: Mode,
        limits: Limits,
        profile: Profile,
    ) -> Result<Self, Error> {
        Self::build(
            instance,
            mode,
            limits,
            profile,
            CoreStorage::Heap {
                frames: FrameStore::default(),
                history: None,
            },
        )
    }

    /// Use caller-owned storage for signed SERVICE history. The byte pool must
    /// be empty; the separate workspace must hold one maximum incoming frame.
    /// Room metadata and native work still use bounded allocator-backed tables.
    pub fn with_frame_pool(
        instance: &'id mut Instance,
        limits: Limits,
        profile: Profile,
        pool: OriginalPool<'id, 'id>,
        workspace: &'id mut [u8],
    ) -> Result<Self, Error> {
        let frames = Self::fixed_frames(limits, pool, workspace)?;
        Self::build(
            instance,
            Mode::Service,
            limits,
            profile,
            CoreStorage::Heap {
                frames,
                history: None,
            },
        )
    }

    /// Use caller-owned signed frames, message table, hash index and ready
    /// queue for SERVICE history. Other service tables still use bounded
    /// allocations. Each partition is charged while its room is admitted.
    pub fn with_fixed_history(
        instance: &'id mut Instance,
        limits: Limits,
        profile: Profile,
        pool: OriginalPool<'id, 'id>,
        workspace: &'id mut [u8],
        storage: RoomHistoryStorage<'id>,
    ) -> Result<Self, Error> {
        let frames = Self::fixed_frames(limits, pool, workspace)?;
        Self::build(
            instance,
            Mode::Service,
            limits,
            profile,
            CoreStorage::Heap {
                frames,
                history: Some(storage),
            },
        )
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Use caller-owned buffers for SERVICE history, work, names and room state.
    /// Take byte-bearing work through [`Self::take_work_into`] or
    /// [`Self::take_service_signing_work_into`]. Epoch membership snapshots
    /// share one caller-owned arena per room.
    ///
    /// # Errors
    /// `ROOMS` and buffer lengths must match the configured limits, and all
    /// original byte pools must start empty.
    pub fn with_service_buffers(
        instance: &'id mut Instance,
        limits: Limits,
        profile: Profile,
        buffers: ServiceBuffers<'id, ROOMS>,
    ) -> Result<Self, Error> {
        if !buffers.work.is_empty() || !buffers.tables.names.is_empty() {
            return Err(Fault::InvalidInput.into());
        }
        if limits.rooms != ROOMS
            || buffers.work.slot_capacity() == 0
            || buffers.work.capacity() < limits.frame_bytes
            || buffers.tables.names.slot_capacity() < limits.contacts
            || buffers.tables.names.capacity() < limits.name_bytes
            || buffers.ancestry.len() < limits.messages_per_room
        {
            return Err(Fault::Capacity.into());
        }
        Self::build(
            instance,
            Mode::Service,
            limits,
            profile,
            CoreStorage::Fixed(buffers),
        )
    }

    fn fixed_frames(
        limits: Limits,
        pool: OriginalPool<'id, 'id>,
        workspace: &'id mut [u8],
    ) -> Result<FrameStore<'id>, Error> {
        if !pool.is_empty() {
            return Err(Fault::InvalidInput.into());
        }
        if workspace.len() < limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        Ok(FrameStore::fixed(pool, workspace))
    }

    fn build(
        instance: &'id mut Instance,
        mode: Mode,
        limits: Limits,
        profile: Profile,
        storage: CoreStorage<'id, ROOMS>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if mode.is_client() && limits.operations_per_room < 3 {
            return Err(Fault::InvalidInput.into());
        }
        profile.validate()?;
        let instance = Brand::new(instance);
        let (ancestry_bytes, partition_bytes, signer_bytes) = match &storage {
            CoreStorage::Fixed(buffers) => (
                HistoryWorkspace::required_bytes(buffers.ancestry.len())?,
                RoomPartitions::<ROOMS>::required_bytes(limits.rooms)?,
                SignerTable::required_bytes(limits.own_signers)?,
            ),
            #[cfg(feature = "alloc")]
            CoreStorage::Heap { history, .. } => (
                0,
                if history.is_some() {
                    RoomPartitions::<ROOMS>::required_bytes(limits.rooms)?
                } else {
                    0
                },
                0,
            ),
        };
        let event_bytes = EventQueue::required_bytes(limits.events)?;
        let lower = RoomDirectory::<ROOMS>::required_bytes(limits.rooms)?
            .checked_add(ContactTable::required_bytes(limits.contacts)?)
            .and_then(|n| n.checked_add(partition_bytes))
            .and_then(|n| n.checked_add(event_bytes))
            .and_then(|n| n.checked_add(signer_bytes))
            .and_then(|n| n.checked_add(ancestry_bytes))
            .ok_or(Fault::Overflow)?;
        if lower > limits.total_bytes {
            return Err(Fault::Capacity.into());
        }
        let (rooms, room_partitions, frames, work, contacts, names, events, own_signers, ancestry) =
            match storage {
                CoreStorage::Fixed(buffers) => {
                    let ServiceTables {
                        contacts,
                        names,
                        events,
                        own_signers,
                    } = buffers.tables;
                    (
                        RoomDirectory::inline(),
                        Some(RoomPartitions::new(
                            RoomPartition::Service(buffers.rooms),
                            limits,
                        )?),
                        Self::fixed_frames(limits, buffers.history, buffers.workspace)?,
                        ByteStore::Fixed(buffers.work),
                        ContactTable::fixed(contacts, limits.contacts)?,
                        ByteStore::Fixed(names),
                        EventQueue::fixed(events, limits.events)?,
                        SignerTable::fixed(own_signers, limits.own_signers)?,
                        Some(HistoryWorkspace::from_cells(buffers.ancestry)?),
                    )
                }
                #[cfg(feature = "alloc")]
                CoreStorage::Heap { frames, history } => (
                    RoomDirectory::owned(limits.rooms)?,
                    history
                        .map(|history| RoomPartitions::new(RoomPartition::History(history), limits))
                        .transpose()?,
                    frames,
                    ByteStore::Heap,
                    ContactTable::new(limits.contacts)?,
                    ByteStore::Heap,
                    EventQueue::new(limits.events)?,
                    SignerTable::new(),
                    None,
                ),
            };
        let partition_bytes = room_partitions
            .as_ref()
            .map(RoomPartitions::bytes)
            .transpose()?
            .unwrap_or(0);
        let event_bytes = events.bytes()?;
        let signer_bytes = own_signers.bytes()?;
        let used = rooms
            .bytes()?
            .checked_add(contacts.bytes()?)
            .and_then(|n| n.checked_add(partition_bytes))
            .and_then(|n| n.checked_add(event_bytes))
            .and_then(|n| n.checked_add(signer_bytes))
            .and_then(|n| n.checked_add(ancestry_bytes))
            .ok_or(Fault::Overflow)?;
        if used > limits.total_bytes {
            return Err(Fault::Capacity.into());
        }
        let anonymous = gnunet_identity::SecretKey::anonymous().public_key()?;
        Ok(Self {
            instance,
            limits,
            profile,
            mode,
            rooms,
            contacts,
            names,
            events,
            frames,
            work,
            ancestry,
            room_partitions,
            used,
            anonymous,
            local_peer: None,
            own_signers,
        })
    }
    /// Actual retained state and outstanding original-work allocation charge.
    pub const fn charged_bytes(&self) -> usize {
        self.used
    }
    /// Remaining configured retained allocation budget.
    pub fn remaining_bytes(&self) -> usize {
        self.limits.total_bytes.saturating_sub(self.used)
    }
    /// Consume one actual state observation, freeing bounded event capacity.
    pub fn pop_event(&mut self) -> Option<Event<'id>> {
        self.events
            .pop_front()
            .map(|event| event.bind(self.instance))
    }
    pub(crate) fn event_room(&self, slot: Slot) -> Room<'id> {
        self.instance.room_id(slot)
    }
    pub(crate) fn source_id(&self, room: Slot, slot: Slot) -> Source<'id> {
        self.instance.source_id(room, slot)
    }
    pub(crate) fn member_id(&self, room: Slot, slot: Slot) -> MemberSession<'id> {
        self.instance.member_id(room, slot)
    }
    pub(crate) fn contact_id(&self, slot: Slot) -> Contact<'id> {
        self.instance.contact_id(slot)
    }
    pub(crate) fn check_room(&self, id: Room<'id>) -> Result<Slot, Error> {
        if id.core != self.instance || id.room != id.slot {
            return Err(Fault::StaleGeneration.into());
        }
        self.rooms.get(id.slot)?;
        Ok(id.slot)
    }
    pub(crate) fn check_source(&self, id: Source<'id>) -> Result<(), Error> {
        if id.core != self.instance || !self.rooms.get(id.room)?.sources.get(id.slot)?.attached {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(())
    }
    /// Exact attached source's original room generation. This read-only lookup
    /// never grants a source, binding or membership to a caller.
    pub fn source_room(&self, source: Source<'id>) -> Result<Room<'id>, Error> {
        self.check_source(source)?;
        Ok(self.event_room(source.room))
    }
    pub(crate) fn check_member(&self, id: MemberSession<'id>) -> Result<(), Error> {
        if id.core != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        self.rooms.get(id.room)?.sessions.get(id.slot)?;
        Ok(())
    }
    pub(crate) fn operation_member_slot(
        &self,
        room: Slot,
        member: Option<MemberSession<'id>>,
    ) -> Result<Option<Slot>, Error> {
        let Some(member) = member else {
            return Ok(None);
        };
        if member.room != room {
            return Err(Fault::StaleGeneration.into());
        }
        self.check_member(member)?;
        Ok(Some(member.slot))
    }
    pub(crate) fn reserve_events(&self, count: usize) -> Result<(), Error> {
        self.events.reserve(count)
    }
    pub(crate) fn event(&mut self, event: Event<'id>) -> Result<(), Error> {
        self.events
            .vacant()?
            .insert(QueuedEvent::capture(event, self.instance)?);
        Ok(())
    }
    pub(crate) fn charge(&mut self, n: usize) -> Result<(), Error> {
        let next = self.used.checked_add(n).ok_or(Fault::Overflow)?;
        if next > self.limits.total_bytes {
            return Err(Fault::Capacity.into());
        }
        self.used = next;
        Ok(())
    }
    pub(crate) fn release(&mut self, n: usize) -> Result<(), Error> {
        self.used = self.used.checked_sub(n).ok_or(Fault::Conflict)?;
        Ok(())
    }
    /// Create actual empty room tables. Duplicate keys return the existing
    /// generation; they do not overwrite membership, history or pending source.
    pub fn room(&mut self, key: Hash, local_public: Option<PublicKey>) -> Result<Room<'id>, Error> {
        self.room_profiled(key, local_public, self.profile)
    }
    /// Explicit original capability creator profile, independent from message
    /// producers and transport padding. Existing stored room facts are retained.
    pub fn room_profiled(
        &mut self,
        key: Hash,
        local_public: Option<PublicKey>,
        profile: Profile,
    ) -> Result<Room<'id>, Error> {
        profile.validate()?;
        if let Some(public) = local_public {
            wire::PublicKey::new(&public)?;
        }
        if let Some((slot, row)) = self.rooms.iter().find(|(_, r)| r.key == key) {
            if row.local_public != local_public {
                return Err(Fault::Conflict.into());
            }
            return Ok(self.event_room(slot));
        }
        self.reserve_events(1)?;
        let index = self.rooms.next_key()?.index;
        let row = self.build_room(index, key, local_public, profile)?;
        let charged = row.metadata_bytes().and_then(|bytes| {
            let total = self.used.checked_add(bytes).ok_or(Fault::Overflow)?;
            if total > self.limits.total_bytes {
                return Err(Fault::Capacity.into());
            }
            Ok(total)
        });
        let used = match charged {
            Ok(used) => used,
            Err(error) => {
                self.recycle_room_partition(index, row)?;
                return Err(error);
            }
        };
        let event = match self.events.vacant() {
            Ok(event) => event,
            Err(error) => {
                self.recycle_room_partition(index, row)?;
                return Err(error);
            }
        };
        let slot = match self.rooms.insert(row) {
            Ok(s) => s,
            Err((e, row)) => {
                self.recycle_room_partition(index, row)?;
                return Err(e);
            }
        };
        self.used = used;
        event.insert(QueuedEvent::RoomChanged(slot, RoomPhase::Detached));
        Ok(self.event_room(slot))
    }

    /// Return the immutable original profile used to interpret a room key.
    /// A later ingress source or local profile cannot change this fact.
    pub fn room_creator_profile(&self, room: Room<'id>) -> Result<Profile, Error> {
        Ok(self.rooms.get(self.check_room(room)?)?.profile)
    }

    pub(crate) fn build_room(
        &mut self,
        index: usize,
        key: Hash,
        local_public: Option<PublicKey>,
        profile: Profile,
    ) -> Result<RoomRow<'id>, Error> {
        let fixed = match &self.room_partitions {
            Some(partitions) => partitions.fixed_capacities(index)?,
            None => None,
        };
        if RoomRow::required_bytes(self.limits, fixed)? > self.remaining_bytes() {
            return Err(Fault::Capacity.into());
        }
        let parts = match &mut self.room_partitions {
            Some(partitions) => partitions.take(index, self.limits)?,
            #[cfg(feature = "alloc")]
            None => RoomParts::owned(self.limits)?,
            #[cfg(not(feature = "alloc"))]
            None => return Err(Fault::Conflict.into()),
        };
        Ok(RoomRow::from_parts(key, local_public, profile, parts))
    }

    fn recycle_room_partition(&mut self, index: usize, room: RoomRow<'id>) -> Result<(), Error> {
        if let Some(history) = &mut self.room_partitions {
            let vacant = history.vacant_partition(index)?;
            *vacant = Some(room.into_partition()?);
        }
        Ok(())
    }
    /// Current original room lifecycle observation.
    pub fn phase(&self, room: Room<'id>) -> Result<RoomPhase, Error> {
        Ok(self.rooms.get(self.check_room(room)?)?.phase)
    }
    /// Whether an authentic own JOIN has actually been applied.
    pub fn joined(&self, room: Room<'id>) -> Result<bool, Error> {
        Ok(self.rooms.get(self.check_room(room)?)?.joined)
    }
    /// Explicit original room capability bytes; do not log private room metadata.
    pub fn room_key(&self, room: Room<'id>) -> Result<&Hash, Error> {
        Ok(&self.rooms.get(self.check_room(room)?)?.key)
    }
    /// Register one actually attached original native source. The native owner
    /// remains responsible for mapping its real epoch to this opaque generation.
    pub fn attach_source(
        &mut self,
        room: Room<'id>,
        role: SourceRole,
        decode_padding: padding::Decode,
        public: Option<PublicKey>,
    ) -> Result<Source<'id>, Error> {
        let r = self.check_room(room)?;
        self.check_service_role(role)?;
        if let Some(p) = public {
            wire::PublicKey::new(&p)?;
        }
        self.reserve_events(1)?;
        let fresh_view = self.mode.is_client()
            && role == SourceRole::Client
            && self.rooms.get(r)?.sources.len() == 0
            && self.rooms.get(r)?.nodes.len() != 0;
        let slot = self
            .rooms
            .get_mut(r)?
            .sources
            .insert(SourceRow {
                role,
                attached: true,
                padding: decode_padding,
                create_written: false,
                public,
                member_id: None,
                pending_member_id: None,
                join_required: false,
                join_operation: None,
            })
            .map_err(|(e, _)| e)?;
        if fresh_view {
            self.rooms.get_mut(r)?.frontier_reset = true;
        }
        let source = self.source_id(r, slot);
        self.event(Event::SourceAttached(source))?;
        Ok(source)
    }
    /// Observe the native adapter's actual complete local CREATE write. There
    /// is no wire ACK or service-ready response for this original message.
    pub fn create_submitted(&mut self, source: Source<'id>) -> Result<(), Error> {
        self.check_source(source)?;
        let row = self
            .rooms
            .get_mut(source.room)?
            .sources
            .get_mut(source.slot)?;
        if row.create_written {
            return Err(Fault::Replay.into());
        }
        row.create_written = true;
        Ok(())
    }
    /// Remaining ordinary/provider/history rows after client protocol credits.
    /// This read-only preflight reserves nothing and does not retire any job.
    /// Service rooms report the remaining full configured operation table.
    pub fn ordinary_operation_capacity(&self, room: Room<'id>) -> Result<usize, Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        let (limit, used) = if self.mode.is_client() {
            (
                row.operations.limit().saturating_sub(2),
                row.operations
                    .iter()
                    .filter(|(_, operation)| operation.class == OperationClass::Ordinary)
                    .count(),
            )
        } else {
            (row.operations.limit(), row.operations.len())
        };
        Ok(limit.saturating_sub(used))
    }
    /// Client rooms retain independent protocol credits: one SYNC and one
    /// required GET cannot be consumed by ordinary/provider/history jobs.
    /// Service ownership uses the full configured table without these credits.
    pub(crate) fn next_operation_slot(
        &self,
        room: Slot,
        _class: OperationClass,
    ) -> Result<Slot, Error> {
        let row = self.rooms.get(room)?;
        #[cfg(feature = "alloc")]
        if self.mode.is_client() {
            let used = row
                .operations
                .iter()
                .filter(|(_, operation)| operation.class == _class)
                .count();
            let limit = match _class {
                OperationClass::Ordinary => row.operations.limit().saturating_sub(2),
                OperationClass::Sync | OperationClass::Dependency => 1,
            };
            if used >= limit {
                return Err(Fault::WouldBlock.into());
            }
        }
        row.operations.next_key()
    }
    pub(crate) fn queue_wire(
        &mut self,
        source: Source<'id>,
        purpose: NativePurpose,
        request: wire::Request<'_>,
        member: Option<MemberSession<'id>>,
        hash: Hash,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        let member = self.operation_member_slot(source.room, member)?;
        if deadline == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        let len = request.encoded_len()?;
        if len > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        let class = match purpose {
            #[cfg(feature = "alloc")]
            NativePurpose::Sync => OperationClass::Sync,
            NativePurpose::Get
                if self
                    .rooms
                    .get(source.room)?
                    .missing
                    .iter()
                    .any(|(_, missing)| missing.source == source.slot && missing.hash == hash) =>
            {
                OperationClass::Dependency
            }
            _ => OperationClass::Ordinary,
        };
        let slot = self.next_operation_slot(source.room, class)?;
        let operation = self.instance.operation_id(source.room, slot);
        let binding = OperationBinding {
            source: source.slot,
            member,
            message: hash,
            epoch: self.rooms.get(source.room)?.current_epoch,
            identifier: [0; 32],
            epoch_revision: 0,
        };
        let budget = self.remaining_bytes();
        let event = self.events.vacant()?;
        let vacant = self.rooms.get_mut(source.room)?.operations.vacant()?;
        let frame = self.work.write(len, budget, |output| {
            request.encode(output)?;
            Ok(())
        })?;
        let capacity = frame.capacity();
        let row = OperationRow {
            class,
            #[cfg(feature = "alloc")]
            join_echo: false,
            binding,
            #[cfg(feature = "alloc")]
            signed_kind: None,
            #[cfg(feature = "alloc")]
            group_keys: [None; 2],
            #[cfg(feature = "alloc")]
            recipient: None,
            job: Job::Wire {
                purpose,
                frame: Some(frame),
                length: len,
                encoding: Encoding::Ipc,
            },
            phase: OperationPhase::Prepared,
            deadline,
            written: 0,
            charged_bytes: capacity,
        };
        vacant.insert(row);
        self.used += capacity;
        event.insert(QueuedEvent::OperationChanged {
            room: source.room,
            operation: slot,
            phase: OperationPhase::Prepared,
        });
        Ok(operation)
    }
    pub(crate) fn room_request(
        &mut self,
        source: Source<'id>,
        purpose: NativePurpose,
        door: [u8; 32],
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        #[cfg(feature = "alloc")]
        let validate = purpose == NativePurpose::Sync && self.mode.is_client();
        #[cfg(feature = "alloc")]
        if validate {
            if self.frontier_sync_in_flight(self.event_room(source.room))? {
                return Err(Fault::WouldBlock.into());
            }
            self.reserve_frontier_scratch(source.room)?;
        }
        let row = self.rooms.get(source.room)?;
        if !row.sources.get(source.slot)?.create_written {
            return Err(Fault::NotReady.into());
        }
        let (key, previous, epoch, public) = (
            row.key,
            row.last_message,
            row.current_epoch,
            row.local_public,
        );
        if purpose == NativePurpose::Open && !row.capabilities.allows_open() {
            return Err(Error::Permission);
        }
        let frame = wire::Room {
            door: &door,
            key: &key,
            previous: &previous,
            epoch: &epoch,
        };
        let public = public
            .as_ref()
            .map(|p| wire::PublicKey::new(p))
            .transpose()?;
        let (request, phase) = match purpose {
            NativePurpose::Open
                if matches!(
                    row.phase,
                    RoomPhase::Detached | RoomPhase::Entered | RoomPhase::Open
                ) =>
            {
                (
                    wire::Request::Open {
                        room: frame,
                        public_key: public,
                    },
                    RoomPhase::Opening,
                )
            }
            NativePurpose::Enter
                if matches!(
                    row.phase,
                    RoomPhase::Detached | RoomPhase::Entered | RoomPhase::Open
                ) =>
            {
                (
                    wire::Request::Entry {
                        room: frame,
                        public_key: public,
                    },
                    RoomPhase::Entering,
                )
            }
            NativePurpose::Close
                if matches!(
                    row.phase,
                    RoomPhase::Open | RoomPhase::Entered | RoomPhase::Synchronizing
                ) =>
            {
                (wire::Request::Close { room: frame }, RoomPhase::Closing)
            }
            NativePurpose::Sync if matches!(row.phase, RoomPhase::Open | RoomPhase::Entered) => (
                wire::Request::Sync { room: frame },
                RoomPhase::Synchronizing,
            ),
            _ => return Err(Fault::Conflict.into()),
        };
        self.reserve_events(2)?;
        let op = self.queue_wire(source, purpose, request, None, [0; 64], deadline)?;
        if purpose == NativePurpose::Sync {
            let prior = self.rooms.get(source.room)?.phase;
            let row = self.rooms.get_mut(source.room)?;
            row.sync_phase = Some(prior);
            #[cfg(feature = "alloc")]
            if validate {
                self.begin_frontier_sync(source.room, op.slot)?;
            }
        }
        self.rooms.get_mut(source.room)?.phase = phase;
        self.event(Event::RoomChanged(self.event_room(source.room), phase))?;
        Ok(op)
    }
    /// Queue the actual official OPEN on this initialized original source. An
    /// entered or already open room keeps its existing source and membership
    /// while the original OPEN operation awaits its actual notification.
    pub fn open(&mut self, source: Source<'id>, deadline: u64) -> Result<Operation<'id>, Error> {
        self.room_request(source, NativePurpose::Open, [0; 32], deadline)
    }
    /// Queue the actual official ENTRY through the supplied public door.
    pub fn enter(
        &mut self,
        source: Source<'id>,
        door: [u8; 32],
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.room_request(source, NativePurpose::Enter, door, deadline)
    }
    /// Queue the actual official CLOSE; a signed LEAVE is a separate real message.
    pub fn close(&mut self, source: Source<'id>, deadline: u64) -> Result<Operation<'id>, Error> {
        self.room_request(source, NativePurpose::Close, [0; 32], deadline)
    }
    /// Queue the actual official SYNC with the retained original room cursor.
    pub fn synchronize(
        &mut self,
        source: Source<'id>,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        let row = self.rooms.get(source.room)?;
        if let Some(control) = row.frontier_control {
            let operation = row.operations.get(control)?;
            let echo = row
                .find_node(&operation.binding.message)
                .and_then(|slot| row.nodes.get(slot).ok());
            if operation.binding.source != source.slot
                || operation.phase != OperationPhase::Complete
                || !echo.is_some_and(|node| {
                    node.local_sent
                        && node.auth.is_some()
                        && !matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                })
            {
                return Err(Fault::NotReady.into());
            }
        }
        self.room_request(source, NativePurpose::Sync, [0; 32], deadline)
    }
    /// Original historical key-control whose authenticated self-echo must be
    /// followed by an actual matching SYNC before ordinary draft admission.
    /// This is a pending effect, not evidence that any frontier is coherent.
    pub fn frontier_control(&self, room: Room<'id>) -> Result<Option<Operation<'id>>, Error> {
        let r = self.check_room(room)?;
        Ok(self
            .rooms
            .get(r)?
            .frontier_control
            .map(|slot| self.instance.operation_id(r, slot)))
    }
    /// Move only original prepared work to its provider. No replacement source,
    /// callback outcome or remote success is synthesized by this transfer.
    #[cfg(feature = "alloc")]
    pub fn take_work(&mut self, room: Room<'id>) -> Result<Option<Work<'id, OwnedBytes>>, Error> {
        self.take_work_matching(room, |_| true, ByteStore::take_owned)
    }

    /// Move one prepared job to the caller. Byte-bearing jobs transfer their
    /// contents into `output`; a busy or short slot keeps the job prepared.
    pub fn take_work_into<'slot, 'buffer>(
        &mut self,
        room: Room<'id>,
        output: &'slot ByteSlot<'buffer>,
    ) -> Result<Option<Work<'id, BorrowedBytes<'slot, 'buffer>>>, Error> {
        self.take_work_matching(
            room,
            |_| true,
            |store, frame| store.take_into(frame, output),
        )
    }
    /// Take only a prepared original signature draft from this SERVICE room.
    /// Signed Wire work stays prepared and owned by Core until its original
    /// local commit or normal generic transport work extraction.
    #[cfg(feature = "alloc")]
    pub fn take_service_signing_work(
        &mut self,
        room: Room<'id>,
    ) -> Result<Option<ServiceSignWork<'id, OwnedBytes>>, Error> {
        self.take_sign_matching(room, ByteStore::take_owned)
    }

    /// Take a prepared SERVICE signing draft into an exclusive caller buffer.
    /// A busy or short slot leaves the original draft prepared for retry.
    pub fn take_service_signing_work_into<'slot, 'buffer>(
        &mut self,
        room: Room<'id>,
        output: &'slot ByteSlot<'buffer>,
    ) -> Result<Option<ServiceSignWork<'id, BorrowedBytes<'slot, 'buffer>>>, Error> {
        self.take_sign_matching(room, |store, frame| store.take_into(frame, output))
    }

    fn take_sign_matching<Bytes>(
        &mut self,
        room: Room<'id>,
        take: impl FnOnce(&mut ByteStore<'id>, &mut Option<RetainedFrame>) -> Result<Bytes, Error>,
    ) -> Result<Option<ServiceSignWork<'id, Bytes>>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        match self.take_work_matching(room, |job| matches!(job, Job::Sign { .. }), take)? {
            Some(Work::Sign {
                binding,
                kind,
                body,
                public,
                sender,
                previous,
                timestamp,
            }) => Ok(Some(ServiceSignWork {
                binding,
                kind,
                body,
                public,
                sender,
                previous,
                timestamp,
            })),
            None => Ok(None),
            // No mutation or observer runs between selection and extraction.
            Some(_) => Err(Fault::Conflict.into()),
        }
    }
    fn take_work_matching<Bytes>(
        &mut self,
        room: Room<'id>,
        accepts: fn(&Job) -> bool,
        take: impl FnOnce(&mut ByteStore<'id>, &mut Option<RetainedFrame>) -> Result<Bytes, Error>,
    ) -> Result<Option<Work<'id, Bytes>>, Error> {
        let r = self.check_room(room)?;
        let row = self.rooms.get_mut(r)?;
        let key = row.operations.iter().find_map(|(s, o)| {
            (o.phase == OperationPhase::Prepared && accepts(&o.job)).then_some(s)
        });
        let Some(slot) = key else {
            return Ok(None);
        };
        let op = row.operations.get_mut(slot)?;
        let binding = op.binding.bind(self.instance, r, slot);
        let work = match &mut op.job {
            Job::Wire {
                purpose,
                encoding,
                frame,
                ..
            } => Work::Wire {
                binding,
                purpose: *purpose,
                encoding: *encoding,
                frame: take(&mut self.work, frame)?,
            },
            Job::Sign {
                body,
                kind,
                public,
                sender,
                previous,
                timestamp,
            } => Work::Sign {
                binding,
                kind: *kind,
                body: take(&mut self.work, body)?,
                public: *public,
                sender: *sender,
                previous: *previous,
                timestamp: *timestamp,
            },
            #[cfg(feature = "alloc")]
            Job::SharedKey => Work::SharedKey { binding },
            #[cfg(feature = "alloc")]
            Job::EpochRecord { public, .. } => Work::EpochRecord {
                binding,
                public: *public,
            },
            #[cfg(feature = "alloc")]
            Job::EphemeralKey { valid_until } => Work::EphemeralKey {
                binding,
                valid_until: *valid_until,
            },
        };
        op.phase = OperationPhase::Taken;
        Ok(Some(work))
    }
    pub(crate) fn check_binding(&self, binding: Binding<'id>) -> Result<&OperationRow, Error> {
        self.check_source(binding.source)?;
        if binding.operation.core != self.instance || binding.operation.room != binding.source.room
        {
            return Err(Fault::StaleGeneration.into());
        }
        let row = self
            .rooms
            .get(binding.source.room)?
            .operations
            .get(binding.operation.slot)?;
        self.operation_member_slot(binding.source.room, binding.member)?;
        if row.binding != binding.coordinates() {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(row)
    }
    /// Observe exact original local byte exposure. Whole writing alone records
    /// Written. A JOIN completes here only if its separate authenticated echo
    /// already arrived; otherwise the original receive observation is required.
    pub fn write_progress(
        &mut self,
        binding: Binding<'id>,
        bytes: usize,
        complete: bool,
    ) -> Result<(), Error> {
        let original = self.check_binding(binding)?;
        #[cfg(feature = "alloc")]
        let echoed_join =
            complete && original.signed_kind == Some(Kind::JOIN) && original.join_echo;
        let Job::Wire { length, .. } = &original.job else {
            return Err(Fault::Conflict.into());
        };
        if original.phase != OperationPhase::Taken {
            return Err(Fault::Replay.into());
        }
        let written = original.written.checked_add(bytes).ok_or(Fault::Overflow)?;
        if written > *length || complete && written != *length {
            return Err(Fault::Malformed.into());
        }
        #[cfg(feature = "alloc")]
        if bytes > 0 {
            self.retain_written_group_keys(binding, original.group_keys)?;
        }
        if complete {
            #[cfg(feature = "alloc")]
            self.reserve_events(if echoed_join { 2 } else { 1 })?;
            #[cfg(not(feature = "alloc"))]
            self.reserve_events(1)?;
        }
        let row = self
            .rooms
            .get_mut(binding.source.room)?
            .operations
            .get_mut(binding.operation.slot)?;
        row.written = written;
        if complete {
            row.phase = OperationPhase::Written;
            self.event(Event::OperationChanged(
                binding.operation,
                OperationPhase::Written,
            ))?;
        }
        #[cfg(feature = "alloc")]
        if echoed_join {
            self.finish_bootstrap_join(binding.source, binding.operation.slot)?;
        }
        Ok(())
    }
    /// Retain keys used by an original positive byte prefix observed during
    /// native retirement. This does not complete a write or acknowledge a peer.
    /// `bytes` is the cumulative native prefix for the exact taken frame.
    #[cfg(feature = "alloc")]
    pub fn observe_retired_write_prefix(
        &mut self,
        binding: Binding<'id>,
        bytes: usize,
    ) -> Result<(), Error> {
        let original = self.check_binding(binding)?;
        let Job::Wire { length, .. } = &original.job else {
            return Err(Fault::Conflict.into());
        };
        if original.phase != OperationPhase::Taken
            || bytes == 0
            || bytes < original.written
            || bytes >= *length
        {
            return Err(Fault::Malformed.into());
        }
        self.retain_written_group_keys(binding, original.group_keys)
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn pending_wire(
        &self,
        source: Source<'id>,
        purpose: NativePurpose,
        hash: Option<&Hash>,
    ) -> Option<Slot> {
        self.rooms
            .get(source.room)
            .ok()?
            .operations
            .iter()
            .find_map(|(s, o)| {
                (o.binding.source == source.slot
                    && o.phase == OperationPhase::Written
                    && hash.is_none_or(|h| o.binding.message == *h)
                    && matches!(&o.job,Job::Wire {purpose:p,..} if *p==purpose))
                .then_some(s)
            })
    }
    #[cfg(feature = "alloc")]
    pub(crate) fn finish_wire(&mut self, source: Source<'id>, slot: Slot) -> Result<(), Error> {
        self.reserve_events(1)?;
        let row = self.rooms.get_mut(source.room)?.operations.get_mut(slot)?;
        row.phase = OperationPhase::Complete;
        let op = self.instance.operation_id(source.room, slot);
        self.event(Event::OperationChanged(op, OperationPhase::Complete))?;
        Ok(())
    }
    /// Retire a terminal observation after the caller has consumed it. No RID is
    /// reused on wire; the private local slot receives a new generation later.
    pub fn retire_operation(&mut self, operation: Operation<'id>) -> Result<(), Error> {
        if operation.core != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        let room = self.rooms.get_mut(operation.room)?;
        let row = room.operations.get(operation.slot)?;
        if room.frontier_control == Some(operation.slot) {
            return Err(Fault::NotReady.into());
        }
        if !matches!(
            row.phase,
            OperationPhase::Complete | OperationPhase::Cancelled | OperationPhase::Failed
        ) {
            return Err(Fault::NotReady.into());
        }
        if let Some(payload) = row.job.payload() {
            self.work.expose(payload)?;
        }
        let mut row = room.operations.remove(operation.slot)?;
        if let Some(payload) = row.job.take_payload() {
            self.work.remove(payload)?;
        }
        #[cfg(feature = "alloc")]
        if room
            .automatic_proposal
            .is_some_and(|proposal| proposal.operation == operation.slot)
            && row.phase != OperationPhase::Complete
            && row.written == 0
        {
            room.automatic_proposal = None;
        }
        if let Ok(source) = room.sources.get_mut(row.binding.source)
            && source.join_operation == Some(operation.slot)
        {
            source.join_operation = None;
        }
        let bytes = row.charged_bytes;
        self.release(bytes)?;
        Ok(())
    }
    /// Actual source-stop observation, called only after its native owner has
    /// physically stopped. Original authenticated history remains; unverified
    /// source frames and pending operations are retired without moving them.
    pub fn source_stopped(&mut self, source: Source<'id>) -> Result<(), Error> {
        self.retire_source(source, false)
    }
    /// Observe actual physical owner cancellation; no wire cancel is invented.
    pub fn source_cancelled(&mut self, source: Source<'id>) -> Result<(), Error> {
        self.retire_source(source, true)
    }

    /// Reclaim only inputs that never entered the authenticated room graph.
    /// The caller must validate its own source and terminal work before this
    /// step. Any extra completed work is charged against the same preflight.
    pub(crate) fn reclaim_source_inputs(
        &mut self,
        source: Source<'id>,
        retired_work_bytes: usize,
    ) -> Result<(), Error> {
        let inputs = self
            .rooms
            .get_mut(source.room)?
            .unverified_inputs(source, &self.frames)?;
        let charge = inputs.as_ref().map_or(0, |inputs| inputs.charge());
        let remaining = self
            .used
            .checked_sub(retired_work_bytes)
            .and_then(|used| used.checked_sub(charge))
            .ok_or(Fault::Conflict)?;
        if let Some(inputs) = inputs {
            // These public observations carry a hash, not an admission ID.
            // Remove them before the same original hash can be readmitted.
            self.events.retain(|event| match event {
                QueuedEvent::MessageChanged(r, hash, _) | QueuedEvent::Rejected(r, hash, _)
                    if *r == source.room =>
                {
                    !inputs.contains(hash)
                }
                _ => true,
            });
            inputs.reclaim(&mut self.frames)?;
        }
        self.used = remaining;
        Ok(())
    }

    fn retire_source(&mut self, source: Source<'id>, cancelled: bool) -> Result<(), Error> {
        self.check_source(source)?;
        self.reserve_events(2)?;
        #[cfg(feature = "alloc")]
        self.clear_frontier_scratch(source)?;
        self.reclaim_source_inputs(source, 0)?;
        let room = self.rooms.get_mut(source.room)?;
        let stopped = room.sources.remove(source.slot)?;
        if room.frontier_control.is_some_and(|control| {
            room.operations
                .get(control)
                .is_ok_and(|operation| operation.binding.source == source.slot)
        }) {
            room.frontier_control = None;
            room.frontier_base = None;
            room.frontier_control_hash = None;
        }
        for (_, op) in room.operations.iter_mut() {
            if op.binding.source == source.slot
                && !matches!(op.phase, OperationPhase::Complete | OperationPhase::Failed)
            {
                op.phase = if cancelled {
                    OperationPhase::Cancelled
                } else {
                    OperationPhase::Failed
                };
            }
        }
        let detached = self.mode.is_client() && stopped.role == SourceRole::Client;
        if detached {
            room.frontier_reset = true;
            room.frontier_base = None;
            room.frontier_control_hash = None;
            for (_, s) in room.subscriptions.iter_mut() {
                s.keep_alive = false;
                s.renew_at = None;
                s.renew_operation = None;
            }
            room.joined = false;
            room.local_id = None;
            room.sync_phase = None;
            room.phase = RoomPhase::Detached;
        }
        #[cfg(feature = "alloc")]
        let count = self.rooms.get(source.room)?.operations.limit();
        #[cfg(feature = "alloc")]
        for i in 0..count {
            if let Some(s) = self.rooms.get(source.room)?.operations.slot_at(i) {
                let o = self.rooms.get(source.room)?.operations.get(s)?;
                if o.binding.source == source.slot && matches!(&o.job, Job::SharedKey) {
                    self.reset_failed_key_job(source.room, s)?;
                }
            }
        }
        self.event(Event::SourceLost(source))?;
        if detached {
            self.event(Event::RoomChanged(
                self.event_room(source.room),
                RoomPhase::Detached,
            ))?;
        }
        Ok(())
    }
    /// Borrow one retained message or deletion tombstone, with its resident
    /// original or exact archive location when the original still exists.
    pub fn message(&self, room: Room<'id>, hash: &Hash) -> Result<MessageRef<'_, 'id>, Error> {
        let r = self.rooms.get(self.check_room(room)?)?;
        let slot = r.find_node(hash).ok_or(Fault::NotFound)?;
        MessageRef::new(r.nodes.get(slot)?, r, &self.frames, self.instance)
    }
    /// Resolve the actual completed private message's recipient Contact. A
    /// recovered zone key without matching historical membership remains None.
    #[cfg(feature = "alloc")]
    pub fn recipient(&self, room: Room<'id>, hash: &Hash) -> Result<Option<Contact<'id>>, Error> {
        Ok(self.message(room, hash)?.recipient())
    }
    /// Start a bounded iterative walk authorized by the original member session.
    /// The workspace must fit every configured message slot in the room.
    pub fn history<'a, 'w>(
        &'a self,
        member: MemberSession<'id>,
        hash: &Hash,
        work: &'w mut HistoryWorkspace<'_>,
    ) -> Result<History<'a, 'w, 'id>, Error> {
        self.check_member(member)?;
        let room = self.rooms.get(member.room)?;
        let session = room.sessions.get(member.slot)?;
        if matches!(
            session.phase,
            SessionPhase::Joining | SessionPhase::Completed
        ) {
            return Err(Error::Permission);
        }
        History::start(room, session, &self.frames, self.instance, hash, work)
    }
    /// Iterate actual member sessions, including retained closing/completed history.
    pub fn members(
        &self,
        room: Room<'id>,
    ) -> Result<
        impl Iterator<Item = (MemberSession<'id>, Contact<'id>, ShortHash, SessionPhase)> + '_,
        Error,
    > {
        let r = self.check_room(room)?;
        let instance = self.instance;
        Ok(self.rooms.get(r)?.sessions.iter().map(move |(s, m)| {
            (
                instance.member_id(r, s),
                instance.contact_id(m.contact),
                m.id,
                m.phase,
            )
        }))
    }
    /// Borrow the actual current public contact key without secret material.
    pub fn contact_public(&self, contact: Contact<'id>) -> Result<&PublicKey, Error> {
        if contact.core != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(&self.contacts.get(contact.slot)?.key)
    }
    /// Borrow the actual first-NUL name content retained by NAME application.
    pub fn contact_name(&self, contact: Contact<'id>) -> Result<Option<&[u8]>, Error> {
        if contact.core != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        self.contact_name_at(contact.slot)
    }

    pub(crate) fn contact_name_at(&self, slot: Slot) -> Result<Option<&[u8]>, Error> {
        self.contacts
            .get(slot)?
            .name
            .as_ref()
            .map(|name| self.names.expose(name))
            .transpose()
    }

    pub(crate) fn replace_contact_name(&mut self, slot: Slot, content: &[u8]) -> Result<(), Error> {
        if content.len() > self.limits.name_bytes {
            return Err(Fault::TooLarge.into());
        }
        let row = self.contacts.get_mut(slot)?;
        let base = self
            .used
            .checked_sub(row.name.as_ref().map_or(0, RetainedFrame::capacity))
            .ok_or(Fault::Conflict)?;
        let budget = self
            .limits
            .total_bytes
            .checked_sub(base)
            .ok_or(Fault::Conflict)?;
        let name = self
            .names
            .retain(content, row.name.as_ref(), budget)
            .map_err(|(error, _)| error)?;
        self.used = base + name.capacity();
        row.name = Some(name);
        Ok(())
    }
    /// Inspect one original local operation without fabricating an RPC result.
    pub fn operation_phase(&self, operation: Operation<'id>) -> Result<OperationPhase, Error> {
        if operation.core != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(self
            .rooms
            .get(operation.room)?
            .operations
            .get(operation.slot)?
            .phase)
    }

    /// The immutable logical deadline of the exact original operation.
    pub fn operation_deadline(&self, operation: Operation<'id>) -> Result<u64, Error> {
        if operation.core != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(self
            .rooms
            .get(operation.room)?
            .operations
            .get(operation.slot)?
            .deadline)
    }
}
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Whether another bounded advance turn can progress queued graph work.
    pub fn has_work(&self, room: Room<'id>) -> Result<bool, Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        #[cfg(feature = "alloc")]
        if row.derivation.pending()
            || row
                .frontier_validation
                .as_ref()
                .is_some_and(|v| v.runnable())
        {
            return Ok(true);
        }
        Ok(!row.ready.is_empty()
            || row.has_completion_work()
            || row.epochs.iter().any(|(_, e)| {
                !e.complete
                    && e.parents.iter().all(|p| {
                        *p == [0; 64]
                            || row
                                .find_epoch(p)
                                .and_then(|s| row.epochs.get(s).ok())
                                .is_some_and(|e| e.complete)
                    })
            }))
    }
    /// Actual room flags, interpreted using the pinned producer bitfield profile.
    pub fn room_capabilities(&self, room: Room<'id>) -> Result<RoomCapabilities, Error> {
        Ok(self.rooms.get(self.check_room(room)?)?.capabilities)
    }
    /// Real peer announcements and connection policy, for an external routing
    /// owner. Presence never claims an established CADET tunnel or reachability.
    pub fn peers(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = (&[u8; 32], bool, u32, u32)> + '_, Error> {
        Ok(self
            .rooms
            .get(self.check_room(room)?)?
            .queues
            .peers
            .iter()
            .map(|p| {
                let connection = p.connection().unwrap_or_default();
                (
                    &p.peer,
                    p.is_announced(),
                    connection.amount,
                    connection.flags,
                )
            }))
    }
    /// Every actual original operation observation, including failures after a
    /// physical source stop. Terminal slots remain until explicitly retired.
    pub fn operations(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = (Binding<'id>, OperationPhase)> + '_, Error> {
        let r = self.check_room(room)?;
        Ok(self
            .rooms
            .get(r)?
            .operations
            .iter()
            .map(move |(slot, o)| (o.binding.bind(self.instance, r, slot), o.phase)))
    }
    /// Deferred encrypted/signer/parent messages, without copying retained data.
    pub fn deferred(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = (&Hash, MessagePhase)> + '_, Error> {
        Ok(self
            .rooms
            .get(self.check_room(room)?)?
            .nodes
            .iter()
            .filter(|(_, n)| {
                matches!(
                    n.phase,
                    MessagePhase::AwaitingSender
                        | MessagePhase::AwaitingEpoch
                        | MessagePhase::AwaitingParents
                )
            })
            .map(|(_, n)| (&n.hash, n.phase)))
    }
    /// Authenticated retained ciphertext awaiting a plaintext interpretation.
    /// Presence here does not prove membership, key availability or AEAD success.
    /// Other deferred graph/control work is excluded from crypto scheduling.
    #[cfg(feature = "alloc")]
    pub fn pending_decryption(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = &Hash> + '_, Error> {
        Ok(self
            .rooms
            .get(self.check_room(room)?)?
            .nodes
            .iter()
            .filter(|(_, node)| {
                node.phase == MessagePhase::AwaitingEpoch
                    && node.auth.is_some()
                    && node.frame.as_ref().is_some_and(RetainedFrame::is_resident)
                    && node.plaintext.is_none()
                    && matches!(node.kind, Kind::SECRET | Kind::PRIVATE)
            })
            .map(|(_, node)| &node.hash))
    }
    /// Exact member/session subscription gate for a real TALK delivery. It uses
    /// inclusive official timestamp bounds and never global public-key aliases.
    pub fn may_deliver_talk(
        &self,
        member: MemberSession<'id>,
        discourse: &ShortHash,
        timestamp: u64,
    ) -> Result<bool, Error> {
        self.check_member(member)?;
        let row = self.rooms.get(member.room)?;
        let m = row.sessions.get(member.slot)?;
        Ok(m.phase != SessionPhase::Completed
            && row.subscription_covers(m.lineage, discourse, timestamp))
    }
    /// Dispose an actual detached room only after all native sources are gone
    /// and original work is terminal. This erases owned keys/plaintext/frames
    /// and releases the exact retained accounting, with fresh future generations.
    pub fn forget_room(&mut self, room: Room<'id>) -> Result<(), Error> {
        let r = self.check_room(room)?;
        let row = self.rooms.get(r)?;
        if row.sources.len() != 0
            || row.operations.iter().any(|(_, o)| {
                !matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
            })
        {
            return Err(Fault::NotReady.into());
        }
        let bytes = row.retained_bytes()?;
        let remaining = self.used.checked_sub(bytes).ok_or(Fault::Conflict)?;
        // Validate custody before invalidating the room or publishing its slot.
        for (_, node) in row.nodes.iter() {
            node.original(&self.frames)?;
        }
        for (_, operation) in row.operations.iter() {
            if let Some(payload) = operation.job.payload() {
                self.work.expose(payload)?;
            }
        }
        let partition = self
            .room_partitions
            .as_mut()
            .map(|history| history.vacant_partition(r.index))
            .transpose()?;
        let row = self.rooms.get_mut(r)?;
        for (_, node) in row.nodes.iter_mut() {
            if let Some(frame) = node.frame.take() {
                self.frames.remove(frame)?;
            }
        }
        for (_, operation) in row.operations.iter_mut() {
            if let Some(payload) = operation.job.take_payload() {
                self.work.remove(payload)?;
            }
        }
        let row = self.rooms.remove(r)?;
        if let Some(partition) = partition {
            *partition = Some(row.into_partition()?);
        } else {
            drop(row);
        }
        self.used = remaining;
        for i in 0..self.contacts.limit() {
            let Some(contact) = self.contacts.slot_at(i) else {
                continue;
            };
            let referenced = self
                .rooms
                .iter()
                .any(|(_, room)| room.sessions.iter().any(|(_, s)| s.contact == contact));
            if !referenced {
                let c = self.contacts.remove(contact)?;
                if let Some(name) = c.name {
                    let bytes = name.capacity();
                    self.names.remove(name)?;
                    self.release(bytes)?;
                }
            }
        }
        Ok(())
    }
}
