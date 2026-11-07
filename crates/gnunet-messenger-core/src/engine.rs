//! Actual bounded room/source/operation ownership and official IPC lifecycle.
use crate::{graph::*, slots::Slots, state::*, *};
use alloc::{collections::VecDeque, vec::Vec};
use core::fmt;
use gnunet_types::Error as Fault;
use wire::{envelope::Kind, padding, profile::Profile};
const GLOBAL: Slot = Slot {
    index: usize::MAX,
    generation: 0,
};
/// Client state retains its received local view; service state also prunes TALK
/// payload outside all real member subscriptions, preserving deletion links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Original initialized local IPC client source.
    Client,
    /// Hosted state with actual subscription pruning; native routing remains external.
    Service,
}
/// Actual source-bound work prepared by the state core. A taken Wire frame is
/// moved to its original native owner; its allocation remains charged until the
/// real terminal receipt/source stop, not merely until this value is returned.
pub enum Work<'id> {
    /// Move actual encoded work to its original native/peer owner.
    Wire {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
        /// Actual official operation family.
        purpose: NativePurpose,
        /// Exact official IPC or raw peer-message framing.
        encoding: Encoding,
        /// Original exclusively owned zeroizing encoded frame.
        frame: OwnedBytes,
    },
    /// Request an actual scoped signature over the original immutable draft.
    Sign {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
        /// Actual official body kind to sign.
        kind: Kind,
        /// Original exclusively owned typed-body encoding, erased on drop.
        body: OwnedBytes,
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
    SharedKey {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
    },
    /// Request a real original local encrypted-record lookup. This is neither
    /// entropy generation nor successful key recovery; its exact original zone
    /// public key is retained independently of cross-room contact mutations.
    EpochRecord {
        /// Immutable original operation/source/member/epoch/identifier scope.
        binding: Binding<'id>,
        /// Exact original private-zone public snapshot selected by this owner.
        public: PublicKey,
    },
    /// Request an actual owned ephemeral key with original finite expiry.
    EphemeralKey {
        /// Immutable original operation/source/member/message scope.
        binding: Binding<'id>,
        /// Original finite ephemeral-key expiration, never reset by a late completion.
        valid_until: u64,
    },
}
impl fmt::Debug for Work<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessengerWork([REDACTED], actual result pending)")
    }
}
/// One original SERVICE signing draft. Taking this value never consumes an
/// already signed Wire job or any member/key-provider work in the same room.
pub struct ServiceSignWork<'id> {
    /// Immutable original operation/source/member/message scope.
    pub binding: Binding<'id>,
    /// Actual official body kind to sign.
    pub kind: Kind,
    /// Original exclusively owned typed body; no second payload copy is retained.
    pub body: OwnedBytes,
    /// Exact authorized public key snapshot.
    pub public: PublicKey,
    /// Original room sender, predecessor and absolute timestamp.
    pub sender: ShortHash,
    /// Original DAG predecessor.
    pub previous: Hash,
    /// Original absolute signing timestamp.
    pub timestamp: u64,
}
impl fmt::Debug for ServiceSignWork<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessengerServiceSignWork([REDACTED], actual result pending)")
    }
}
/// Finite allocation/state owner. Inputs are actual native facts or actual M3
/// cryptographic results. Queuing effects never declares a room/key published.
pub struct Core<'id> {
    pub(crate) instance: Brand<'id>,
    pub(crate) limits: Limits,
    pub(crate) profile: Profile,
    pub(crate) mode: Mode,
    pub(crate) rooms: Slots<RoomRow<'id>>,
    pub(crate) contacts: Slots<ContactRow>,
    pub(crate) events: VecDeque<Event<'id>>,
    pub(crate) used: usize,
    pub(crate) anonymous: PublicKey,
    pub(crate) local_peer: Option<[u8; 32]>,
    /// Sorted locally observed signer provenance, distinct from live authority.
    pub(crate) own_signers: Vec<[u8; 32]>,
}
impl fmt::Debug for Core<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerCore([REDACTED])")
            .field("rooms", &self.rooms.len())
            .field("charged_bytes", &self.used)
            .finish()
    }
}
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
        limits.validate()?;
        profile.validate()?;
        let instance = Brand::new(instance);
        let lower = Slots::<RoomRow<'id>>::required_bytes(limits.rooms)?
            .checked_add(Slots::<ContactRow>::required_bytes(limits.contacts)?)
            .and_then(|n| {
                limits
                    .events
                    .checked_mul(core::mem::size_of::<Event<'id>>())
                    .and_then(|b| n.checked_add(b))
            })
            .ok_or(Fault::Overflow)?;
        if lower > limits.total_bytes {
            return Err(Fault::Capacity.into());
        }
        let rooms = Slots::new(limits.rooms)?;
        let contacts = Slots::new(limits.contacts)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(limits.events)
            .map_err(|_| Fault::Capacity)?;
        let used = rooms
            .bytes()?
            .checked_add(contacts.bytes()?)
            .and_then(|n| {
                events
                    .capacity()
                    .checked_mul(core::mem::size_of::<Event<'id>>())
                    .and_then(|b| n.checked_add(b))
            })
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
            events,
            used,
            anonymous,
            local_peer: None,
            own_signers: Vec::new(),
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
        self.events.pop_front()
    }
    pub(crate) fn event_room(&self, slot: Slot) -> Room<'id> {
        Room {
            core: self.instance,
            room: slot,
            slot,
        }
    }
    pub(crate) fn source_id(&self, room: Slot, slot: Slot) -> Source<'id> {
        Source {
            core: self.instance,
            room,
            slot,
        }
    }
    pub(crate) fn member_id(&self, room: Slot, slot: Slot) -> MemberSession<'id> {
        MemberSession {
            core: self.instance,
            room,
            slot,
        }
    }
    pub(crate) fn contact_id(&self, slot: Slot) -> Contact<'id> {
        Contact {
            core: self.instance,
            room: GLOBAL,
            slot,
        }
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
    pub(crate) fn check_member(&self, id: MemberSession<'id>) -> Result<(), Error> {
        if id.core != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        self.rooms.get(id.room)?.sessions.get(id.slot)?;
        Ok(())
    }
    pub(crate) fn reserve_events(&self, count: usize) -> Result<(), Error> {
        if count > self.events.capacity().saturating_sub(self.events.len()) {
            return Err(Fault::WouldBlock.into());
        }
        Ok(())
    }
    pub(crate) fn event(&mut self, event: Event<'id>) -> Result<(), Error> {
        self.reserve_events(1)?;
        self.events.push_back(event);
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
        if RoomRow::required_bytes(self.limits)? > self.remaining_bytes() {
            return Err(Fault::Capacity.into());
        }
        let row = RoomRow::new(key, local_public, self.limits, profile)?;
        let bytes = row.metadata_bytes()?;
        self.charge(bytes)?;
        let slot = match self.rooms.insert(row) {
            Ok(s) => s,
            Err((e, _)) => {
                self.release(bytes)?;
                return Err(e);
            }
        };
        let id = self.event_room(slot);
        self.event(Event::RoomChanged(id, RoomPhase::Detached))?;
        Ok(id)
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
            })
            .map_err(|(e, _)| e)?;
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
        self.reserve_events(1)?;
        if deadline == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        let len = request.encoded_len()?;
        if len > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(len).map_err(|_| Fault::Capacity)?;
        bytes.resize(len, 0);
        request.encode(&mut bytes)?;
        let frame = OwnedBytes::new(bytes);
        let capacity = frame.capacity();
        let slot = self.rooms.get(source.room)?.operations.next_key()?;
        let operation = Operation {
            core: self.instance,
            room: source.room,
            slot,
        };
        let binding = Binding {
            operation,
            source,
            member,
            message: hash,
            epoch: self.rooms.get(source.room)?.current_epoch,
            identifier: [0; 32],
            epoch_revision: 0,
        };
        self.charge(capacity)?;
        let row = OperationRow {
            binding,
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
        if let Err((e, _)) = self.rooms.get_mut(source.room)?.operations.insert(row) {
            self.release(capacity)?;
            return Err(e);
        }
        self.event(Event::OperationChanged(operation, OperationPhase::Prepared))?;
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
        if purpose == NativePurpose::Open && row.feed && !row.group_room {
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
            self.rooms.get_mut(source.room)?.sync_phase = Some(prior);
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
        self.room_request(source, NativePurpose::Sync, [0; 32], deadline)
    }
    /// Move only original prepared work to its provider. No replacement source,
    /// callback outcome or remote success is synthesized by this transfer.
    pub fn take_work(&mut self, room: Room<'id>) -> Result<Option<Work<'id>>, Error> {
        self.take_work_matching(room, |_| true)
    }
    /// Take only a prepared original signature draft from this SERVICE room.
    /// Signed Wire work stays prepared and owned by Core until its original
    /// local commit or normal generic transport work extraction.
    pub fn take_service_signing_work(
        &mut self,
        room: Room<'id>,
    ) -> Result<Option<ServiceSignWork<'id>>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        match self.take_work_matching(room, |job| matches!(job, Job::Sign { .. }))? {
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
    fn take_work_matching(
        &mut self,
        room: Room<'id>,
        accepts: fn(&Job) -> bool,
    ) -> Result<Option<Work<'id>>, Error> {
        let r = self.check_room(room)?;
        let row = self.rooms.get_mut(r)?;
        let key = row.operations.iter().find_map(|(s, o)| {
            (o.phase == OperationPhase::Prepared && accepts(&o.job)).then_some(s)
        });
        let Some(slot) = key else {
            return Ok(None);
        };
        let op = row.operations.get_mut(slot)?;
        op.phase = OperationPhase::Taken;
        let binding = op.binding;
        Ok(Some(match &mut op.job {
            Job::Wire {
                purpose,
                encoding,
                frame,
                ..
            } => Work::Wire {
                binding,
                purpose: *purpose,
                encoding: *encoding,
                frame: frame.take().ok_or(Fault::Conflict)?,
            },
            Job::Sign {
                body,
                kind,
                public,
                sender,
                previous,
                timestamp,
            } => {
                let mut empty = OwnedBytes::new(zeroize::Zeroizing::new(Vec::new()));
                core::mem::swap(body, &mut empty);
                Work::Sign {
                    binding,
                    kind: *kind,
                    body: empty,
                    public: *public,
                    sender: *sender,
                    previous: *previous,
                    timestamp: *timestamp,
                }
            }
            Job::SharedKey => Work::SharedKey { binding },
            Job::EpochRecord { public } => Work::EpochRecord {
                binding,
                public: *public,
            },
            Job::EphemeralKey { valid_until } => Work::EphemeralKey {
                binding,
                valid_until: *valid_until,
            },
        }))
    }
    pub(crate) fn check_binding(&self, binding: Binding<'id>) -> Result<&OperationRow<'id>, Error> {
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
        if row.binding.operation != binding.operation
            || row.binding.source != binding.source
            || row.binding.member != binding.member
            || row.binding.message != binding.message
            || row.binding.epoch != binding.epoch
            || row.binding.identifier != binding.identifier
            || row.binding.epoch_revision != binding.epoch_revision
        {
            return Err(Fault::StaleGeneration.into());
        }
        if let Some(member) = binding.member {
            self.check_member(member)?;
        }
        Ok(row)
    }
    /// Observe exact original local byte exposure. Complete SEND becomes only
    /// Written; actual receive/absence notifications remain distinct facts.
    pub fn write_progress(
        &mut self,
        binding: Binding<'id>,
        bytes: usize,
        complete: bool,
    ) -> Result<(), Error> {
        self.check_binding(binding)?;
        self.reserve_events(1)?;
        let row = self
            .rooms
            .get_mut(binding.source.room)?
            .operations
            .get_mut(binding.operation.slot)?;
        let Job::Wire { length, .. } = &row.job else {
            return Err(Fault::Conflict.into());
        };
        if row.phase != OperationPhase::Taken {
            return Err(Fault::Replay.into());
        }
        let written = row.written.checked_add(bytes).ok_or(Fault::Overflow)?;
        if written > *length || complete && written != *length {
            return Err(Fault::Malformed.into());
        }
        row.written = written;
        if complete {
            row.phase = OperationPhase::Written;
            self.event(Event::OperationChanged(
                binding.operation,
                OperationPhase::Written,
            ))?;
        }
        Ok(())
    }
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
                (o.binding.source == source
                    && o.phase == OperationPhase::Written
                    && hash.is_none_or(|h| o.binding.message == *h)
                    && matches!(&o.job,Job::Wire {purpose:p,..} if *p==purpose))
                .then_some(s)
            })
    }
    pub(crate) fn finish_wire(&mut self, source: Source<'id>, slot: Slot) -> Result<(), Error> {
        self.reserve_events(1)?;
        let row = self.rooms.get_mut(source.room)?.operations.get_mut(slot)?;
        row.phase = OperationPhase::Complete;
        let op = row.binding.operation;
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
        if !matches!(
            row.phase,
            OperationPhase::Complete | OperationPhase::Cancelled | OperationPhase::Failed
        ) {
            return Err(Fault::NotReady.into());
        }
        let row = room.operations.remove(operation.slot)?;
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
    fn retire_source(&mut self, source: Source<'id>, cancelled: bool) -> Result<(), Error> {
        self.check_source(source)?;
        self.reserve_events(2)?;
        let room = self.rooms.get_mut(source.room)?;
        let stopped = room.sources.remove(source.slot)?;
        let mut released = 0usize;
        for (_, n) in room.nodes.iter_mut() {
            if n.origin.live() == Some(source) && n.auth.is_none() {
                released = released
                    .checked_add(n.payload_bytes())
                    .ok_or(Fault::Overflow)?;
                n.frame = None;
                n.plaintext = None;
                n.phase = MessagePhase::Rejected;
            }
        }
        for (_, op) in room.operations.iter_mut() {
            if op.binding.source == source
                && !matches!(op.phase, OperationPhase::Complete | OperationPhase::Failed)
            {
                op.phase = if cancelled {
                    OperationPhase::Cancelled
                } else {
                    OperationPhase::Failed
                };
            }
        }
        let detached = self.mode == Mode::Client && stopped.role == SourceRole::Client;
        if detached {
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
        self.release(released)?;
        let count = self.rooms.get(source.room)?.operations.limit();
        for i in 0..count {
            if let Some(s) = self.rooms.get(source.room)?.operations.slot_at(i) {
                let o = self.rooms.get(source.room)?.operations.get(s)?;
                if o.binding.source == source && matches!(&o.job, Job::SharedKey) {
                    self.reset_failed_key_job(o.binding)?;
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
    /// Borrow one actual retained message or immutable deletion tombstone.
    pub fn message(&self, room: Room<'id>, hash: &Hash) -> Result<MessageRef<'_, 'id>, Error> {
        let r = self.rooms.get(self.check_room(room)?)?;
        let slot = r.find_node(hash).ok_or(Fault::NotFound)?;
        Ok(MessageRef {
            row: r.nodes.get(slot)?,
            room: r,
            profile: self.profile,
        })
    }
    /// Resolve the actual completed private message's recipient Contact. A
    /// recovered zone key without matching historical membership remains None.
    pub fn recipient(&self, room: Room<'id>, hash: &Hash) -> Result<Option<Contact<'id>>, Error> {
        Ok(self.message(room, hash)?.recipient())
    }
    /// Start a bounded iterative walk authorized by the original member session.
    pub fn history<'a, 'w>(
        &'a self,
        member: MemberSession<'id>,
        hash: &Hash,
        work: &'w mut HistoryWorkspace,
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
        let root = room.find_node(hash).ok_or(Fault::NotFound)?;
        work.reset(root);
        Ok(History {
            room,
            session,
            profile: self.profile,
            work,
        })
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
                MemberSession {
                    core: instance,
                    room: r,
                    slot: s,
                },
                m.contact,
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
        Ok(self
            .contacts
            .get(contact.slot)?
            .name
            .as_ref()
            .map(OwnedBytes::expose))
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
}
impl<'id> Core<'id> {
    /// Whether another bounded advance turn can progress queued graph work.
    pub fn has_work(&self, room: Room<'id>) -> Result<bool, Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        Ok(!row.ready.is_empty()
            || !row.completion_queue.is_empty()
            || row.completion_session.is_some()
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
    pub fn room_flags(&self, room: Room<'id>) -> Result<(bool, bool, bool), Error> {
        let r = self.rooms.get(self.check_room(room)?)?;
        Ok((!r.private, r.group_room, r.feed))
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
            .peers
            .iter()
            .map(|p| {
                (
                    &p.peer,
                    p.announced,
                    p.connection_amount,
                    p.connection_flags,
                )
            }))
    }
    /// Every actual original operation observation, including failures after a
    /// physical source stop. Terminal slots remain until explicitly retired.
    pub fn operations(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = (Binding<'id>, OperationPhase)> + '_, Error> {
        Ok(self
            .rooms
            .get(self.check_room(room)?)?
            .operations
            .iter()
            .map(|(_, o)| (o.binding, o.phase)))
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
        self.rooms.remove(r)?;
        self.release(bytes)?;
        for i in 0..self.contacts.limit() {
            let Some(contact) = self.contacts.slot_at(i) else {
                continue;
            };
            let referenced = self
                .rooms
                .iter()
                .any(|(_, room)| room.sessions.iter().any(|(_, s)| s.contact.slot == contact));
            if !referenced {
                let c = self.contacts.remove(contact)?;
                self.release(c.name.as_ref().map_or(0, OwnedBytes::capacity))?;
            }
        }
        Ok(())
    }
}
impl<'id> Core<'id> {
    /// Exact current active local session in this original room generation.
    /// This uses its own session/public-ID snapshot, never a Contact.key changed
    /// by another room. Absence grants no membership or signing authorization.
    pub fn local_member(&self, room: Room<'id>) -> Result<Option<MemberSession<'id>>, Error> {
        let r = self.check_room(room)?;
        Ok(self
            .rooms
            .get(r)?
            .local_session()
            .map(|s| self.member_id(r, s)))
    }
    /// Original public signing snapshot of this exact checked member session.
    /// Completed historical sessions remain readable; this getter grants no
    /// eligibility to sign or revive their original provider/native operations.
    pub fn member_public(&self, member: MemberSession<'id>) -> Result<&PublicKey, Error> {
        self.check_member(member)?;
        Ok(&self
            .rooms
            .get(member.room)?
            .sessions
            .get(member.slot)?
            .public)
    }
    /// Retire only the original client room lease after its actual matching
    /// CLOSE notification completed the original Written CLOSE operation. This
    /// is not physical MQ loss and emits no SourceLost event. Shared native MQ
    /// epochs and other rooms remain live. Old authenticated history/keys remain;
    /// unverified originals cannot be adopted by a later reopened room lease.
    pub fn retire_room_lease(
        &mut self,
        source: Source<'id>,
        close: Operation<'id>,
    ) -> Result<(), Error> {
        self.check_source(source)?;
        if self.mode != Mode::Client || close.core != self.instance || close.room != source.room {
            return Err(Error::Permission);
        }
        let room = self.rooms.get(source.room)?;
        let source_row = room.sources.get(source.slot)?;
        if source_row.role != SourceRole::Client || room.phase != RoomPhase::Detached {
            return Err(Fault::NotReady.into());
        }
        let operation = room.operations.get(close.slot)?;
        if operation.binding.source != source
            || operation.binding.operation != close
            || operation.phase != OperationPhase::Complete
            || !matches!(
                &operation.job,
                Job::Wire {
                    purpose: NativePurpose::Close,
                    encoding: Encoding::Ipc,
                    ..
                }
            )
        {
            return Err(Fault::StaleGeneration.into());
        }
        if room.operations.iter().any(|(_, o)| {
            !matches!(
                o.phase,
                OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
            )
        }) {
            return Err(Fault::NotReady.into());
        }
        let mut released = 0usize;
        for (_, n) in room.nodes.iter() {
            if n.origin.live() == Some(source) && n.auth.is_none() {
                released = released
                    .checked_add(n.payload_bytes())
                    .ok_or(Fault::Overflow)?;
            }
        }
        // Accounting and every scope/debt preflight precede the first mutation.
        if released > self.used {
            return Err(Fault::Conflict.into());
        }
        let room = self.rooms.get_mut(source.room)?;
        room.sources.remove(source.slot)?;
        for (_, n) in room.nodes.iter_mut() {
            if n.origin.live() == Some(source) && n.auth.is_none() {
                n.frame = None;
                n.plaintext = None;
                n.phase = MessagePhase::Rejected;
            }
        }
        if room.sources.len() == 0 {
            room.joined = false;
            room.local_id = None;
            room.sync_phase = None;
            for (_, s) in room.subscriptions.iter_mut() {
                s.keep_alive = false;
                s.renew_at = None;
                s.renew_operation = None;
            }
        }
        self.release(released)?;
        Ok(())
    }
    /// Configure a new local signing owner for a genuinely detached room with
    /// no live lease or unsettled original work. History retains its original
    /// author/session snapshots. This queues no OPEN/JOIN and proves no key
    /// possession; those require real original native and signature results.
    pub fn configure_reopen(&mut self, room: Room<'id>, public: PublicKey) -> Result<(), Error> {
        let r = self.check_room(room)?;
        wire::PublicKey::new(&public)?;
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(r)?;
        if row.phase != RoomPhase::Detached
            || row.sources.len() != 0
            || row.operations.iter().any(|(_, o)| {
                !matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
            })
        {
            return Err(Fault::NotReady.into());
        }
        let row = self.rooms.get_mut(r)?;
        row.local_public = Some(public);
        row.local_id = None;
        row.joined = false;
        row.sync_phase = None;
        // A known contact may have first appeared remotely in another room.
        // Local configuration records an owner selection, not verification;
        // exact source/member IDs and real signatures still grant all rights.
        for (_, contact) in self.contacts.iter_mut() {
            if contact.key == public {
                contact.local = true;
            }
        }
        Ok(())
    }
}
