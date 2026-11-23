//! Real local signatures through the independent SERVICE work and history pools.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert public work custody and history commit outcomes"
)]

use gnunet_crypto::eddsa::EddsaPrivateKey;
use gnunet_identity::SecretKey;
#[cfg(feature = "alloc")]
use gnunet_messenger_core::Mode;
use gnunet_messenger_core::{
    Binding, BorrowedBytes, ByteSlot, CommittedArchive, ContactCell, Core, EpochAliasCell,
    EpochCell, EpochMemberCell, Error, EventCell, Hash, HistoryCell, HistoryNodeCell,
    HistorySlotCell, Instance, Limits, MissingCell, OperationCell, OperationPhase, OriginalLayout,
    OriginalPool, OriginalPoolInstance, OriginalSigner, OriginalSlot, ReceiveMeta, Room,
    RoomHistoryStorage, RoomPeerCell, RoomQueueStorage, RoomTableStorage, SensitiveBuffer,
    ServiceBuffers, ServiceRoomStorage, ServiceSignWork, ServiceTables, SessionCell, SourceCell,
    SourceRole, SubscriptionCell,
    archive::ArchiveGraphCell,
    crypto::signature::{SigningHeader, encode_signed_peer},
    wire::{
        self, SensitiveBytes,
        body::{Body, Text},
        padding,
        profile::Profile,
    },
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use zeroize::Zeroizing;

const FRAME_BYTES: usize = 512;
const PROFILE: Profile = Profile::LITTLE_255;
const CONTACTS: usize = 4;
const EVENTS: usize = 16;
const SIGNERS: usize = 2;
const ROOMS: usize = 2;
const SOURCES: usize = 1;
const SESSIONS: usize = 2;
const MESSAGES: usize = 2;
const COMPLETION_VERTICES: usize = 5;
const EPOCHS: usize = 1;
const SUBSCRIPTIONS: usize = 1;
const OPERATIONS: usize = 2;
const MISSING: usize = 1;
const ALIASES: usize = 4 * MESSAGES;

fn sign<'id>(
    key: &EddsaPrivateKey,
    draft: ServiceSignWork<'id, BorrowedBytes<'_, '_>>,
    output: &mut [u8],
) -> Result<(Binding<'id>, usize), Error> {
    let len = encode_signed_peer(
        key,
        SigningHeader {
            timestamp: AbsoluteTime::from_micros(draft.timestamp),
            sender_id: &draft.sender,
            previous: &draft.previous,
        },
        draft.kind,
        SensitiveBytes::new(draft.body.expose()),
        PROFILE,
        padding::Encode::Absent,
        output,
    )?;
    Ok((draft.binding, len))
}

struct Arena {
    history_instance: OriginalPoolInstance,
    history_slots: [OriginalSlot; MESSAGES],
    history_bytes: [u8; MESSAGES * FRAME_BYTES],
    work_instance: OriginalPoolInstance,
    work_slots: [OriginalSlot; 1],
    work_bytes: [u8; FRAME_BYTES],
    workspace: [u8; FRAME_BYTES],
    key_ancestry: [HistoryCell; MESSAGES],
    nodes: [HistoryNodeCell; ROOMS * MESSAGES],
    index: [HistorySlotCell; ROOMS * MESSAGES],
    ready: [HistorySlotCell; ROOMS * MESSAGES],
    sources: [SourceCell; ROOMS * SOURCES],
    sessions: [SessionCell; ROOMS * SESSIONS],
    epochs: [EpochCell; ROOMS * EPOCHS],
    epoch_members: [EpochMemberCell; ROOMS * SESSIONS],
    subscriptions: [SubscriptionCell; ROOMS * SUBSCRIPTIONS],
    operations: [OperationCell; ROOMS * OPERATIONS],
    missing: [MissingCell; ROOMS * MISSING],
    frontier: [Hash; ROOMS * MESSAGES],
    peers: [RoomPeerCell; ROOMS * SOURCES],
    completion_marks: [HistoryCell; ROOMS * COMPLETION_VERTICES],
    completion_queue: [HistorySlotCell; ROOMS * SESSIONS],
    aliases: [EpochAliasCell; ROOMS * ALIASES],
    contacts: [ContactCell; CONTACTS],
    name_instance: OriginalPoolInstance,
    name_slots: [OriginalSlot; CONTACTS],
    name_bytes: [u8; FRAME_BYTES],
    events: [EventCell; EVENTS],
    own_signers: [[u8; 32]; SIGNERS],
}

impl Arena {
    const fn new() -> Self {
        Self {
            history_instance: OriginalPoolInstance::new(),
            history_slots: [OriginalSlot::EMPTY; MESSAGES],
            history_bytes: [0; MESSAGES * FRAME_BYTES],
            work_instance: OriginalPoolInstance::new(),
            work_slots: [OriginalSlot::EMPTY],
            work_bytes: [0; FRAME_BYTES],
            workspace: [0; FRAME_BYTES],
            key_ancestry: [HistoryCell::EMPTY; MESSAGES],
            nodes: [const { HistoryNodeCell::empty() }; ROOMS * MESSAGES],
            index: [HistorySlotCell::empty(); ROOMS * MESSAGES],
            ready: [HistorySlotCell::empty(); ROOMS * MESSAGES],
            sources: [const { SourceCell::empty() }; ROOMS * SOURCES],
            sessions: [const { SessionCell::empty() }; ROOMS * SESSIONS],
            epochs: [const { EpochCell::empty() }; ROOMS * EPOCHS],
            epoch_members: [EpochMemberCell::empty(); ROOMS * SESSIONS],
            subscriptions: [const { SubscriptionCell::empty() }; ROOMS * SUBSCRIPTIONS],
            operations: [const { OperationCell::empty() }; ROOMS * OPERATIONS],
            missing: [const { MissingCell::empty() }; ROOMS * MISSING],
            frontier: [[0; 64]; ROOMS * MESSAGES],
            peers: [const { RoomPeerCell::empty() }; ROOMS * SOURCES],
            completion_marks: [HistoryCell::EMPTY; ROOMS * COMPLETION_VERTICES],
            completion_queue: [HistorySlotCell::empty(); ROOMS * SESSIONS],
            aliases: [const { EpochAliasCell::empty() }; ROOMS * ALIASES],
            contacts: [const { ContactCell::empty() }; CONTACTS],
            name_instance: OriginalPoolInstance::new(),
            name_slots: [OriginalSlot::EMPTY; CONTACTS],
            name_bytes: [0; FRAME_BYTES],
            events: [const { EventCell::empty() }; EVENTS],
            own_signers: [[0; 32]; SIGNERS],
        }
    }

    fn buffers(&mut self) -> ServiceBuffers<'_, ROOMS> {
        self.buffers_with_history(1)
    }

    fn buffers_with_history(&mut self, history_slots: usize) -> ServiceBuffers<'_, ROOMS> {
        let history = OriginalPool::new(
            &mut self.history_instance,
            &mut self.history_slots[..history_slots],
            &mut self.history_bytes[..history_slots * FRAME_BYTES],
        );
        let work = OriginalPool::new(
            &mut self.work_instance,
            &mut self.work_slots,
            &mut self.work_bytes,
        );
        let history_rows =
            RoomHistoryStorage::new(&mut self.nodes, &mut self.index, &mut self.ready);
        let room_tables = RoomTableStorage::new(
            &mut self.sources,
            &mut self.sessions,
            &mut self.epochs,
            &mut self.subscriptions,
            &mut self.operations,
            &mut self.missing,
        );
        let queues = RoomQueueStorage::new(
            &mut self.frontier,
            &mut self.peers,
            &mut self.completion_marks,
            &mut self.completion_queue,
        );
        let rooms = ServiceRoomStorage::new(
            history_rows,
            room_tables,
            queues,
            &mut self.aliases,
            &mut self.epoch_members,
        );
        let names = OriginalPool::new(
            &mut self.name_instance,
            &mut self.name_slots,
            &mut self.name_bytes,
        );
        let tables = ServiceTables::new(
            &mut self.contacts,
            names,
            &mut self.events,
            &mut self.own_signers,
        );
        ServiceBuffers::new(
            history,
            &mut self.workspace,
            rooms,
            work,
            tables,
            &mut self.key_ancestry,
        )
    }
}

fn limits() -> Limits {
    Limits {
        rooms: ROOMS,
        contacts: CONTACTS,
        sources_per_room: SOURCES,
        sessions_per_room: SESSIONS,
        messages_per_room: MESSAGES,
        epochs_per_room: EPOCHS,
        subscriptions_per_room: SUBSCRIPTIONS,
        operations_per_room: OPERATIONS,
        missing_per_room: MISSING,
        events: EVENTS,
        own_signers: SIGNERS,
        frame_bytes: FRAME_BYTES,
        name_bytes: FRAME_BYTES,
        ..Limits::default()
    }
}

#[test]
fn inline_room_capacity_must_match_the_service_profile() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut arena = Arena::new();
    let mut different_size = limits();
    different_size.rooms += 1;
    assert!(matches!(
        Core::with_service_buffers(&mut instance, different_size, PROFILE, arena.buffers()),
        Err(Error::Protocol(Fault::Capacity))
    ));

    let mut core = Core::with_service_buffers(&mut instance, limits(), PROFILE, arena.buffers())?;
    for id in 1..=ROOMS {
        core.room([u8::try_from(id).map_err(|_| Fault::Overflow)?; 64], None)?;
    }
    assert_eq!(core.room([0; 64], None), Err(Fault::Capacity.into()));
    Ok(())
}

#[test]
fn signed_work_survives_history_backpressure_and_reuses_the_work_slot() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut arena = Arena::new();
    let mut core = Core::with_service_buffers(&mut instance, limits(), PROFILE, arena.buffers())?;
    let key = EddsaPrivateKey::from_seed([7; 32]);
    let peer = *key.public_key().as_bytes();
    let before_signer = core.charged_bytes();
    core.configure_local_peer(peer)?;
    assert_eq!(core.charged_bytes(), before_signer);
    let role = SourceRole::ServiceSigner(peer);
    let body = Body::Peer { peer: &peer };
    let padding = padding::Decode::Absent;
    let mut draft_bytes = [0; 32];
    let output = ByteSlot::new(&mut draft_bytes);

    let blocking_room = core.room([1; 64], None)?;
    let blocker = core.attach_source(blocking_room, role, padding, None)?;
    core.prepare_peer(blocker, peer, body, 10, 100)?;
    let mut blocking_frame = Zeroizing::new([0; FRAME_BYTES]);
    let (blocking_binding, len) = sign(
        &key,
        core.take_service_signing_work_into(blocking_room, &output)?
            .ok_or(Fault::NotReady)?,
        &mut blocking_frame[..],
    )?;
    let blocking_frame = &blocking_frame[..len];
    core.complete_signature_from(blocking_binding, blocking_frame, padding, 11)?;
    let blocking_hash = core.service_commit_signature(blocking_binding, 11)?;
    core.retire_operation(blocking_binding.operation())?;
    while core.pop_event().is_some() {}
    assert_eq!(
        core.service_message_epoch(blocking_room, &blocking_hash)?,
        blocking_hash,
        "the retained frame has not yet supplied an epoch hint"
    );
    let before_indexing = core.charged_bytes();
    assert!(core.advance(blocking_room, 11)? > 0);
    assert_eq!(core.charged_bytes(), before_indexing);
    assert_eq!(
        core.service_message_epoch(blocking_room, &blocking_hash)?,
        [0; 64],
        "the signed PEER inherits the zero predecessor's epoch"
    );
    assert_eq!(core.peers(blocking_room)?.next(), Some((&peer, true, 0, 0)));
    while core.pop_event().is_some() {}

    let room = core.room([2; 64], None)?;
    let signer = core.attach_source(room, role, padding, None)?;
    let operation = core.prepare_peer(signer, peer, body, 20, 100)?;
    let mut short_bytes = [0; 31];
    let short = ByteSlot::new(&mut short_bytes);
    let draft_charge = core.charged_bytes();
    assert!(matches!(
        core.take_service_signing_work_into(room, &short),
        Err(Error::Protocol(Fault::Capacity))
    ));
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Prepared);
    assert_eq!(core.charged_bytes(), draft_charge);
    let mut original = Zeroizing::new([0; FRAME_BYTES]);
    let (binding, len) = sign(
        &key,
        core.take_service_signing_work_into(room, &output)?
            .ok_or(Fault::NotReady)?,
        &mut original[..],
    )?;
    let original = &original[..len];
    assert_eq!(binding.operation(), operation);
    core.complete_signature_from(binding, original, padding, 21)?;
    while core.pop_event().is_some() {}

    let wire_charge = core.charged_bytes();
    assert_eq!(
        core.service_commit_signature(binding, 21),
        Err(Fault::Capacity.into())
    );
    assert_eq!(
        core.charged_bytes(),
        wire_charge,
        "refusal changed the work charge"
    );
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Prepared);
    assert!(
        core.pop_event().is_none(),
        "refusal published a state change"
    );
    assert!(matches!(
        core.message(room, binding.message()),
        Err(Error::Protocol(Fault::NotFound))
    ));
    assert!(core.message(blocking_room, &blocking_hash)?.original() == Some(blocking_frame));
    assert_eq!(
        core.prepare_peer(signer, peer, body, 22, 100),
        Err(Fault::Capacity.into()),
        "the blocked signature must keep the only work slot"
    );

    core.source_stopped(blocker)?;
    core.forget_room(blocking_room)?;
    let replacement = core.room([1; 64], None)?;
    assert_ne!(replacement, blocking_room);
    assert_eq!(
        core.service_message_epoch(replacement, &blocking_hash)?,
        blocking_hash,
        "the reused room slot cannot retain the retired epoch hint"
    );
    assert!(core.peers(replacement)?.next().is_none());
    let before_commit = core.charged_bytes();
    let hash = core.service_commit_signature(binding, 23)?;
    assert_eq!(&hash, binding.message());
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Complete);
    assert_eq!(
        core.charged_bytes(),
        before_commit,
        "commit transfers one frame charge"
    );
    let stored = core.message(room, &hash)?;
    assert!(stored.original() == Some(original));
    assert_eq!(stored.original_signer(), Some(OriginalSigner::Peer(peer)));

    core.retire_operation(operation)?;
    assert_eq!(
        core.charged_bytes(),
        before_commit,
        "retirement must not release history bytes"
    );
    core.prepare_peer(signer, peer, body, 24, 100)?;
    Ok(())
}

struct StoredArchive<'a>(&'a [u8]);

impl CommittedArchive for StoredArchive<'_> {
    fn generation(&self) -> u64 {
        7
    }

    fn expose_committed(&self) -> &[u8] {
        self.0
    }
}

const MEMBER_NAME: &[u8] = b"remote member";

fn receive_join_and_name<'id, const N: usize>(
    core: &mut Core<'id, N>,
    room: Room<'id>,
    peer: [u8; 32],
    key: &SecretKey,
) -> Result<Hash, Error> {
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let public = key.public_key()?;
    let meta = |epoch| ReceiveMeta {
        epoch,
        flags: 8,
        requested: false,
        sender_hash: None,
        context: None,
    };
    let sign = |previous: &Hash, body, timestamp| {
        let mut frame = SensitiveBuffer::<FRAME_BYTES>::new();
        frame.encode_signed(
            key,
            SigningHeader {
                timestamp: AbsoluteTime::from_micros(timestamp),
                sender_id: &[2; 32],
                previous,
            },
            body,
            PROFILE,
            padding::Encode::Absent,
        )?;
        Ok::<_, Error>(frame)
    };
    let zero = [0; 64];
    let join = sign(
        &zero,
        Body::Join {
            epoch: &zero,
            public_key: wire::PublicKey::new(&public)?,
            hpke_key: wire::keys::HpkePublicKey::new(&[0; 36])?,
        },
        10,
    )?;
    let layout = OriginalLayout::same(PROFILE);
    let epoch = core.receive_borrowed(source, meta(zero), layout, join.expose())?;
    while core.pop_event().is_some() {}
    core.advance(room, 10)?;
    assert!(core.message(room, &epoch)?.semantic_applied());

    let name = sign(
        &epoch,
        Body::Name {
            name: Text::new(MEMBER_NAME)?,
        },
        11,
    )?;
    let hash = core.receive_borrowed(source, meta(epoch), layout, name.expose())?;
    while core.pop_event().is_some() {}
    core.advance(room, 11)?;
    assert!(core.message(room, &hash)?.semantic_applied());
    Ok(epoch)
}

#[test]
fn signed_epoch_members_and_name_roundtrip() -> Result<(), Error> {
    const ARCHIVE_BYTES: usize = 4096;
    let mut secret = Zeroizing::new([3; 36]);
    secret[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    let key = SecretKey::from_serialized(&secret[..])?;
    let peer = *EddsaPrivateKey::from_seed([4; 32]).public_key().as_bytes();
    let mut fixed_image = Zeroizing::new([0; ARCHIVE_BYTES]);
    let mut instance = Instance::new();
    let mut arena = Arena::new();
    let mut fixed = Core::with_service_buffers(
        &mut instance,
        limits(),
        PROFILE,
        arena.buffers_with_history(MESSAGES),
    )?;
    let local_peer = *EddsaPrivateKey::from_seed([5; 32]).public_key().as_bytes();
    fixed.configure_local_peer(local_peer)?;
    let room_key = [7; 64];
    let room = fixed.room(room_key, None)?;
    let epoch = receive_join_and_name(&mut fixed, room, peer, &key)?;
    let fixed_bytes = fixed.prepare_archive_into(&mut fixed_image[..])?;
    #[cfg(feature = "alloc")]
    {
        let mut owned_image = Zeroizing::new([0; ARCHIVE_BYTES]);
        let mut owned_instance = Instance::new();
        let mut owned = Core::new(&mut owned_instance, Mode::Service, limits(), PROFILE)?;
        owned.configure_local_peer(local_peer)?;
        let owned_room = owned.room(room_key, None)?;
        assert_eq!(
            receive_join_and_name(&mut owned, owned_room, peer, &key)?,
            epoch
        );
        let owned_bytes = owned.prepare_archive_into(&mut owned_image[..])?;
        assert!(fixed_bytes.expose() == owned_bytes.expose());
    }
    drop(fixed);

    let mut graph = [const { ArchiveGraphCell::empty() }; MESSAGES];
    let (mut restored, _, _) = Core::recover_archive_with_service_buffers(
        &mut instance,
        &StoredArchive(fixed_bytes.expose()),
        limits(),
        PROFILE,
        ARCHIVE_BYTES,
        arena.buffers_with_history(MESSAGES),
        &mut graph,
    )?
    .into_parts();
    let room = restored.room(room_key, None)?;
    let mut contacts = restored.epoch_members(room, &epoch)?;
    let contact = contacts.next().ok_or(Fault::NotFound)?;
    assert!(contacts.next().is_none());
    assert_eq!(restored.contact_public(contact)?, &key.public_key()?);
    assert_eq!(restored.contact_name(contact)?, Some(MEMBER_NAME));
    Ok(())
}

#[cfg(feature = "alloc")]
#[test]
fn heap_archive_restores_signer_history_without_restoring_a_live_signer() -> Result<(), Error> {
    let mut heap_instance = Instance::new();
    let original_key = EddsaPrivateKey::from_seed([1; 32]);
    let original_peer = *original_key.public_key().as_bytes();
    let current_peer = *EddsaPrivateKey::from_seed([2; 32]).public_key().as_bytes();
    let mut heap_core = Core::new(&mut heap_instance, Mode::Service, limits(), PROFILE)?;
    heap_core.configure_local_peer(original_peer)?;
    let room_key = [4; 64];
    let room = heap_core.room(room_key, None)?;
    let padding = padding::Decode::Absent;
    let source = heap_core.attach_source(
        room,
        SourceRole::ServiceSigner(original_peer),
        padding,
        None,
    )?;
    heap_core.prepare_peer(
        source,
        original_peer,
        Body::Peer {
            peer: &original_peer,
        },
        10,
        100,
    )?;
    let mut body = [0; 32];
    let mut frame = Zeroizing::new([0; FRAME_BYTES]);
    let (binding, len) = sign(
        &original_key,
        heap_core
            .take_service_signing_work_into(room, &ByteSlot::new(&mut body))?
            .ok_or(Fault::NotReady)?,
        &mut frame[..],
    )?;
    heap_core.complete_signature_from(binding, &frame[..len], padding, 11)?;
    let hash = heap_core.service_commit_signature(binding, 11)?;
    heap_core.retire_operation(binding.operation())?;
    while heap_core.pop_event().is_some() {}
    assert!(heap_core.advance(room, 11)? > 0);
    assert_eq!(heap_core.service_message_epoch(room, &hash)?, [0; 64]);
    const ARCHIVE_BYTES: usize = 4096;
    let mut image = Zeroizing::new([0; ARCHIVE_BYTES]);
    let prepared = heap_core.prepare_archive_into(&mut image[..])?;

    let mut instance = Instance::new();
    let mut arena = Arena::new();
    let mut graph = [const { ArchiveGraphCell::empty() }; {
        if MESSAGES > EPOCHS { MESSAGES } else { EPOCHS }
    }];
    let recovered = Core::recover_archive_with_service_buffers(
        &mut instance,
        &StoredArchive(prepared.expose()),
        limits(),
        PROFILE,
        ARCHIVE_BYTES,
        arena.buffers(),
        &mut graph,
    )?;
    let (mut core, generation, historical_peer) = recovered.into_parts();
    assert_eq!(generation, 7);
    assert_eq!(historical_peer, Some(original_peer));
    assert!(core.is_own_signer(&original_peer));
    assert!(core.pop_event().is_none());
    let room = core.room(room_key, None)?;
    assert_eq!(core.service_message_epoch(room, &hash)?, [0; 64]);
    assert!(core.message(room, &hash)?.original() == Some(&frame[..len]));
    assert!(matches!(
        core.attach_source(
            room,
            SourceRole::ServiceSigner(original_peer),
            padding::Decode::Absent,
            None,
        ),
        Err(Error::Permission)
    ));
    let used = core.charged_bytes();
    core.configure_local_peer(current_peer)?;
    assert_eq!(core.charged_bytes(), used);
    assert!(core.is_own_signer(&current_peer));
    assert!(core.is_own_signer(&original_peer));
    drop(core);

    let fresh = Core::with_service_buffers(&mut instance, limits(), PROFILE, arena.buffers())?;
    assert!(!fresh.is_own_signer(&original_peer));
    assert!(!fresh.is_own_signer(&current_peer));
    Ok(())
}
