//! Single structural model. Arrays are explicitly public mock metadata, not
//! private keys, generated keys, signatures, digests or cryptographic fixtures.
//! This source calls no crypto, I/O, key provider or native implementation.
use crate::{graph::*, slots::Slots, state::*, *};
use alloc::{collections::VecDeque, vec::Vec};
use wire::{envelope::Kind, padding, profile::Profile};
fn limits() -> Limits {
    Limits {
        rooms: 2,
        contacts: 8,
        sources_per_room: 4,
        sessions_per_room: 8,
        messages_per_room: 16,
        epochs_per_room: 8,
        groups_per_epoch: 4,
        subscriptions_per_room: 8,
        operations_per_room: 8,
        events: 32,
        missing_per_room: 8,
        nonce_per_epoch: 16,
        work_per_turn: 8,
        ..Limits::default()
    }
}
pub(super) fn structural_core<'id>(instance: &'id mut Instance) -> Result<Core<'id>, Error> {
    let limits = limits();
    let rooms = Slots::new(limits.rooms)?;
    let contacts = Slots::new(limits.contacts)?;
    let mut events = VecDeque::new();
    events
        .try_reserve_exact(limits.events)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    let used =
        rooms.bytes()? + contacts.bytes()? + events.capacity() * core::mem::size_of::<Event<'id>>();
    Ok(Core {
        instance: Brand::new(instance),
        limits,
        profile: Profile::LITTLE_255,
        mode: Mode::Client,
        rooms,
        contacts,
        events,
        used,
        anonymous: [0; 36],
        local_peer: None,
        own_signers: Vec::new(),
    })
}
fn mock_source<'id>(brand: Brand<'id>) -> Source<'id> {
    let slot = Slot {
        index: 0,
        generation: 1,
    };
    Source {
        core: brand,
        room: slot,
        slot,
    }
}
fn mock_contact<'id>(brand: Brand<'id>) -> Contact<'id> {
    Contact {
        core: brand,
        room: Slot {
            index: usize::MAX,
            generation: 0,
        },
        slot: Slot {
            index: 0,
            generation: 1,
        },
    }
}
pub(super) fn session<'id>(brand: Brand<'id>, lineage: u64, generation: u64) -> SessionRow<'id> {
    SessionRow {
        contact: mock_contact(brand),
        id: [2; 32],
        public: [3; 36],
        hpke: [4; 36],
        lineage,
        generation,
        known_from: 1,
        phase: SessionPhase::Active,
        archived: false,
        historical_phase: SessionPhase::Active,
        first_bound: [1; 64],
        last_bound: [2; 64],
        successor: None,
        completed_at: None,
    }
}
pub(super) fn node<'id>(
    brand: Brand<'id>,
    hash: u8,
    parent: u8,
    lineage: u64,
    generation: u64,
    sequence: u64,
) -> Result<Node<'id>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(8)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    bytes.extend_from_slice(b"PUBLIC!!");
    Ok(Node {
        hash: [hash; 64],
        origin: MessageOrigin::Live(mock_source(brand)),
        provenance: SourceObservation {
            room: mock_source(brand).room,
            source: mock_source(brand).slot,
            role: SourceRole::Client,
        },
        layout: OriginalLayout::same(Profile::LITTLE_255),
        cipher_layout: None,
        plain_layout: None,
        transcript_layout: None,
        identifier_order: None,
        resume_pending: false,
        meta: ReceiveMeta {
            epoch: [0; 64],
            flags: 0,
            requested: false,
            sender_hash: None,
            context: None,
        },
        phase: MessagePhase::Applied,
        frame: Some(OwnedBytes::new(zeroize::Zeroizing::new(bytes))),
        plaintext: None,
        auth: Some(Authentication {
            owner: Some(Owner {
                contact: mock_contact(brand),
                lineage,
                generation,
            }),
            session: None,
            public: [3; 36],
            peer: None,
        }),
        padding: padding::Decode::Absent,
        plain_padding: padding::Decode::Absent,
        semantic_applied: true,
        complete: false,
        parents: [[parent; 64], [0; 64]],
        references: [[0; 64]; 3],
        frontier_applied: true,
        epoch: [0; 64],
        epoch_indexed: true,
        kind: Kind::TEXT,
        semantic_kind: Kind::TEXT,
        timestamp: 10,
        sequence,
        queued: false,
        requested: false,
        delete_at: None,
        deleted_by: None,
        discourse: None,
        local_sent: false,
        transcript: None,
        private_recipient: None,
        recipient: None,
        visit: 0,
    })
}
fn write_original<'id>(core: &mut Core<'id>, room: Room<'id>) -> Result<Binding<'id>, Error> {
    let Work::Wire { binding, frame, .. } =
        core.take_work(room)?.ok_or(gnunet_types::Error::NotReady)?
    else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    core.write_progress(binding, frame.expose().len(), true)?;
    Ok(binding)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "One public structural model asserts ownership and table invariants with fallible setup"
)]
fn bounded_original_state_model() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let brand = core.instance;
    // Actual slots reject a retired original generation.
    let mut slots = Slots::new(1)?;
    let old = slots.insert(7u32).map_err(|(e, _)| e)?;
    assert_eq!(slots.remove(old)?, 7);
    let new = slots.insert(9u32).map_err(|(e, _)| e)?;
    assert!(old != new);
    assert!(slots.get(old).is_err());
    let mut room = RoomRow::new([1; 64], None, limits(), Profile::LITTLE_255)?;
    let root = room
        .insert_node(node(brand, 1, 0, 1, 1, 1)?)
        .map_err(|r| r.error)?;
    let tail = room
        .insert_node(node(brand, 2, 1, 1, 1, 2)?)
        .map_err(|r| r.error)?;
    assert!(!room.graph_complete(tail)?);
    assert!(room.graph_complete(root)?);
    room.nodes.get_mut(root)?.complete = true;
    assert!(room.graph_complete(tail)?);
    room.nodes.get_mut(tail)?.complete = true;
    // Ownership flows only along an actual successor lineage, never because
    // another session happens to have the same public mock key/contact.
    assert!(owns(&session(brand, 1, 2), room.nodes.get(root)?));
    assert!(!owns(&session(brand, 2, 2), room.nodes.get(root)?));
    let mut future = node(brand, 3, 2, 1, 2, 3)?;
    assert!(!owns(&session(brand, 1, 1), &future));
    future.sequence = 0;
    assert!(!known(&session(brand, 1, 2), &future));
    // A deleted original preserves author/links and does not block descendants.
    assert!(room.erase_message(tail, Some([4; 64]))? > 0);
    assert!(room.nodes.get(tail)?.frame.is_none());
    assert!(room.nodes.get(tail)?.auth.is_some());
    assert!(room.graph_complete(tail)?);
    let mut closing = session(brand, 1, 2);
    closing.phase = SessionPhase::Closing;
    let s = room.sessions.insert(closing).map_err(|(e, _)| e)?;
    room.sequence = 3;
    room.schedule_completion(s)?;
    for _ in 0..8 {
        let _completion = room.completion_step()?;
    }
    assert_eq!(room.sessions.get(s)?.phase, SessionPhase::Completed);
    room.subscriptions
        .insert(Subscription {
            contact: mock_contact(brand),
            discourse: [5; 32],
            lineage: 1,
            start: 10,
            end: 20,
            keep_alive: false,
            duration: 10,
            renew_at: None,
            renew_operation: None,
        })
        .map_err(|(e, _)| e)?;
    assert!(room.subscription_covers(1, &[5; 32], 10));
    assert!(room.subscription_covers(1, &[5; 32], 20));
    assert!(!room.subscription_covers(1, &[5; 32], 21));
    assert!(!room.subscription_covers(2, &[5; 32], 15));
    let mut id = [0; 32];
    id[0] = 7;
    assert_eq!(
        crate::epoch::identifier(Profile::LITTLE_255, &id),
        (true, 3)
    );
    id[0] = 0x83;
    assert_eq!(crate::epoch::identifier(Profile::BIG_255, &id), (true, 3));
    // Original source generations and exact metadata budget are exercised
    // through production public operations, with explicit mock native facts.
    let initial = core.charged_bytes();
    let room = core.room([1; 64], None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.create_submitted(source)?;
    core.on_notification(
        source,
        wire::Response::MemberId {
            key: &[1; 64],
            id: &[2; 32],
            reset: 1,
        },
        10,
    )?;
    core.on_notification(
        source,
        wire::Response::MemberId {
            key: &[1; 64],
            id: &[3; 32],
            reset: 0,
        },
        11,
    )?;
    let row = core.rooms.get(source.room)?.sources.get(source.slot)?;
    assert_eq!(row.member_id, Some([2; 32]));
    assert_eq!(row.pending_member_id, Some([3; 32]));
    core.source_stopped(source)?;
    let replacement =
        core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    assert!(source != replacement);
    assert!(core.create_submitted(source).is_err());
    core.source_cancelled(replacement)?;
    core.forget_room(room)?;
    assert_eq!(core.charged_bytes(), initial);
    // A modeled whole CLOSE and its exact notification retire one room lease,
    // without pretending the shared physical client source has been stopped.
    let room = core.room([1; 64], None)?;
    let other_room = core.room([2; 64], None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    let other_source = core.attach_source(
        other_room,
        SourceRole::Client,
        padding::Decode::Absent,
        None,
    )?;
    core.create_submitted(source)?;
    core.create_submitted(other_source)?;
    let open = core.open(source, 100)?;
    assert_eq!(write_original(&mut core, room)?.operation(), open);
    let notification_room = wire::Room {
        door: &[0; 32],
        key: &[1; 64],
        previous: &[0; 64],
        epoch: &[0; 64],
    };
    core.on_notification(source, wire::Response::Open(notification_room), 20)?;
    core.retire_operation(open)?;
    let close = core.close(source, 100)?;
    assert_eq!(write_original(&mut core, room)?.operation(), close);
    assert!(core.retire_room_lease(source, close).is_err());
    core.on_notification(source, wire::Response::Close(notification_room), 21)?;
    assert!(core.retire_room_lease(other_source, close).is_err());
    let events = core.events.len();
    core.retire_room_lease(source, close)?;
    assert_eq!(core.events.len(), events);
    assert!(core.check_source(source).is_err());
    assert!(core.check_source(other_source).is_ok());
    assert_eq!(core.phase(other_room)?, RoomPhase::Detached);
    core.retire_operation(close)?;
    let mut public = [0x42; 36];
    public[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    core.configure_reopen(room, public)?;
    assert!(core.local_member(room)?.is_none());
    let reopened = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    assert!(reopened != source);
    core.source_cancelled(reopened)?;
    core.source_stopped(other_source)?;
    core.forget_room(room)?;
    core.forget_room(other_room)?;
    assert_eq!(core.charged_bytes(), initial);
    // Service hooks below use only explicit public modeled metadata. No local
    // signature commit, message authentication or real PILS provider is called.
    let room = core.room([3; 64], None)?;
    assert!(
        core.attach_source(
            room,
            SourceRole::ServiceSigner([4; 32]),
            padding::Decode::Absent,
            None
        )
        .is_err()
    );
    core.mode = Mode::Service;
    core.local_peer = Some([4; 32]);
    assert!(
        core.attach_source(
            room,
            SourceRole::ServiceSigner([5; 32]),
            padding::Decode::Absent,
            None
        )
        .is_err()
    );
    let signer = core.attach_source(
        room,
        SourceRole::ServiceSigner([4; 32]),
        padding::Decode::Absent,
        None,
    )?;
    core.release_service_signer(signer)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    assert!(core.service_client(source).is_err());
    let mut old_public = public;
    old_public[35] = 0x43;
    let mut current = session(brand, 1, 2);
    current.public = public;
    let current = core
        .rooms
        .get_mut(room.slot)?
        .sessions
        .insert(current)
        .map_err(|(e, _)| e)?;
    let mut previous = session(brand, 1, 1);
    previous.public = old_public;
    previous.phase = SessionPhase::Closing;
    previous.successor = Some(current);
    core.rooms
        .get_mut(room.slot)?
        .sessions
        .insert(previous)
        .map_err(|(e, _)| e)?;
    // An actual KEY successor retains ID2; its predecessor is history, not a
    // different current principal that can block the new public key's reopen.
    core.bind_service_client(source, public, [2; 32])?;
    let conflicting =
        core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    assert!(
        core.bind_service_client(conflicting, old_public, [2; 32])
            .is_err()
    );
    assert_eq!(core.service_client(source)?, (public, [2; 32]));
    let mut completed = session(brand, 2, 1);
    completed.id = [3; 32];
    completed.public = old_public;
    completed.phase = SessionPhase::Completed;
    core.rooms
        .get_mut(room.slot)?
        .sessions
        .insert(completed)
        .map_err(|(e, _)| e)?;
    core.propose_service_client_id(source, [3; 32])?;
    assert_eq!(core.service_client(source)?, (public, [2; 32]));
    core.release_service_client(conflicting)?;
    core.release_service_client(source)?;
    core.forget_room(room)?;
    assert_eq!(core.charged_bytes(), initial);
    // No model data is presented as a valid message/crypto proof.
    Ok(())
}
