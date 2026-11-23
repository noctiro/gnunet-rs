//! Trusted checkpoint fixtures for transient metadata and signed frame paging.
use super::*;
use crate::epoch::EpochMutation;
use wire::envelope::Kind;

const EPOCH: Hash = [17; 64];
const TALK: Hash = [18; 64];
const SUBSCRIPTION: Hash = [19; 64];
const CHILD: Hash = [20; 64];
const DISCOURSE: ShortHash = [117; 32];
const OLD_CONTEXT: Hash = [118; 64];
const OLD_EPOCH: Hash = [119; 64];
const PAYLOAD: &[u8] = b"synthetic transient content must never enter the durable projection";

fn limits() -> Limits {
    Limits {
        rooms: 1,
        contacts: 2,
        sources_per_room: 2,
        sessions_per_room: 2,
        messages_per_room: 8,
        epochs_per_room: 4,
        groups_per_epoch: 1,
        operations_per_room: 2,
        subscriptions_per_room: 2,
        missing_per_room: 2,
        nonce_per_epoch: 1,
        ..Limits::default()
    }
}
fn node(room: Slot, kind: Kind, hash: Hash, parent: Hash, sequence: u64) -> Node {
    let peer = [3; 32];
    let mut public = [0; 36];
    public[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    public[4..].copy_from_slice(&peer);
    Node {
        hash,
        origin: NodeOrigin::archived(
            ArchivedFact {
                generation: 1,
                sequence,
            },
            SourceObservation {
                room,
                source: Slot {
                    index: 0,
                    generation: 1,
                },
                role: SourceRole::Peer(peer),
            },
        ),
        resume_pending: false,
        meta: ReceiveMeta {
            epoch: EPOCH,
            flags: 0,
            requested: false,
            sender_hash: None,
            context: None,
        },
        phase: MessagePhase::Deleted,
        frame: None,
        plaintext: None,
        auth: Some(Authentication {
            owner: None,
            session: None,
            public,
            peer: Some(peer),
        }),
        padding: wire::padding::Decode::Absent,
        layout: OriginalLayout::same(wire::profile::Profile::LITTLE_255),
        cipher_layout: None,
        plain_layout: None,
        transcript_layout: None,
        identifier_order: None,
        semantic_applied: true,
        complete: true,
        parents: [parent, [0; 64]],
        references: [[0; 64]; 3],
        frontier_applied: true,
        frontier_recent: false,
        epoch: EPOCH,
        epoch_indexed: true,
        kind,
        semantic_kind: kind,
        timestamp: sequence,
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
    }
}
fn install_mock<'id>(core: &mut Core<'id>) -> Result<Room<'id>, Error> {
    core.configure_local_peer([9; 32])?;
    let id = core.room([10; 64], None)?;
    let frame_budget = core.remaining_bytes();
    let row = core.rooms.get_mut(id.slot)?;
    row.sequence = 4;
    row.current_epoch = EPOCH;
    row.last_message = CHILD;
    row.queues.frontier.push(CHILD)?;
    row.epoch_aliases.initialize(32, usize::MAX)?;
    let mut payload_bytes = 0;
    for (kind, hash, parent, seq) in [
        (Kind::MERGE, EPOCH, [0; 64], 1),
        (Kind::TALK, TALK, EPOCH, 2),
        (Kind::SUBSCRIPTION, SUBSCRIPTION, TALK, 3),
        (Kind::TEXT, CHILD, SUBSCRIPTION, 4),
    ] {
        let mut n = node(id.slot, kind, hash, parent, seq);
        if crate::graph::discourse_kind(kind) {
            n.phase = MessagePhase::Applied;
            n.frame = Some(core.frames.copy(PAYLOAD, frame_budget - payload_bytes)?);
            n.discourse = Some(DISCOURSE);
            n.meta.context = Some(OLD_CONTEXT);
            n.meta.epoch = OLD_EPOCH;
            n.epoch = EPOCH;
            payload_bytes += n.payload_bytes();
        }
        if hash == CHILD {
            n.complete = false;
        }
        row.insert_node(n)?;
        row.put_alias(hash, EPOCH)?;
    }
    row.epochs
        .insert(EpochRow::hosted(
            EPOCH,
            [[0; 64]; 2],
            EpochMutation::Merge,
            crate::epoch::members::Snapshot::default(),
            true,
            1,
        ))
        .map_err(|(e, _)| e)?;
    let bytes =
        row.epoch_aliases.capacity() * core::mem::size_of::<Option<EpochAlias>>() + payload_bytes;
    core.charge(bytes)?;
    Ok(id)
}
struct Trusted(Zeroizing<Vec<u8>>);
impl CommittedArchive for Trusted {
    fn generation(&self) -> u64 {
        1
    }
    fn expose_committed(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[test]
fn rooted_recovery_verifies_cross_page_parents_and_cycles_without_restoring_pages()
-> Result<(), Error> {
    use core::num::NonZeroU64;
    use gnunet_crypto::EddsaPublicKey;
    const MAXIMUM: usize = 8 * 1024;
    const ROOM: Hash = [10; 64];
    const PARENT: Hash = [11; 64];
    const BETWEEN: Hash = [12; 64];
    const NAMESPACE: [u8; 16] = [14; 16];
    const PROFILE: wire::profile::Profile = wire::profile::Profile::LITTLE_255;
    const PEER: [u8; 32] = [9; 32];

    struct Page<'a>(&'a [u8]);
    impl CommittedGraphPageBytes for Page<'_> {
        fn expose_committed_page(&self) -> &[u8] {
            self.0
        }
    }

    fn recover<'id>(
        instance: &'id mut Instance,
        image: &Trusted,
        pages: CommittedGraphPages<'_, '_>,
    ) -> Result<Core<'id>, Error> {
        let limits = limits();
        let mut cells = [ArchiveGraphCell::empty(); 10];
        assert_eq!(
            ArchiveGraphCell::required_cells_with_detached(limits, 2),
            Some(cells.len())
        );
        Ok(Core::recover_archive_using(
            image,
            limits,
            MAXIMUM,
            DagWorkspace::with_cells(&mut cells, limits)?,
            RecoveryOriginals::Paged,
            pages,
            || Core::new(instance, Mode::Service, limits, PROFILE),
        )?
        .into_parts()
        .0)
    }

    let mut instance = Instance::new();
    let limits = limits();
    let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
    core.configure_local_peer(PEER)?;
    let room = core.room(ROOM, None)?;
    let row = core.rooms.get_mut(room.slot)?;
    row.sequence = 3;
    row.epoch_aliases.initialize(32, usize::MAX)?;
    for (hash, parent, sequence) in [
        (PARENT, [0; 64], 1),
        (BETWEEN, PARENT, 2),
        (CHILD, BETWEEN, 3),
    ] {
        // Deleted payloads have trusted historical metadata but no frame to
        // verify again, which allows constructing an invalid graph cycle.
        let mut n = node(room.slot, Kind::TEXT, hash, parent, sequence);
        n.auth.as_mut().ok_or(Fault::Conflict)?.peer = None;
        row.insert_node(n)?;
        row.put_alias(hash, EPOCH)?;
    }
    let id = |ordinal| {
        GraphPageIdentity::new(
            NAMESPACE,
            EddsaPublicKey::from_bytes(PEER),
            ROOM,
            NonZeroU64::MIN,
            ordinal,
        )
    };
    let mut parent_bytes = [0; 2048];
    let mut between_bytes = [0; 2048];
    let mut cycle_bytes = [0; 2048];
    let no_frame = |_, _: &mut [u8]| Err(Fault::Conflict.into());
    let parent =
        core.prepare_graph_page_into(room, id(1), &[PARENT], &mut parent_bytes, no_frame)?;
    let between =
        core.prepare_graph_page_into(room, id(2), &[BETWEEN], &mut between_bytes, no_frame)?;
    {
        let row = core.rooms.get_mut(room.slot)?;
        let parent = row.find_node(&PARENT).ok_or(Fault::NotFound)?;
        row.nodes.get_mut(parent)?.parents[0] = CHILD;
    }
    let cyclic_parent =
        core.prepare_graph_page_into(room, id(1), &[PARENT], &mut cycle_bytes, no_frame)?;
    {
        let row = core.rooms.get_mut(room.slot)?;
        for hash in [PARENT, BETWEEN] {
            let slot = row.find_node(&hash).ok_or(Fault::NotFound)?;
            row.index.retain(|at| at != slot);
            row.nodes.remove(slot)?;
            row.remove_alias(&hash)?;
        }
    }
    let checkpoint = Trusted(core.prepare_archive(MAXIMUM)?.into_body());
    let parent = Page(parent.expose());
    let cycle = Page(cyclic_parent.expose());
    let between = Page(between.expose());
    let mut indices = [[ArchiveHistoryCell::EMPTY]; 3];
    let [left, middle, right] = &mut indices;
    let parent = CommittedGraphPage::open(&parent, id(1), limits, left)?;
    let cycle = CommittedGraphPage::open(&cycle, id(1), limits, middle)?;
    let between = CommittedGraphPage::open(&between, id(2), limits, right)?;

    let mut restored_instance = Instance::new();
    let pages = [parent, between];
    let mut restored = recover(
        &mut restored_instance,
        &checkpoint,
        CommittedGraphPages::new(NAMESPACE, &pages),
    )?;
    let room = restored.retained_rooms().next().ok_or(Fault::NotFound)?;
    assert!(restored.message(room, &CHILD)?.history_complete());
    for hash in [PARENT, BETWEEN] {
        assert!(matches!(
            restored.message(room, &hash),
            Err(Error::Protocol(Fault::NotFound))
        ));
    }
    // A bounded closing walk crosses both pages while ordinary working
    // publications change the full archive revision between work units.
    let mut offsets = [ArchiveHistoryCell::EMPTY; 1];
    let view =
        CommittedRoomHistory::from_committed(&checkpoint, limits, MAXIMUM, &ROOM, &mut offsets)?
            .ok_or(Fault::NotFound)?;
    let row = restored.rooms.get_mut(room.slot)?;
    row.queues.completion = crate::graph::completion::Completion::owned(10, 1)?;
    let mut closing = crate::model::session(1, 1);
    closing.phase = SessionPhase::Closing;
    closing.first_bound = PARENT;
    closing.last_bound = CHILD;
    let closing = row.sessions.insert(closing).map_err(|(error, _)| error)?;
    row.schedule_completion(closing)?;
    for turn in 1..=3 {
        let revision = NonZeroU64::new(turn).ok_or(Fault::Conflict)?;
        let view = view.with_detached_pages(&NAMESPACE, revision, &pages)?;
        assert!(row.completion_step(Some(&view))? == (turn == 3).then_some(closing));
    }

    let mut rejected = Instance::new();
    assert!(matches!(
        recover(
            &mut rejected,
            &checkpoint,
            CommittedGraphPages::new(NAMESPACE, &[between])
        ),
        Err(Error::Protocol(Fault::Malformed))
    ));
    assert!(matches!(
        recover(
            &mut rejected,
            &checkpoint,
            CommittedGraphPages::new(NAMESPACE, &[cycle, between])
        ),
        Err(Error::Protocol(Fault::Malformed))
    ));
    assert!(matches!(
        recover(
            &mut rejected,
            &checkpoint,
            CommittedGraphPages::new([15; 16], &pages)
        ),
        Err(Error::Protocol(Fault::Authentication))
    ));
    Ok(())
}

#[test]
fn committed_room_history_walks_deleted_ancestry_without_restoring_nodes() -> Result<(), Error> {
    const MAXIMUM: usize = 8 * 1024;
    struct Later(Trusted);
    impl CommittedArchive for Later {
        fn generation(&self) -> u64 {
            2
        }

        fn expose_committed(&self) -> &[u8] {
            self.0.expose_committed()
        }
    }

    let mut instance = Instance::new();
    let limits = Limits {
        rooms: 2,
        ..limits()
    };
    let mut core = Core::new(
        &mut instance,
        Mode::Service,
        limits,
        wire::profile::Profile::LITTLE_255,
    )?;
    install_mock(&mut core)?;
    let key = [12; 64];
    let room = core.room(key, None)?;
    let row = core.rooms.get_mut(room.slot)?;
    row.sequence = 3;
    let first = [23; 64];
    let erased = [22; 64];
    let unfinished = [21; 64];
    row.insert_node(node(room.slot, Kind::TEXT, first, [0; 64], 1))?;
    row.insert_node(node(room.slot, Kind::TEXT, erased, first, 2))?;
    let mut pending = node(room.slot, Kind::TEXT, unfinished, erased, 3);
    pending.complete = false;
    row.insert_node(pending)?;

    let checkpoint = Trusted(core.prepare_archive(MAXIMUM)?.into_body());
    let earlier_hash = [16; 64];
    let row = core.rooms.get_mut(room.slot)?;
    row.sequence = 4;
    let inserted = row.insert_node(node(room.slot, Kind::TEXT, earlier_hash, erased, 4))?;
    let next = Later(Trusted(core.prepare_archive(MAXIMUM)?.into_body()));
    core.rooms
        .get_mut(room.slot)?
        .nodes
        .get_mut(inserted)?
        .sequence = 3;
    let duplicate = Later(Trusted(core.prepare_archive(MAXIMUM)?.into_body()));
    drop(core);
    let mut offsets = [ArchiveHistoryCell::EMPTY; 3];
    assert!(matches!(
        CommittedRoomHistory::from_committed(&checkpoint, limits, MAXIMUM, &key, &mut offsets[..2]),
        Err(Error::Protocol(Fault::Capacity))
    ));
    let history =
        CommittedRoomHistory::from_committed(&checkpoint, limits, MAXIMUM, &key, &mut offsets)?
            .ok_or(Fault::NotFound)?;
    let mut marks = [HistoryCell::EMPTY; 3];
    let mut workspace = HistoryWorkspace::from_cells(&mut marks)?;
    assert!(history.is_ancestor(&first, &erased, &mut workspace)?);
    assert!(!history.is_ancestor(&erased, &first, &mut workspace)?);
    assert!(!history.is_ancestor(&first, &unfinished, &mut workspace)?);
    assert!(!history.is_ancestor(&EPOCH, &erased, &mut workspace)?);

    let mut next_offsets = [ArchiveHistoryCell::EMPTY; 4];
    let later =
        CommittedRoomHistory::from_committed(&next, limits, MAXIMUM, &key, &mut next_offsets)?
            .ok_or(Fault::NotFound)?;
    assert_ne!(later.generation(), history.generation());
    assert_eq!(later.sequence_for(&erased)?, history.sequence_for(&erased)?);
    assert_eq!(history.sequence_for(&earlier_hash)?, None);
    assert_eq!(
        later
            .sequence_for(&earlier_hash)?
            .map(|seq| seq.get().get()),
        Some(4)
    );
    assert!(matches!(
        CommittedRoomHistory::from_committed(&duplicate, limits, MAXIMUM, &key, &mut next_offsets),
        Err(Error::Protocol(Fault::Conflict))
    ));
    Ok(())
}

#[test]
fn single_message_row_preserves_originals_and_projects_transient_traffic() -> Result<(), Error> {
    let mut instance = Instance::new();
    let limits = limits();
    let mut core = Core::new(
        &mut instance,
        Mode::Service,
        limits,
        wire::profile::Profile::LITTLE_255,
    )?;
    let room = install_mock(&mut core)?;
    let frame = core.frames.copy(PAYLOAD, core.remaining_bytes())?;
    core.charge(frame.capacity())?;
    let room = core.rooms.get_mut(room.slot)?;
    let child = room.find_node(&CHILD).ok_or(Fault::NotFound)?;
    let child = room.nodes.get_mut(child)?;
    child.frame = Some(frame);
    child.phase = MessagePhase::Applied;

    let mut output = [0; 1024];
    for (hash, parent, sequence, original) in [
        (CHILD, SUBSCRIPTION, 4, Some(PAYLOAD)),
        (TALK, EPOCH, 2, None),
    ] {
        let at = room.find_node(&hash).ok_or(Fault::NotFound)?;
        let node = room.nodes.get(at)?;
        let row = AuthenticatedMessageRow::from_node(&room.key, at, node).ok_or(Fault::NotReady)?;
        let mut encoder = Encoder::new(SliceSink::new(&mut output));
        row.write(&mut encoder, &core.frames)?;
        let body = encoder.finish();
        let encoded = body.expose();
        let mut decoder = Decoder::new(encoded);
        let message = MessageRecord::read(&mut decoder, limits, room.sequence)?;
        decoder.end()?;

        assert!(message.at == at);
        assert_eq!(message.hash, hash);
        assert_eq!(message.parents[0], parent);
        assert_eq!(message.sequence, sequence);
        assert_eq!(message.frame.map(|(_, frame)| frame), original);
        if let Some((offset, frame)) = message.frame {
            assert_eq!(&encoded[offset..][..frame.len()], frame);
            assert!(message.phase == MessagePhase::Applied);
        } else {
            assert!(message.phase == MessagePhase::Deleted);
            assert_eq!(message.epoch, [0; 64]);
            assert!(message.discourse.is_none() && message.meta.context.is_none());
        }
    }
    Ok(())
}

#[test]
fn caller_archive_preserves_schema_and_erases_written_bytes() -> Result<(), Error> {
    const UNWRITTEN: u8 = 0x5c;
    let mut instance = Instance::new();
    let mut core = Core::new(
        &mut instance,
        Mode::Service,
        limits(),
        wire::profile::Profile::LITTLE_255,
    )?;
    let room = install_mock(&mut core)?;
    // A durable original has the same position and bytes in either encoder.
    let key = *core.room_key(room)?;
    let frame = core.frames.copy(PAYLOAD, core.remaining_bytes())?;
    core.charge(frame.capacity())?;
    let row = core.rooms.get_mut(room.slot)?;
    let child = row.find_node(&CHILD).ok_or(Fault::NotFound)?;
    let child = row.nodes.get_mut(child)?;
    child.frame = Some(frame);
    child.phase = MessagePhase::Applied;
    let mut output = [UNWRITTEN; 4096];
    let original = core.prepare_archive(output.len())?;
    let len = original.len();
    let mut cells = [const { ArchiveOriginalCell::EMPTY }; 1];
    let mut index = ArchiveOriginals::new(&mut cells);

    let prepare_resident = |_, _: &mut [u8]| Err(Error::Protocol(Fault::NotReady));
    let prepared =
        core.prepare_paged_archive_into(&mut output[..len], &mut index, prepare_resident)?;
    assert_eq!(prepared.historical_peer(), original.historical_peer());
    assert_eq!(prepared.expose(), original.into_body().as_slice());
    let range = index.get(&key, &CHILD).ok_or(Fault::NotFound)?;
    assert_eq!(range.length(), PAYLOAD.len());
    assert_eq!(range.digest(), gnunet_crypto::hash256(PAYLOAD));
    assert_eq!(
        &prepared.expose()[range.offset()..][..range.length()],
        PAYLOAD
    );
    assert!(index.get(&key, &TALK).is_none());
    assert!(index.get(&[0; 64], &CHILD).is_none());
    drop(prepared);
    assert!(output[..len].iter().all(|byte| *byte == 0));
    assert!(output[len..].iter().all(|byte| *byte == UNWRITTEN));

    output.fill(UNWRITTEN);
    assert!(matches!(
        core.prepare_archive_into(&mut output[..len - 1]),
        Err(Error::Protocol(Fault::Capacity))
    ));
    assert_eq!(&output[..MAGIC.len()], &[0; MAGIC.len()]);
    assert!(output.iter().all(|byte| [0, UNWRITTEN].contains(byte)));
    assert!(output[len - 1..].iter().all(|byte| *byte == UNWRITTEN));

    output.fill(UNWRITTEN);
    assert!(matches!(
        core.prepare_paged_archive_into(
            &mut output,
            &mut ArchiveOriginals::new(&mut []),
            prepare_resident,
        ),
        Err(Error::Protocol(Fault::Capacity))
    ));
    assert_eq!(&output[..MAGIC.len()], &[0; MAGIC.len()]);
    assert!(output.iter().all(|byte| [0, UNWRITTEN].contains(byte)));

    // Reject an admitted but incompletely indexed message after archive writes
    // have begun, as happens when the next committed cut must wait for graph work.
    let row = core.rooms.get_mut(room.slot)?;
    let child = row.find_node(&CHILD).ok_or(Fault::NotFound)?;
    row.nodes.get_mut(child)?.epoch_indexed = false;
    output.fill(UNWRITTEN);
    assert!(matches!(
        core.prepare_archive_into(&mut output),
        Err(Error::Protocol(Fault::WouldBlock))
    ));
    assert_eq!(&output[..MAGIC.len()], &[0; MAGIC.len()]);
    assert!(output.iter().all(|byte| [0, UNWRITTEN].contains(byte)));
    Ok(())
}

#[test]
fn paged_original_preserves_the_archive_and_recovers_without_a_frame_pool() -> Result<(), Error> {
    use gnunet_identity::SecretKey;
    use gnunet_types::AbsoluteTime;
    use wire::{
        body::{Body, Text},
        message::Message,
        padding,
        profile::Profile,
    };

    const UNWRITTEN: u8 = 0x5c;
    const PROFILE: Profile = Profile::LITTLE_255;
    let limits = limits();
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
    let room = install_mock(&mut core)?;
    let mut seed = Zeroizing::new([7; 36]);
    seed[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    let signer = SecretKey::from_serialized(&seed[..])?;
    let mut original = SensitiveBuffer::<512>::new();
    original.encode_signed(
        &signer,
        crypto::signature::SigningHeader {
            timestamp: AbsoluteTime::from_micros(5),
            sender_id: &[7; 32],
            previous: &SUBSCRIPTION,
        },
        Body::Text {
            text: Text::new(b"paged original")?,
        },
        PROFILE,
        padding::Encode::Absent,
    )?;
    let hash = crypto::signature::message_hash(Message::decode(
        original.expose(),
        PROFILE,
        padding::Decode::Absent,
    )?);
    let mut child = node(room.slot, Kind::TEXT, hash, SUBSCRIPTION, 5);
    child.auth = Some(Authentication {
        owner: None,
        session: None,
        public: signer.public_key()?,
        peer: None,
    });
    child.phase = MessagePhase::Applied;
    let baseline = core.charged_bytes();
    let frame = core
        .frames
        .copy(original.expose(), core.remaining_bytes())?;
    core.charge(frame.capacity())?;
    child.frame = Some(frame);
    let row = core.rooms.get_mut(room.slot)?;
    row.sequence = 5;
    row.insert_node(child)?;
    row.put_alias(hash, EPOCH)?;

    let mut output = [UNWRITTEN; 8192];
    let committed = Trusted(core.prepare_archive(output.len())?.into_body());
    let mut cells = [ArchiveOriginalCell::EMPTY];
    let mut index = ArchiveOriginals::new(&mut cells);
    let prepared = core
        .prepare_paged_archive_into(&mut output, &mut index, |_, _| Err(Fault::NotReady.into()))?;
    assert_eq!(prepared.expose(), committed.expose_committed());
    let range = index
        .get(core.room_key(room)?, &hash)
        .ok_or(Fault::NotFound)?;
    let written = prepared.into_len_for_storage();
    assert_eq!(&output[..written], committed.expose_committed());
    output[..written].fill(0);
    core.settle_paged_archive(&index)?;
    assert_eq!(core.charged_bytes(), baseline);
    assert!(core.message(room, &hash)?.has_original());
    assert!(core.message(room, &hash)?.original().is_none());

    let prepared = core.prepare_paged_archive_into(&mut output, &mut index, |range, out| {
        out.copy_from_slice(range.in_image(committed.expose_committed())?);
        Ok(())
    })?;
    assert_eq!(prepared.expose(), committed.expose_committed());
    drop(prepared);

    output.fill(UNWRITTEN);
    assert!(matches!(
        core.prepare_paged_archive_into(&mut output, &mut index, |_, out| {
            out.fill(0xff);
            Ok(())
        }),
        Err(Error::Protocol(Fault::Authentication))
    ));
    let attempted = range.offset() + range.length();
    assert!(output[..attempted].iter().all(|byte| *byte == 0));
    assert!(output[attempted..].iter().all(|byte| *byte == UNWRITTEN));
    assert!(index.get(core.room_key(room)?, &hash).is_none());

    let mut restored_instance = Instance::new();
    let mut pool_instance = OriginalPoolInstance::new();
    let mut decode = alloc::vec![0; limits.frame_bytes];
    let mut pool_slots = [];
    let mut pool_bytes = [];
    let pool = OriginalPool::new(&mut pool_instance, &mut pool_slots, &mut pool_bytes);
    let recovered = Core::recover_archive_using(
        &committed,
        limits,
        output.len(),
        DagWorkspace::owned(limits),
        RecoveryOriginals::Paged,
        CommittedGraphPages::EMPTY,
        || Core::with_frame_pool(&mut restored_instance, limits, PROFILE, pool, &mut decode),
    )?;
    let (restored, _, _) = recovered.into_parts();
    let room = restored.retained_rooms().next().ok_or(Fault::NotFound)?;
    let message = restored.message(room, &hash)?;
    assert!(message.has_original());
    assert!(message.original().is_none());
    Ok(())
}

#[test]
fn transient_projection_preserves_durable_child_and_real_epoch() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut original = Core::new(
        &mut instance,
        Mode::Service,
        limits(),
        wire::profile::Profile::LITTLE_255,
    )?;
    let id = install_mock(&mut original)?;
    let image = original.prepare_archive(1 << 20)?;
    let body = image.into_body();
    for excluded in [
        PAYLOAD,
        DISCOURSE.as_slice(),
        OLD_CONTEXT.as_slice(),
        OLD_EPOCH.as_slice(),
    ] {
        assert!(!body.windows(excluded.len()).any(|v| v == excluded));
    }
    // Preparation itself must not erase/mutate the live original input owner.
    let row = original.rooms.get(id.slot)?;
    assert!(
        row.nodes
            .get(row.find_node(&TALK).ok_or(Fault::NotFound)?)?
            .frame
            .is_some()
    );
    let mut rejected = original.prepare_archive(1 << 20)?.into_body();
    rejected[..8].copy_from_slice(b"GMSHIS04");
    let mut old_domain = Instance::new();
    assert!(matches!(
        Core::recover_archive(
            &mut old_domain,
            &Trusted(rejected),
            limits(),
            wire::profile::Profile::LITTLE_255,
            1 << 20
        ),
        Err(Error::Protocol(Fault::Authentication))
    ));
    let row = original.rooms.get_mut(id.slot)?;
    let child = row.find_node(&CHILD).ok_or(Fault::NotFound)?;
    row.nodes.get_mut(child)?.sequence = 3;
    let duplicate = Trusted(original.prepare_archive(1 << 20)?.into_body());
    let mut duplicate_domain = Instance::new();
    assert!(matches!(
        Core::recover_archive(
            &mut duplicate_domain,
            &duplicate,
            limits(),
            wire::profile::Profile::LITTLE_255,
            1 << 20,
        ),
        Err(Error::Protocol(Fault::Conflict))
    ));
    let mut next = Instance::new();
    // A history that never used groups or authenticated nonces must fit below
    // their configured capacity. Recovery must not allocate either empty table.
    let recovery_limits = Limits {
        groups_per_epoch: 1 << 20,
        nonce_per_epoch: 1 << 20,
        total_bytes: 1 << 20,
        ..limits()
    };
    let mut restored = Core::recover_archive(
        &mut next,
        &Trusted(body),
        recovery_limits,
        wire::profile::Profile::LITTLE_255,
        1 << 20,
    )?
    .into_parts()
    .0;
    let room = restored.retained_rooms().next().ok_or(Fault::NotFound)?;
    for hash in [TALK, SUBSCRIPTION] {
        let row = restored.rooms.get(room.slot)?;
        let n = row
            .nodes
            .get(row.find_node(&hash).ok_or(Fault::NotFound)?)?;
        assert!(n.phase == MessagePhase::Deleted && n.frame.is_none() && n.discourse.is_none());
        assert!(n.epoch == [0; 64] && n.meta.context.is_none() && n.origin.is_archived());
        assert!(
            row.alias(&hash).is_none() && row.sources.len() == 0 && row.subscriptions.len() == 0
        );
        assert!(restored.service_message_epoch(room, &hash)? == EPOCH);
    }
    let talk = restored
        .rooms
        .get(room.slot)?
        .find_node(&TALK)
        .ok_or(Fault::NotFound)?;
    restored
        .rooms
        .get_mut(room.slot)?
        .nodes
        .get_mut(talk)?
        .meta
        .context = Some(OLD_CONTEXT);
    assert!(matches!(
        restored.validate_archive_using(
            Some([9; 32]),
            DagWorkspace::owned(restored.limits),
            &[],
            CommittedGraphPages::EMPTY,
        ),
        Err(Error::Protocol(Fault::Malformed))
    ));
    restored
        .rooms
        .get_mut(room.slot)?
        .nodes
        .get_mut(talk)?
        .meta
        .context = None;
    assert!(restored.service_message_epoch(room, &CHILD)? == EPOCH);
    assert!(restored.epoch_members(room, &EPOCH)?.next().is_none());
    let row = restored.rooms.get_mut(room.slot)?;
    let child = row.find_node(&CHILD).ok_or(Fault::NotFound)?;
    assert!(row.nodes.get(child)?.parents == [SUBSCRIPTION, [0; 64]]);
    assert!(row.nodes.get(child)?.sequence == 4 && row.nodes.get(child)?.auth.is_some());
    row.put_alias(TALK, [88; 64])?;
    assert!(row.alias(&TALK).is_none());
    row.queue_node(child)?;
    restored.advance(room, 100)?;
    let n = restored.rooms.get(room.slot)?.nodes.get(child)?;
    assert!(n.complete && n.origin.is_archived());
    Ok(())
}
#[test]
fn cleanup_erases_both_discourse_kinds_and_cannot_refill_alias() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = Core::new(
        &mut instance,
        Mode::Service,
        limits(),
        wire::profile::Profile::LITTLE_255,
    )?;
    let room = install_mock(&mut core)?;
    for hash in [TALK, SUBSCRIPTION] {
        let row = core.rooms.get_mut(room.slot)?;
        let slot = row.find_node(&hash).ok_or(Fault::NotFound)?;
        let released = row.erase_message(&mut core.frames, slot, None)?;
        core.release(released)?;
        let row = core.rooms.get_mut(room.slot)?;
        row.put_alias(hash, [89; 64])?;
        assert!(row.alias(&hash).is_none());
        let n = row.nodes.get(slot)?;
        assert!(n.frame.is_none() && n.discourse.is_none() && n.meta.context.is_none());
        assert!(n.epoch == [0; 64] && n.phase == MessagePhase::Deleted);
    }
    assert!(core.service_message_epoch(room, &CHILD)? == EPOCH);
    Ok(())
}
#[test]
fn backshift_preserves_wrapped_full_cluster_values_and_count() -> Result<(), Error> {
    let mut room = RoomRow::new([1; 64], None, limits(), wire::profile::Profile::LITTLE_255)?;
    room.epoch_aliases.initialize(4, usize::MAX)?;
    let mut keys = [[0; 64]; 4];
    for (i, key) in keys.iter_mut().enumerate() {
        key[0] = 3;
        key[63] = u8::try_from(i).map_err(|_| Fault::Overflow)?;
        room.put_alias(
            *key,
            [u8::try_from(i + 40).map_err(|_| Fault::Overflow)?; 64],
        )?;
    }
    assert!(room.remove_alias(&keys[0])? && room.epoch_alias_count == 3);
    for (i, key) in keys.iter().enumerate().skip(1) {
        assert!(room.alias(key) == Some([u8::try_from(i + 40).map_err(|_| Fault::Overflow)?; 64]));
    }
    assert!(room.remove_alias(&keys[2])? && room.epoch_alias_count == 2);
    assert!(room.alias(&keys[1]) == Some([41; 64]) && room.alias(&keys[3]) == Some([43; 64]));
    assert!(!room.remove_alias(&keys[0])? && room.epoch_alias_count == 2);
    Ok(())
}
