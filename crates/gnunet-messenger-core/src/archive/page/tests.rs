use super::*;
use crate::model::{node, structural_core};

const PEER: [u8; 32] = [9; 32];
const ROOM: Hash = [54; 64];
const ORIGINAL: &[u8] = b"mock original retained by the exact old archive";
const NAMESPACE: [u8; 16] = [19; 16];
const ACCEPTED: u64 = (1 << 32) + 1;
const ID: GraphPageIdentity = GraphPageIdentity::new(
    NAMESPACE,
    EddsaPublicKey::from_bytes(PEER),
    ROOM,
    NonZeroU64::MIN,
    4,
);

struct NativePage<'a>(&'a [u8]);

impl CommittedGraphPageBytes for NativePage<'_> {
    fn expose_committed_page(&self) -> &[u8] {
        self.0
    }
}

struct Working<'a>(&'a [u8]);

impl CommittedArchive for Working<'_> {
    fn generation(&self) -> u64 {
        2
    }

    fn expose_committed(&self) -> &[u8] {
        self.0
    }
}

fn fixture<'id>(instance: &'id mut Instance) -> Result<(Core<'id>, Room<'id>), Error> {
    let mut core = structural_core(instance)?;
    core.mode = Mode::Service;
    core.configure_local_peer(PEER)?;
    let room = core.room(ROOM, None)?;
    for (hash, parent, sequence) in [(1, 0, ACCEPTED - 1), (2, 1, ACCEPTED)] {
        let mut row = node(core.instance, hash, parent, 1, 1, sequence)?;
        let mut public = [3; 36];
        public[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
        row.auth = Some(Authentication {
            owner: None,
            session: None,
            public,
            peer: None,
        });
        row.origin = NodeOrigin::archived(
            ArchivedFact {
                generation: 8,
                sequence,
            },
            SourceObservation {
                room: room.slot,
                source: Slot {
                    index: 0,
                    generation: 1,
                },
                role: SourceRole::Peer([3; 32]),
            },
        );
        row.complete = true;
        if parent == 0 {
            row.phase = MessagePhase::Deleted;
            row.frame = None;
        } else {
            row.frame = Some(RetainedFrame::Archived(ArchiveOriginalRange::at(
                42, ORIGINAL,
            )));
        }
        core.rooms.get_mut(room.slot)?.insert_node(row)?;
    }
    core.rooms.get_mut(room.slot)?.sequence = ACCEPTED;
    Ok((core, room))
}

fn read_original(range: ArchiveOriginalRange, output: &mut [u8]) -> Result<(), Error> {
    if range.offset() != 42 || output.len() != ORIGINAL.len() {
        return Err(Fault::Conflict.into());
    }
    output.copy_from_slice(ORIGINAL);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert exact graph identity, cold byte custody and independent room order"
)]
fn detached_page_indexes_borrowed_rows_and_validates_its_identity() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (core, room) = fixture(&mut instance)?;
    let mut bytes = [0xa3; 2048];
    let prepared =
        core.prepare_graph_page_into(room, ID, &[[1; 64], [2; 64]], &mut bytes, read_original)?;
    let raw = prepared.expose();
    assert_eq!(GraphPageIdentity::read_prefix(raw)?, ID);
    let native = NativePage(raw);
    let mut cells = [ArchiveHistoryCell::EMPTY; 2];
    let other = GraphPageIdentity::new([23; 16], ID.peer(), ROOM, ID.emission(), ID.ordinal());
    assert!(matches!(
        CommittedGraphPage::open(&native, other, core.limits, &mut cells),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert!(matches!(
        CommittedGraphPage::open(&native, ID, core.limits, &mut cells[..1]),
        Err(Error::Protocol(Fault::Capacity))
    ));
    let page = CommittedGraphPage::open(&native, ID, core.limits, &mut cells)?;
    assert_eq!(
        page.room_position(),
        (room.slot.index, room.slot.generation)
    );
    assert_eq!(page.coordinate_revision(), Some(ID.emission()));
    assert_eq!(page.accepted_through(), ACCEPTED);
    assert_eq!(page.len(), 2);
    let child = page.get(&[2; 64])?.ok_or(Fault::NotFound)?;
    assert_eq!(*child.parents(), [[1; 64], [0; 64]]);
    assert_eq!(child.original(), Some(ORIGINAL));
    assert_eq!(child.sequence().get(), ACCEPTED);
    let deleted = page.entry(0)?;
    assert_eq!(*deleted.hash(), [1; 64]);
    assert_eq!(deleted.phase(), MessagePhase::Deleted);
    assert!(deleted.original().is_none());
    assert!(page.get(&[7; 64])?.is_none());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert corruption refusal and cleanup of attempted detached bytes"
)]
fn detached_page_refuses_duplicate_orders_and_changed_cold_originals() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (core, room) = fixture(&mut instance)?;
    let mut bytes = [0xa3; 2048];
    assert!(matches!(
        core.prepare_graph_page_into(room, ID, &[[1; 64], [2; 64]], &mut bytes, |_, output| {
            output.fill(17);
            Ok(())
        }),
        Err(Error::Protocol(Fault::Authentication))
    ));
    assert!(bytes.iter().all(|byte| *byte == 0 || *byte == 0xa3));
    assert!(matches!(
        core.prepare_graph_page_into(room, ID, &[[2; 64], [2; 64]], &mut bytes, read_original),
        Err(Error::Protocol(Fault::InvalidInput))
    ));
    let written = core
        .prepare_graph_page_into(room, ID, &[[1; 64], [2; 64]], &mut bytes, read_original)?
        .into_len_for_storage();
    let mut cells = [ArchiveHistoryCell::EMPTY; 2];
    let store = NativePage(&bytes[..written]);
    CommittedGraphPage::open(&store, ID, core.limits, &mut cells)?;
    let at = cells[1].sequence as usize;
    bytes[at..at + 8].copy_from_slice(&(ACCEPTED - 1).to_be_bytes());
    let altered = NativePage(&bytes[..written]);
    assert!(matches!(
        CommittedGraphPage::open(&altered, ID, core.limits, &mut cells),
        Err(Error::Protocol(Fault::Conflict))
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "check exact workspace and cross-page ancestry"
)]
fn committed_directory_follows_a_tombstone_across_pages() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut core, room) = fixture(&mut instance)?;
    let limits = core.limits;
    let right = GraphPageIdentity::new(NAMESPACE, ID.peer(), ROOM, ID.emission(), 5);
    let mut parent_bytes = [0; 2048];
    let mut child_bytes = [0; 2048];
    let mut conflicting_bytes = [0; 2048];
    let parent =
        core.prepare_graph_page_into(room, ID, &[[1; 64]], &mut parent_bytes, read_original)?;
    let child =
        core.prepare_graph_page_into(room, right, &[[2; 64]], &mut child_bytes, read_original)?;
    let conflicting =
        core.prepare_graph_page_into(room, ID, &[[2; 64]], &mut conflicting_bytes, read_original)?;
    let parent = NativePage(parent.expose());
    let child = NativePage(child.expose());
    let mut cells = [ArchiveHistoryCell::EMPTY; 2];
    let [left_index, right_index] = cells.each_mut();
    let first = CommittedGraphPage::open(&parent, ID, limits, core::slice::from_mut(left_index))?;
    let second =
        CommittedGraphPage::open(&child, right, limits, core::slice::from_mut(right_index))?;
    let working = core.rooms.get_mut(room.slot)?;
    // Test the directory with old accepted nodes no longer in working storage.
    working.index.retain(|_| false);
    for index in 0..working.nodes.limit() {
        if let Some(slot) = working.nodes.slot_at(index) {
            working.nodes.remove(slot)?;
        }
    }
    let body = core.prepare_archive(8192)?.into_body();
    let working = Working(&body);
    let history = CommittedRoomHistory::from_committed(&working, limits, 8192, &ROOM, &mut [])?
        .ok_or(Fault::NotFound)?;
    let conflicting = NativePage(conflicting.expose());
    let mut conflicting_index = [ArchiveHistoryCell::EMPTY];
    let conflicting = CommittedGraphPage::open(&conflicting, ID, limits, &mut conflicting_index)?;
    let duplicate = [first, conflicting];
    assert!(matches!(
        history.with_detached_pages(&NAMESPACE, ID.emission(), &duplicate),
        Err(Error::Protocol(Fault::Conflict))
    ));
    let pages = [first, second];
    let history = history.with_detached_pages(&NAMESPACE, ID.emission(), &pages)?;
    let mut marks = [HistoryCell::EMPTY; 2];
    let mut workspace = HistoryWorkspace::from_cells(&mut marks)?;
    assert!(history.is_ancestor(&[1; 64], &[2; 64], &mut workspace)?);
    assert_eq!(
        history
            .sequence_for(&[2; 64])?
            .ok_or(Fault::NotFound)?
            .get()
            .get(),
        ACCEPTED
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert live timer work cannot leave the room"
)]
fn an_original_with_a_pending_deletion_stays_in_the_working_set() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut core, room) = fixture(&mut instance)?;
    let row = core.rooms.get_mut(room.slot)?;
    let slot = row.find_node(&[2; 64]).ok_or(Fault::NotFound)?;
    row.nodes.get_mut(slot)?.delete_at = Some(30);
    let mut bytes = [0; 2048];
    assert!(matches!(
        core.prepare_graph_page_into(room, ID, &[[2; 64]], &mut bytes, read_original),
        Err(Error::Protocol(Fault::NotReady))
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert signed detached controls survive recovery without live routing authority"
)]
fn rooted_archive_authenticates_detached_peer_controls() -> Result<(), Error> {
    use gnunet_identity::SecretKey;
    use gnunet_types::AbsoluteTime;
    use wire::{body::Body, envelope::Kind, padding, profile::Profile};

    const PROFILE: Profile = Profile::LITTLE_255;
    const MAXIMUM: usize = 8192;
    let mut key = Zeroizing::new([42; 36]);
    key[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    let key = SecretKey::from_serialized(&key[..])?;
    let peer: ShortHash = key.public_key()?[4..]
        .try_into()
        .map_err(|_| Fault::Malformed)?;
    let mut instance = Instance::new();
    let limits = structural_core(&mut instance)?.limits;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
    core.configure_local_peer(PEER)?;
    let room = core.room(ROOM, None)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let mut previous = [0; 64];
    let mut hashes = [[0; 64]; 5];
    let mut current = None;
    for (index, (hash, body)) in hashes
        .iter_mut()
        .zip([
            Body::Peer { peer: &peer },
            Body::Connection {
                amount: 2,
                flags: 1,
            },
            Body::Miss { peer: &peer },
            Body::Peer { peer: &peer },
            Body::Connection {
                amount: 1,
                flags: 0,
            },
        ])
        .enumerate()
    {
        let now = index as u64 + 1;
        let kind = body.kind();
        let mut original = SensitiveBuffer::<512>::new();
        original.encode_signed(
            &key,
            crypto::signature::SigningHeader {
                timestamp: AbsoluteTime::from_micros(now),
                sender_id: &peer,
                previous: &previous,
            },
            body,
            PROFILE,
            padding::Encode::Absent,
        )?;
        *hash = core.receive_borrowed(
            source,
            ReceiveMeta {
                epoch: [0; 64],
                flags: 4,
                requested: false,
                sender_hash: None,
                context: None,
            },
            OriginalLayout::same(PROFILE),
            original.expose(),
        )?;
        core.advance(room, now)?;
        match kind {
            Kind::PEER => current = Some(*hash),
            Kind::MISS => current = None,
            _ => (),
        }
        assert_eq!(core.service_peer_announcement(room, &peer)?, current);
        while core.pop_event().is_some() {}
        previous = *hash;
    }

    let [announcement, connection, withdrawal, current, frontier] = hashes;
    let mut detached = [announcement, connection, withdrawal, current];
    detached.sort_unstable();
    let plan = core.begin_graph_detachment(room, &detached)?;
    let mut bytes = [0; 4096];
    let no_cold = |_, _: &mut [u8]| Err(Fault::Conflict.into());
    let written = plan
        .prepare_page_into(ID, &mut bytes, no_cold)?
        .into_len_for_storage();
    let mut working = [0; MAXIMUM];
    let mut ranges = [const { ArchiveOriginalCell::EMPTY }; 1];
    let mut originals = ArchiveOriginals::new(&mut ranges);
    let working_len = plan
        .prepare_checkpoint_into(&mut working, &mut originals, no_cold)?
        .into_len_for_storage();
    plan.settle(&originals)?;
    assert_eq!(core.retained_messages(room)?.count(), 1);
    assert!(core.message(room, &frontier)?.semantic_applied());
    assert_eq!(core.service_peer_announcement(room, &peer)?, Some(current));

    let mut index = [ArchiveHistoryCell::EMPTY; 4];
    let page_bytes = NativePage(&bytes[..written]);
    let page = CommittedGraphPage::open(&page_bytes, ID, limits, &mut index)?;
    for (hash, kind) in [
        (announcement, Kind::PEER),
        (connection, Kind::CONNECTION),
        (withdrawal, Kind::MISS),
        (current, Kind::PEER),
    ] {
        let record = page.get(&hash)?.ok_or(Fault::NotFound)?;
        assert_eq!(record.kind(), kind);
        assert!(record.original().is_some());
    }
    assert_eq!(page.deletion_reserve()?, 0);
    let restore = |archive: &[u8], page: &CommittedGraphPage<'_, '_>| {
        let mut instance = Instance::new();
        let cells = ArchiveGraphCell::required_cells_with_detached(limits, page.len())
            .ok_or(Fault::Overflow)?;
        let mut graph = alloc::vec![ArchiveGraphCell::empty(); cells];
        let restored = Core::recover_archive_using(
            &Working(archive),
            limits,
            MAXIMUM,
            DagWorkspace::with_cells(&mut graph, limits)?,
            RecoveryOriginals::Paged,
            CommittedGraphPages::new(NAMESPACE, core::slice::from_ref(page)),
            || Core::new(&mut instance, Mode::Service, limits, PROFILE),
        )?;
        let (restored, _, _) = restored.into_parts();
        let room = restored.retained_rooms().next().ok_or(Fault::NotFound)?;
        assert_eq!(restored.retained_messages(room)?.count(), 1);
        assert_eq!(restored.service_room_ring(room)?.members(), 0);
        assert_eq!(restored.service_peer_candidates(room)?.next(), Some(&peer));
        assert_eq!(restored.service_peer_announcement(room, &peer)?, None);
        Ok::<_, Error>(())
    };
    restore(&working[..working_len], &page)?;

    // The accepted live PEER is detached while its signed successor is
    // resident. A recovered MISS must prove its way through both tiers.
    let store = Working(&working[..working_len]);
    let mut offsets = [ArchiveHistoryCell::EMPTY];
    let pages = [page];
    let history =
        CommittedRoomHistory::from_committed(&store, limits, MAXIMUM, &ROOM, &mut offsets)?
            .ok_or(Fault::NotFound)?
            .with_detached_pages(&NAMESPACE, ID.emission(), &pages)?;
    let mut recovered = SensitiveBuffer::<512>::new();
    recovered.encode_signed(
        &key,
        crypto::signature::SigningHeader {
            timestamp: AbsoluteTime::from_micros(6),
            sender_id: &peer,
            previous: &frontier,
        },
        Body::Miss { peer: &peer },
        PROFILE,
        padding::Encode::Absent,
    )?;
    let miss = core.receive_borrowed_with_history(
        source,
        ReceiveMeta {
            epoch: [0; 64],
            flags: 4,
            requested: true,
            sender_hash: None,
            context: None,
        },
        OriginalLayout::same(PROFILE),
        recovered.expose(),
        history,
    )?;
    core.advance_with_committed_history(room, 6, history)?;
    assert_eq!(core.service_peer_announcement(room, &peer)?, None);
    assert!(core.message(room, &miss)?.history_complete());

    let (offset, frame) = page
        .record(page.position(&connection).ok_or(Fault::NotFound)?)?
        .frame
        .ok_or(Fault::NotFound)?;
    let last = offset + frame.len() - 1;
    bytes[last] ^= 1;
    let altered = NativePage(&bytes[..written]);
    let page = CommittedGraphPage::open(&altered, ID, limits, &mut index)?;
    assert!(matches!(
        restore(&working[..working_len], &page),
        Err(Error::Protocol(Fault::Authentication))
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert signed request custody, reference binding and deletion parity"
)]
fn rooted_archive_preserves_signed_request_target_and_deletion() -> Result<(), Error> {
    use gnunet_identity::SecretKey;
    use gnunet_types::AbsoluteTime;
    use wire::{body::Body, envelope::Kind, keys::HpkePublicKey, padding, profile::Profile};

    const PROFILE: Profile = Profile::LITTLE_255;
    const MAXIMUM: usize = 8192;
    let mut instance = Instance::new();
    let limits = structural_core(&mut instance)?.limits;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
    core.configure_local_peer(PEER)?;
    let room = core.room(ROOM, None)?;
    let source = core.attach_source(
        room,
        SourceRole::Peer([18; 32]),
        padding::Decode::Absent,
        None,
    )?;
    let mut seed = Zeroizing::new([77; 36]);
    seed[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    let key = SecretKey::from_serialized(&seed[..])?;
    let public = key.public_key()?;
    let member_id = [11; 32];
    let sign = |previous: &Hash, body: Body<'_>, at| {
        let mut frame = SensitiveBuffer::<512>::new();
        frame.encode_signed(
            &key,
            crypto::signature::SigningHeader {
                timestamp: AbsoluteTime::from_micros(at),
                sender_id: &member_id,
                previous,
            },
            body,
            PROFILE,
            padding::Encode::Absent,
        )?;
        Ok::<_, Error>(frame)
    };
    let meta = |epoch| ReceiveMeta {
        epoch,
        flags: 0,
        requested: false,
        sender_hash: None,
        context: None,
    };
    let layout = OriginalLayout::same(PROFILE);
    let zero = [0; 64];
    let join = sign(
        &zero,
        Body::Join {
            epoch: &zero,
            public_key: wire::PublicKey::new(&public)?,
            hpke_key: HpkePublicKey::new(&[0; 36])?,
        },
        1,
    )?;
    let join = core.receive_borrowed(source, meta(zero), layout, join.expose())?;
    core.advance(room, 1)?;
    let target = [0xc5; 64];
    let signed = sign(&join, Body::Request { hash: &target }, 2)?;
    let request = core.receive_borrowed(source, meta(join), layout, signed.expose())?;
    core.advance(room, 2)?;
    while core.pop_event().is_some() {}

    let detached = [request];
    let plan = core.begin_graph_detachment(room, &detached)?;
    let mut page_bytes = [0; 2048];
    let no_cold = |_, _: &mut [u8]| Err(Fault::Conflict.into());
    let page_len = plan
        .prepare_page_into(ID, &mut page_bytes, no_cold)?
        .into_len_for_storage();
    let mut working = [0; MAXIMUM];
    let mut ranges = [const { ArchiveOriginalCell::EMPTY }; 1];
    let mut originals = ArchiveOriginals::new(&mut ranges);
    let working_len = plan
        .prepare_checkpoint_into(&mut working, &mut originals, no_cold)?
        .into_len_for_storage();
    plan.settle(&originals)?;
    assert_eq!(core.service_state(room)?.previous, join);
    assert_eq!(core.retained_messages(room)?.count(), 1);

    let native = NativePage(&page_bytes[..page_len]);
    let mut cells = [ArchiveHistoryCell::EMPTY];
    let page = CommittedGraphPage::open(&native, ID, limits, &mut cells)?;
    let row = page.record(0)?;
    assert_eq!(row.kind, Kind::REQUEST);
    assert_eq!(row.parents, [join, zero]);
    assert_eq!(row.references, [target, zero, zero]);
    let (frame_at, frame) = row.frame.ok_or(Fault::NotFound)?;
    assert_eq!(frame, signed.expose());
    assert_eq!(page.deletion_reserve()?, DELETION_BYTES);
    let restore = |page: &CommittedGraphPage<'_, '_>| {
        let mut instance = Instance::new();
        let required = ArchiveGraphCell::required_cells_with_detached(limits, page.len())
            .ok_or(Fault::Overflow)?;
        let mut graph = alloc::vec![ArchiveGraphCell::empty(); required];
        Core::recover_archive_using(
            &Working(&working[..working_len]),
            limits,
            MAXIMUM,
            DagWorkspace::with_cells(&mut graph, limits)?,
            RecoveryOriginals::Paged,
            CommittedGraphPages::new(NAMESPACE, core::slice::from_ref(page)),
            || Core::new(&mut instance, Mode::Service, limits, PROFILE),
        )
        .map(|_| ())
    };
    restore(&page)?;

    // Change the retained target while keeping the exact signed frame.
    let mut altered = page_bytes;
    let metadata = frame_at + frame.len();
    let target_at = altered[metadata..page_len]
        .windows(target.len())
        .position(|bytes| bytes == target)
        .ok_or(Fault::NotFound)?;
    altered[metadata + target_at] ^= 1;
    let altered = NativePage(&altered[..page_len]);
    let mut altered_cells = [ArchiveHistoryCell::EMPTY];
    let altered = CommittedGraphPage::open(&altered, ID, limits, &mut altered_cells)?;
    assert!(matches!(
        restore(&altered),
        Err(Error::Protocol(Fault::Malformed))
    ));

    let member = core
        .rooms
        .get(room.slot)?
        .sessions
        .get(row.session.ok_or(Fault::Authentication)?)?;
    let deletion = page
        .plan_deletion(0, member, 10, [9; 64], 3)?
        .ok_or(Fault::NotReady)?;
    assert!(!deletion.erases_original());
    let next = GraphPageIdentity::new(
        NAMESPACE,
        ID.peer(),
        ROOM,
        NonZeroU64::new(2).ok_or(Fault::Conflict)?,
        ID.ordinal(),
    );
    let mut pending = [0; 2048];
    let pending = deletion.prepare_into(&page, next, &mut pending)?;
    let pending = NativePage(pending.expose());
    let mut pending_cells = [ArchiveHistoryCell::EMPTY];
    let pending = CommittedGraphPage::open(&pending, next, limits, &mut pending_cells)?;
    assert!(pending.expire_deletion(9)?.is_none());
    let expired = pending.expire_deletion(10)?.ok_or(Fault::NotReady)?;
    assert!(expired.erases_original());
    let final_id = GraphPageIdentity::new(
        NAMESPACE,
        ID.peer(),
        ROOM,
        NonZeroU64::new(3).ok_or(Fault::Conflict)?,
        ID.ordinal(),
    );
    let mut deleted = [0; 2048];
    let deleted = expired.prepare_into(&pending, final_id, &mut deleted)?;
    let deleted = NativePage(deleted.expose());
    let mut deleted_cells = [ArchiveHistoryCell::EMPTY];
    let deleted = CommittedGraphPage::open(&deleted, final_id, limits, &mut deleted_cells)?;
    let row = deleted.get(&request)?.ok_or(Fault::NotFound)?;
    assert_eq!(row.phase(), MessagePhase::Deleted);
    assert!(row.original().is_none());
    restore(&deleted)
}
