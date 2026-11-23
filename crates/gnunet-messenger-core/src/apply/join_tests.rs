//! Service JOIN authority follows the committed membership snapshot.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert signed service transitions"
)]

use crate::{
    archive::{
        ArchiveHistoryCell, CommittedGraphPage, CommittedGraphPageBytes, CommittedRoomHistory,
        GraphPageIdentity,
    },
    epoch::members::MemberArena,
    model::structural_core,
    *,
};
use core::num::NonZeroU64;
use gnunet_crypto::EddsaPublicKey;
use gnunet_identity::SecretKey;
use gnunet_types::{AbsoluteTime, Error as Fault, RelativeTime};
use wire::{
    body::{Body, Text},
    keys::HpkePublicKey,
    padding,
    profile::Profile,
};
use zeroize::Zeroizing;

const PROFILE: Profile = Profile::LITTLE_255;
const FRAME_BYTES: usize = 512;

fn signer(seed: u8) -> Result<SecretKey, Error> {
    let mut bytes = Zeroizing::new([seed; 36]);
    bytes[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    Ok(SecretKey::from_serialized(&bytes[..])?)
}

fn bound_client<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    signer: &SecretKey,
    id: ShortHash,
) -> Result<Source<'id>, Error> {
    let public = signer.public_key()?;
    let source = core.attach_source(
        room,
        SourceRole::Client,
        padding::Decode::Absent,
        Some(public),
    )?;
    core.bind_service_client(source, public, id)?;
    Ok(source)
}

fn receive_signed<'id>(
    core: &mut Core<'id>,
    source: Source<'id>,
    signer: &SecretKey,
    sender: &ShortHash,
    parent: &Hash,
    body: Body<'_>,
) -> Result<Hash, Error> {
    let mut frame = SensitiveBuffer::<FRAME_BYTES>::new();
    frame.encode_signed(
        signer,
        crypto::signature::SigningHeader {
            timestamp: AbsoluteTime::UNIX_EPOCH,
            sender_id: sender,
            previous: parent,
        },
        body,
        PROFILE,
        padding::Encode::Absent,
    )?;
    core.receive_borrowed(
        source,
        ReceiveMeta {
            epoch: *parent,
            flags: 8,
            requested: false,
            sender_hash: None,
            context: None,
        },
        OriginalLayout::same(PROFILE),
        frame.expose(),
    )
}

fn receive_join<'id>(
    core: &mut Core<'id>,
    source: Source<'id>,
    signer: &SecretKey,
    sender: &ShortHash,
    parent: &Hash,
) -> Result<Hash, Error> {
    receive_signed(
        core,
        source,
        signer,
        sender,
        parent,
        Body::Join {
            epoch: parent,
            public_key: wire::PublicKey::new(&signer.public_key()?)?,
            hpke_key: HpkePublicKey::new(&[0; 36])?,
        },
    )
}

struct Committed<'a>(&'a [u8]);

impl CommittedArchive for Committed<'_> {
    fn generation(&self) -> u64 {
        2
    }

    fn expose_committed(&self) -> &[u8] {
        self.0
    }
}

impl CommittedGraphPageBytes for Committed<'_> {
    fn expose_committed_page(&self) -> &[u8] {
        self.0
    }
}

#[test]
fn signed_child_advances_against_its_detached_predecessor() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let room_key = [37; 64];
    let local = EddsaPublicKey::from_bytes([9; 32]);
    core.mode = Mode::Service;
    core.configure_local_peer(*local.as_bytes())?;
    let room = core.room(room_key, None)?;
    let member = signer(3)?;
    let id = [3; 32];
    let source = bound_client(&mut core, room, &member, id)?;
    let join = receive_join(&mut core, source, &member, &id, &[0; 64])?;
    core.advance(room, 0)?;
    let mut text = |parent: &Hash, bytes: &[u8]| {
        receive_signed(
            &mut core,
            source,
            &member,
            &id,
            parent,
            Body::Text {
                text: Text::new(bytes)?,
            },
        )
    };
    let predecessor = text(&join, b"old text")?;
    let _working_frontier = text(&predecessor, b"current frontier")?;
    core.advance(room, 0)?;

    let namespace = [17; 16];
    let identity = GraphPageIdentity::new(namespace, local, room_key, NonZeroU64::MIN, 0);
    let mut bytes = [0; 2048];
    let prepared =
        core.prepare_graph_page_into(room, identity, &[predecessor], &mut bytes, |_, _| {
            Err(Fault::Conflict.into())
        })?;
    let page = Committed(prepared.expose());
    let mut index = [ArchiveHistoryCell::EMPTY];
    let pages = [CommittedGraphPage::open(
        &page,
        identity,
        core.limits,
        &mut index,
    )?];
    {
        // Model the split only after writing the exact original into its page.
        let working = core.rooms.get_mut(room.slot)?;
        let slot = working.find_node(&predecessor).ok_or(Fault::NotFound)?;
        working.index.retain(|at| at != slot);
        working.nodes.remove(slot)?;
        working.remove_alias(&predecessor)?;
    }
    let checkpoint = core.prepare_archive(8192)?.into_body();
    let checkpoint = Committed(&checkpoint);
    let mut index = [ArchiveHistoryCell::EMPTY; 2];
    let history = CommittedRoomHistory::from_committed(
        &checkpoint,
        core.limits,
        8192,
        &room_key,
        &mut index,
    )?
    .ok_or(Fault::NotFound)?
    .with_detached_pages(&namespace, identity.emission(), &pages)?;
    while core.pop_event().is_some() {}

    let child = receive_signed(
        &mut core,
        source,
        &member,
        &id,
        &predecessor,
        Body::Text {
            text: Text::new(b"new text on an old branch")?,
        },
    )?;
    core.advance_with_committed_history(room, 0, history)?;
    let applied = core.message(room, &child)?;
    assert!(applied.history_complete());
    assert_eq!(applied.phase(), MessagePhase::Applied);
    assert_eq!(*applied.epoch(), join);
    let working = core.rooms.get(room.slot)?;
    assert!(working.alias(&predecessor).is_none());
    assert_eq!(working.missing.len(), 0);
    Ok(())
}

#[test]
fn signed_detached_delete_preserves_its_timer_and_erases_only_the_target() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let room_key = [39; 64];
    let local = EddsaPublicKey::from_bytes([9; 32]);
    core.mode = Mode::Service;
    core.configure_local_peer(*local.as_bytes())?;
    let room = core.room(room_key, None)?;
    let alice = signer(3)?;
    let alice_id = [3; 32];
    let alice_source = bound_client(&mut core, room, &alice, alice_id)?;
    let join = receive_join(&mut core, alice_source, &alice, &alice_id, &[0; 64])?;
    core.advance(room, 0)?;
    let text = Body::Text {
        text: Text::new(b"detached payload")?,
    };
    let target = receive_signed(&mut core, alice_source, &alice, &alice_id, &join, text)?;
    let sibling = receive_signed(&mut core, alice_source, &alice, &alice_id, &target, text)?;
    core.advance(room, 0)?;
    let bob = signer(4)?;
    let bob_id = [4; 32];
    let bob_source = bound_client(&mut core, room, &bob, bob_id)?;
    let bob_join = receive_signed(
        &mut core,
        bob_source,
        &bob,
        &bob_id,
        &sibling,
        Body::Join {
            epoch: &join,
            public_key: wire::PublicKey::new(&bob.public_key()?)?,
            hpke_key: HpkePublicKey::new(&[0; 36])?,
        },
    )?;
    core.advance(room, 0)?;

    let namespace = [22; 16];
    let mut hashes = [target, sibling];
    hashes.sort_unstable();
    let identity = GraphPageIdentity::new(namespace, local, room_key, NonZeroU64::MIN, 0);
    let mut bytes = [0; 4096];
    let prepared = core.prepare_graph_page_into(room, identity, &hashes, &mut bytes, |_, _| {
        Err(Fault::Conflict.into())
    })?;
    let page = Committed(prepared.expose());
    let mut index = [ArchiveHistoryCell::EMPTY; 2];
    let pages = [CommittedGraphPage::open(
        &page,
        identity,
        core.limits,
        &mut index,
    )?];
    let original = pages[0].get(&target)?.ok_or(Fault::NotFound)?;
    let neighbor = pages[0].get(&sibling)?.ok_or(Fault::NotFound)?;
    {
        // The native settlement is separate; model its result for this test.
        let working = core.rooms.get_mut(room.slot)?;
        for hash in hashes {
            let slot = working.find_node(&hash).ok_or(Fault::NotFound)?;
            working.index.retain(|at| at != slot);
            working.nodes.remove(slot)?;
            working.remove_alias(&hash)?;
        }
    }
    let checkpoint = core.prepare_archive(8192)?.into_body();
    let checkpoint = Committed(&checkpoint);
    let mut index = [ArchiveHistoryCell::EMPTY; 8];
    let history = CommittedRoomHistory::from_committed(
        &checkpoint,
        core.limits,
        8192,
        &room_key,
        &mut index,
    )?
    .ok_or(Fault::NotFound)?
    .with_detached_pages(&namespace, identity.emission(), &pages)?;
    while core.pop_event().is_some() {}

    let deletion = Body::Deletion {
        hash: &target,
        delay: RelativeTime::from_micros(75),
    };
    let unauthorized = receive_signed(&mut core, bob_source, &bob, &bob_id, &bob_join, deletion)?;
    let mut mutation = None;
    core.advance_with_detached_deletion(room, 0, history, &mut mutation)?;
    assert!(mutation.is_none());
    assert_eq!(
        core.message(room, &unauthorized)?.phase(),
        MessagePhase::Rejected
    );
    while core.pop_event().is_some() {}

    let authorized = receive_signed(
        &mut core,
        alice_source,
        &alice,
        &alice_id,
        &bob_join,
        deletion,
    )?;
    assert!(matches!(
        core.advance_with_committed_history(room, 0, history),
        Err(Error::Protocol(Fault::WouldBlock))
    ));
    core.advance_with_detached_deletion(room, 0, history, &mut mutation)?;
    assert_eq!(
        core.message(room, &authorized)?.phase(),
        MessagePhase::Applied
    );
    let mutation = mutation.ok_or(Fault::NotReady)?;
    assert_eq!(mutation.target(), &target);
    assert!(!mutation.erases_original());
    assert!(matches!(
        core.message(room, &target),
        Err(Error::Protocol(Fault::NotFound))
    ));

    let next = identity.emission().saturating_add(1);
    let scheduled = GraphPageIdentity::new(namespace, local, room_key, next, 0);
    let mut scheduled_bytes = [0; 4096];
    let prepared = history.prepare_detached_deletion(&mutation, scheduled, &mut scheduled_bytes)?;
    let page = Committed(prepared.expose());
    let mut index = [ArchiveHistoryCell::EMPTY; 2];
    let pages = [CommittedGraphPage::open(
        &page,
        scheduled,
        core.limits,
        &mut index,
    )?];
    let checkpoint = core.prepare_archive(8192)?.into_body();
    let checkpoint = Committed(&checkpoint);
    let mut index = [ArchiveHistoryCell::EMPTY; 8];
    let history = CommittedRoomHistory::from_committed(
        &checkpoint,
        core.limits,
        8192,
        &room_key,
        &mut index,
    )?
    .ok_or(Fault::NotFound)?
    .with_detached_pages(&namespace, next, &pages)?;
    assert_eq!(history.next_detached_deletion(), Some(75));
    assert!(history.expire_detached_deletion(74)?.is_none());
    assert_eq!(
        pages[0].get(&target)?.ok_or(Fault::NotFound)?.original(),
        original.original()
    );
    let expiry = history
        .expire_detached_deletion(75)?
        .ok_or(Fault::NotReady)?;
    assert!(expiry.erases_original());

    let final_id = GraphPageIdentity::new(namespace, local, room_key, next.saturating_add(1), 0);
    let mut final_bytes = [0; 4096];
    assert!(matches!(
        history.prepare_detached_deletion(&mutation, final_id, &mut final_bytes),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    let prepared = history.prepare_detached_deletion(&expiry, final_id, &mut final_bytes)?;
    let page = Committed(prepared.expose());
    let mut index = [ArchiveHistoryCell::EMPTY; 2];
    let page = CommittedGraphPage::open(&page, final_id, core.limits, &mut index)?;
    let deleted = page.get(&target)?.ok_or(Fault::NotFound)?;
    let retained = page.get(&sibling)?.ok_or(Fault::NotFound)?;
    assert_eq!(deleted.phase(), MessagePhase::Deleted);
    assert_eq!(deleted.sequence(), original.sequence());
    assert_eq!(deleted.parents(), original.parents());
    assert!(deleted.original().is_none());
    assert_eq!(retained.original(), neighbor.original());
    assert_eq!(retained.sequence(), neighbor.sequence());
    Ok(())
}

#[test]
fn fixed_epoch_capacity_cannot_activate_a_joining_signer() -> Result<(), Error> {
    let mut members = [EpochMemberCell::empty(); 1];
    let mut instance = Instance::new();
    let mut core = Core::new(
        &mut instance,
        Mode::Service,
        Limits {
            rooms: 1,
            contacts: 2,
            sources_per_room: 2,
            sessions_per_room: 2,
            messages_per_room: 4,
            epochs_per_room: 2,
            groups_per_epoch: 1,
            subscriptions_per_room: 1,
            operations_per_room: 1,
            missing_per_room: 1,
            events: 16,
            own_signers: 1,
            nonce_per_epoch: 1,
            frame_bytes: FRAME_BYTES,
            name_bytes: 32,
            work_per_turn: 4,
            ..Limits::default()
        },
        PROFILE,
    )?;
    core.configure_local_peer([9; 32])?;
    let room = core.room([1; 64], None)?;
    // Hold all other quotas constant and exhaust the actual fixed snapshot arena.
    let room_slot = core.check_room(room)?;
    core.charge(MemberArena::required_bytes(members.len())?)?;
    core.rooms.get_mut(room_slot)?.member_arena = MemberArena::fixed(&mut members);

    let first = signer(3)?;
    let first_id = [3; 32];
    let first_source = bound_client(&mut core, room, &first, first_id)?;
    let parent = receive_join(&mut core, first_source, &first, &first_id, &[0; 64])?;
    core.advance(room, 0)?;
    assert!(core.service_member(first_source)?.is_some());
    assert_eq!(core.epoch_members(room, &parent)?.len(), 1);
    while core.pop_event().is_some() {}

    let second = signer(4)?;
    let second_id = [4; 32];
    let second_source = bound_client(&mut core, room, &second, second_id)?;
    let join = receive_join(&mut core, second_source, &second, &second_id, &parent)?;
    assert_eq!(core.advance(room, 1), Err(Fault::Capacity.into()));
    assert!(core.service_member(second_source)?.is_none());
    assert!(!core.service_may_read(second_source, &parent)?);
    assert!(core.service_attribution(room, &join).is_err());
    assert!(!core.message(room, &join)?.semantic_applied());
    assert_eq!(core.epoch_members(room, &parent)?.len(), 1);
    while let Some(event) = core.pop_event() {
        assert!(!matches!(
            event,
            Event::MemberChanged(_, SessionPhase::Active)
        ));
    }

    let name = receive_signed(
        &mut core,
        second_source,
        &second,
        &second_id,
        &join,
        Body::Name {
            name: Text::new(b"pending signer")?,
        },
    )?;
    assert_eq!(
        core.message(room, &name)?.phase(),
        MessagePhase::AwaitingSender
    );

    let authenticated = receive_signed(
        &mut core,
        first_source,
        &first,
        &first_id,
        &parent,
        Body::Name {
            name: Text::new(b"active signer")?,
        },
    )?;
    assert_eq!(core.advance(room, 2), Err(Fault::Capacity.into()));
    assert!(matches!(
        core.prepare_archive(8192),
        Err(Error::Protocol(Fault::WouldBlock))
    ));
    let queue = |core: &Core<'_>| {
        let ready = &core.rooms.get(room_slot)?.ready;
        Ok::<_, Error>([ready.get(0), ready.get(1), ready.get(2)])
    };
    let original_order = queue(&core)?;
    core.register_archive_ingress()?;
    assert!(
        queue(&core)? == original_order,
        "registration must keep ready order"
    );
    assert!(!core.message(room, &authenticated)?.semantic_applied());
    assert!(!core.message(room, &join)?.semantic_applied());
    assert!(core.service_member(second_source)?.is_none());
    assert_eq!(core.service_message_epoch(room, &authenticated)?, parent);
    assert_eq!(
        core.message(room, &name)?.phase(),
        MessagePhase::AwaitingSender
    );
    let prepared = core.prepare_archive(8192)?;
    core.register_archive_ingress()?;
    assert!(prepared.into_body() == core.prepare_archive(8192)?.into_body());
    Ok(())
}
