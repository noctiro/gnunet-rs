//! Signed service ingress through caller-owned frame storage.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert public fixed-history admission, retention and reclamation outcomes"
)]

use gnunet_identity::SecretKey;
use gnunet_messenger_core::{
    CommittedArchive, Core, Error, HistoryNodeCell, HistorySlotCell, Instance, Limits, Mode,
    OriginalLayout, OriginalPool, OriginalPoolInstance, OriginalSigner, OriginalSlot, ReceiveMeta,
    RoomHistoryStorage, SensitiveBuffer, SourceRole, carrier,
    crypto::signature::{SigningHeader, message_hash},
    wire::{
        KeyType, SensitiveBytes, body::Body, envelope, message::Message, padding, profile::Profile,
    },
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use zeroize::Zeroizing;

const PROFILE: Profile = Profile::LITTLE_255;
const FRAME_BYTES: usize = 512;
const META: ReceiveMeta = ReceiveMeta {
    epoch: [0; 64],
    flags: 4,
    requested: false,
    sender_hash: None,
    context: None,
};

fn info(seed: u8, timestamp: u64) -> Result<([u8; 32], SensitiveBuffer<FRAME_BYTES>), Error> {
    let mut secret = Zeroizing::new([seed; 36]);
    secret[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    let key = SecretKey::from_serialized(&secret[..])?;
    let peer = key.public_key()?[4..]
        .try_into()
        .map_err(|_| Fault::Malformed)?;
    let mut frame = SensitiveBuffer::new();
    const INFO_BYTES: usize = envelope::HEADER_LEN + core::mem::size_of::<u32>();
    frame.encode_signed(
        &key,
        SigningHeader {
            timestamp: AbsoluteTime::from_micros(timestamp),
            sender_id: &peer,
            previous: &[0; 64],
        },
        Body::Info {
            version: carrier::VERSION,
        },
        PROFILE,
        padding::Encode::ToLength {
            total: FRAME_BYTES,
            noise: SensitiveBytes::new(&[0x5a; FRAME_BYTES - INFO_BYTES - padding::MIN_PADDING]),
        },
    )?;
    Ok((peer, frame))
}

#[test]
fn borrowed_history_releases_its_pool_slot_when_the_room_is_forgotten() -> Result<(), Error> {
    let mut pool_instance = OriginalPoolInstance::new();
    let mut pool_slots = [OriginalSlot::EMPTY];
    let mut storage = [0; 2 * FRAME_BYTES];
    let pool = OriginalPool::new(&mut pool_instance, &mut pool_slots, &mut storage);
    let mut workspace = [0; FRAME_BYTES];
    let mut instance = Instance::new();
    let limits = Limits {
        rooms: 2,
        sources_per_room: 2,
        messages_per_room: 2,
        frame_bytes: FRAME_BYTES,
        name_bytes: FRAME_BYTES,
        ..Limits::default()
    };
    let mut core = Core::with_frame_pool(&mut instance, limits, PROFILE, pool, &mut workspace)?;
    let room = core.room([1; 64], None)?;
    let (peer, frame) = info(7, 10)?;
    let source = core.attach_source(
        room,
        SourceRole::Peer(peer),
        padding::Decode::Required,
        None,
    )?;
    let layout = OriginalLayout::same(PROFILE);
    let hash = core.receive_borrowed(source, META, layout, frame.expose())?;
    core.advance(room, 10)?;
    let original = core.message(room, &hash)?;
    assert!(original.semantic_applied(), "admitted INFO did not advance");
    assert_eq!(original.original_signer(), Some(OriginalSigner::Peer(peer)));
    assert!(
        original.original() == Some(frame.expose()),
        "advanced history did not preserve the signed frame and its padding"
    );

    let other_room = core.room([2; 64], None)?;
    let (other_peer, other_frame) = info(8, 11)?;
    let other_source = core.attach_source(
        other_room,
        SourceRole::Peer(other_peer),
        padding::Decode::Required,
        None,
    )?;
    let other_hash = message_hash(Message::decode(
        other_frame.expose(),
        PROFILE,
        padding::Decode::Required,
    )?);
    let charged = core.charged_bytes();
    assert_eq!(
        core.receive_borrowed(other_source, META, layout, other_frame.expose()),
        Err(Fault::Capacity.into()),
        "a second original cannot occupy the single metadata slot"
    );
    assert_eq!(core.charged_bytes(), charged, "refusal retained bytes");
    assert!(matches!(
        core.message(other_room, &other_hash),
        Err(Error::Protocol(Fault::NotFound))
    ));

    core.source_stopped(source)?;
    assert!(
        core.message(room, &hash)?.original() == Some(frame.expose()),
        "retiring the transport must preserve authenticated history"
    );
    core.forget_room(room)?;
    assert_eq!(
        core.receive_borrowed(other_source, META, layout, other_frame.expose())?,
        other_hash
    );
    core.advance(other_room, 11)?;
    assert!(
        core.message(other_room, &other_hash)?.original() == Some(other_frame.expose()),
        "the reclaimed slot did not retain the replacement original"
    );
    Ok(())
}

struct HistoryArena<const N: usize> {
    nodes: [HistoryNodeCell; N],
    index: [HistorySlotCell; N],
    ready: [HistorySlotCell; N],
}

impl<const N: usize> HistoryArena<N> {
    const fn new() -> Self {
        Self {
            nodes: [const { HistoryNodeCell::empty() }; N],
            index: [HistorySlotCell::empty(); N],
            ready: [HistorySlotCell::empty(); N],
        }
    }

    fn storage(&mut self) -> RoomHistoryStorage<'_> {
        RoomHistoryStorage::new(&mut self.nodes, &mut self.index, &mut self.ready)
    }
}

#[test]
fn fixed_history_reuses_room_storage_after_forgetting_queued_input() -> Result<(), Error> {
    let mut arena = HistoryArena::<1>::new();
    let mut pool_instance = OriginalPoolInstance::new();
    let mut pool_slots = [OriginalSlot::EMPTY];
    let mut bytes = [0; FRAME_BYTES];
    let mut workspace = [0; FRAME_BYTES];
    let limits = Limits {
        rooms: 1,
        sources_per_room: 1,
        messages_per_room: 1,
        frame_bytes: FRAME_BYTES,
        name_bytes: FRAME_BYTES,
        ..Limits::default()
    };
    let layout = OriginalLayout::same(PROFILE);
    let (next_peer, next_frame) = info(8, 11)?;
    let next_hash = {
        let mut instance = Instance::new();
        let pool = OriginalPool::new(&mut pool_instance, &mut pool_slots, &mut bytes);
        let mut core = Core::with_fixed_history(
            &mut instance,
            limits,
            PROFILE,
            pool,
            &mut workspace,
            arena.storage(),
        )?;
        let initial_bytes = core.charged_bytes();
        let room = core.room([1; 64], None)?;
        let (peer, frame) = info(7, 10)?;
        let source = core.attach_source(
            room,
            SourceRole::Peer(peer),
            padding::Decode::Required,
            None,
        )?;
        let hash = core.receive_borrowed(source, META, layout, frame.expose())?;
        // Leave an authenticated original in the one-entry ready queue.
        core.source_stopped(source)?;
        let original = core.message(room, &hash)?;
        assert!(!original.semantic_applied());
        assert!(original.original() == Some(frame.expose()));
        core.forget_room(room)?;
        assert_eq!(core.charged_bytes(), initial_bytes);

        let reopened = core.room([2; 64], None)?;
        assert_eq!(reopened.observation().index(), room.observation().index());
        assert_ne!(
            reopened.observation().generation(),
            room.observation().generation()
        );
        assert_eq!(core.room_key(room), Err(Fault::StaleGeneration.into()));
        assert_eq!(core.source_room(source), Err(Fault::StaleGeneration.into()));
        assert!(matches!(
            core.message(reopened, &hash),
            Err(Error::Protocol(Fault::NotFound))
        ));

        let source = core.attach_source(
            reopened,
            SourceRole::Peer(next_peer),
            padding::Decode::Required,
            None,
        )?;
        let hash = core.receive_borrowed(source, META, layout, next_frame.expose())?;
        core.advance(reopened, 11)?;
        let original = core.message(reopened, &hash)?;
        assert!(original.semantic_applied());
        assert!(original.original() == Some(next_frame.expose()));
        hash
    };

    let mut instance = Instance::new();
    let pool = OriginalPool::new(&mut pool_instance, &mut pool_slots, &mut bytes);
    let mut core = Core::with_fixed_history(
        &mut instance,
        limits,
        PROFILE,
        pool,
        &mut workspace,
        arena.storage(),
    )?;
    let room = core.room([2; 64], None)?;
    assert!(matches!(
        core.message(room, &next_hash),
        Err(Error::Protocol(Fault::NotFound))
    ));
    let source = core.attach_source(
        room,
        SourceRole::Peer(next_peer),
        padding::Decode::Required,
        None,
    )?;
    assert_eq!(
        core.receive_borrowed(source, META, layout, next_frame.expose())?,
        next_hash
    );
    Ok(())
}

struct TestArchive<'a>(&'a [u8]);

impl CommittedArchive for TestArchive<'_> {
    fn generation(&self) -> u64 {
        7
    }

    fn expose_committed(&self) -> &[u8] {
        self.0
    }
}

#[test]
fn fixed_history_recovery_keeps_sparse_room_partitions_independent() -> Result<(), Error> {
    const MAX_ARCHIVE: usize = 4096;
    let limits = Limits {
        rooms: 2,
        sources_per_room: 1,
        messages_per_room: 1,
        frame_bytes: FRAME_BYTES,
        name_bytes: FRAME_BYTES,
        ..Limits::default()
    };
    let layout = OriginalLayout::same(PROFILE);
    let (peer, frame) = info(7, 10)?;
    let local_peer = info(6, 9)?.0;
    let (image, archived_room, hash) = {
        let mut instance = Instance::new();
        let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
        core.configure_local_peer(local_peer)?;
        let empty = core.room([1; 64], None)?;
        let room = core.room([2; 64], None)?;
        core.forget_room(empty)?;
        let source = core.attach_source(
            room,
            SourceRole::Peer(peer),
            padding::Decode::Required,
            None,
        )?;
        let hash = core.receive_borrowed(source, META, layout, frame.expose())?;
        core.advance(room, 10)?;
        assert_eq!(room.observation().index(), 1);
        (
            core.prepare_archive(MAX_ARCHIVE)?.into_body(),
            room.observation(),
            hash,
        )
    };

    let mut arena = HistoryArena::<2>::new();
    let mut pool_instance = OriginalPoolInstance::new();
    let mut pool_slots = [OriginalSlot::EMPTY; 2];
    let mut bytes = [0; 2 * FRAME_BYTES];
    let pool = OriginalPool::new(&mut pool_instance, &mut pool_slots, &mut bytes);
    let mut workspace = [0; FRAME_BYTES];
    let mut instance = Instance::new();
    let (mut restored, generation, historical_peer) = Core::recover_archive_with_fixed_history(
        &mut instance,
        limits,
        PROFILE,
        pool,
        &mut workspace,
        arena.storage(),
        &TestArchive(&image),
        MAX_ARCHIVE,
    )?
    .into_parts();
    assert_eq!((generation, historical_peer), (7, Some(local_peer)));
    assert_eq!(restored.retained_rooms().count(), 1);
    let restored_room = restored.retained_rooms().next().ok_or(Fault::NotFound)?;
    assert_eq!(restored_room.observation(), archived_room);
    assert!(
        restored
            .message(restored_room, &hash)?
            .origin()
            .live()
            .is_none()
    );

    let new_room = restored.room([3; 64], None)?;
    assert_eq!(new_room.observation().index(), 0);
    let (new_peer, new_frame) = info(8, 11)?;
    let source = restored.attach_source(
        new_room,
        SourceRole::Peer(new_peer),
        padding::Decode::Required,
        None,
    )?;
    let new_hash = restored.receive_borrowed(source, META, layout, new_frame.expose())?;
    restored.advance(new_room, 11)?;
    let original = restored.message(new_room, &new_hash)?;
    assert!(original.semantic_applied());
    assert!(original.original() == Some(new_frame.expose()));
    assert!(matches!(
        restored.message(new_room, &hash),
        Err(Error::Protocol(Fault::NotFound))
    ));
    restored.source_stopped(source)?;
    restored.forget_room(new_room)?;
    assert!(restored.message(restored_room, &hash)?.original() == Some(frame.expose()));
    Ok(())
}
