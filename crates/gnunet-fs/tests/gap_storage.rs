//! Original local storage/replication ownership models, not remote-store proofs.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible models assert exact original storage receipts, metadata, pause generations and isolated push ownership"
)]
use gnunet_fs::{
    content::encode_data,
    gap::{self, Entropy, NeighborSlot, PathSlot, RouteSlot, storage},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, RelativeTime,
    datastore::Data,
    fs::BlockType,
    fs_gap::{MigrationStop, Put},
};
struct Random;
impl Entropy for Random {
    fn uniform(&mut self, upper: u32) -> Result<u32, Error> {
        upper.checked_sub(1).map(|_| 0).ok_or(Error::InvalidInput)
    }
}
fn block(out: &mut [u8]) -> Result<([u8; 64], usize), Error> {
    let c = encode_data(b"actual test content", out)?;
    Ok((c.key().query, c.bytes().len()))
}

#[test]
fn cache_advances_only_original_status_and_pressure_encodes_real_stop_duration() -> Result<(), Error>
{
    let mut gap_id = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 2];
    let mut result = [0; 256];
    let mut routes = [RouteSlot::new(&mut result)];
    let mut paths = [PathSlot::default(); 2];
    let mut output = [0; 256];
    let mut gap = gap::Router::new(
        &mut gap_id,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let peer = gap.attach([1; 32])?;
    let mut id = storage::Instance::new();
    let mut peers = [storage::PeerSlot::new(); 2];
    let mut cache_bytes = [0; 256];
    let mut cache = [storage::CacheSlot::new(&mut cache_bytes)];
    let mut migration_bytes = [0; 256];
    let mut migrations = [storage::MigrationSlot::new(&mut migration_bytes)];
    let mut owner = storage::Owner::new(
        &mut id,
        &mut peers,
        &mut cache,
        &mut migrations,
        storage::Limits {
            pushing: false,
            ..storage::Limits::default()
        },
    )?;
    owner.attach(peer, [1; 32])?;
    let mut encrypted = [0; 128];
    let (key, n) = block(&mut encrypted)?;
    let mut wire = [0; 256];
    let n = Put {
        block_type: BlockType::DBLOCK,
        expiration: AbsoluteTime::NEVER,
        block: &encrypted[..n],
    }
    .encode(&mut wire)?;
    let storage::CacheAdmission::Queued(original) =
        owner.receive(peer, &wire[..n], 7, false, 100)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(owner.report().cache_stored, 0);
    assert!(matches!(
        owner.receive(peer, &wire[..n], 0, false, 100)?,
        storage::CacheAdmission::Declined(storage::Declined::Capacity)
    ));
    let Some(storage::Command::Put(write)) = owner.next_command(100)? else {
        return Err(Error::NotReady);
    };
    assert_eq!(write.token, original);
    assert_eq!(*write.data.key, key);
    assert_eq!(write.data.priority, 7);
    assert_eq!(
        (write.data.anonymity, write.data.replication, write.data.uid),
        (1, 0, 0)
    );
    assert_eq!(write.data.expiration.as_micros(), 100 + storage::YEAR_US);
    assert_eq!(write.data.value, Put::decode(&wire[..n])?.block);
    owner.cache_status(original, 1, AbsoluteTime::UNIX_EPOCH, 101, &mut Random)?;
    assert_eq!(owner.report().cache_stored, 1);
    assert_eq!(
        owner.cache_status(original, 1, AbsoluteTime::UNIX_EPOCH, 102, &mut Random),
        Err(Error::StaleGeneration)
    );
    let Some(stop) = owner.next_stop(101)? else {
        return Err(Error::NotReady);
    };
    let mut encoded = [0; 16];
    assert_eq!(stop.message.encode(&mut encoded)?, 16);
    assert_eq!(
        MigrationStop::decode(&encoded)?.duration,
        RelativeTime::from_micros(4_999_999)
    );
    assert_eq!(owner.report().stops_written, 0);
    owner.disconnect(peer)?;
    owner.stop_sent(stop.token, false)?;
    assert_eq!(owner.report().stops_retired, 1);
    assert!(owner.next_stop(102)?.is_none());
    owner.request_shutdown();
    assert!(owner.quiesced());
    gap.request_shutdown();
    assert!(gap.quiesced());
    Ok(())
}

#[test]
fn selected_uid_score_and_anonymity_survive_push_pause_without_closing_queries() -> Result<(), Error>
{
    let mut gap_id = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 3];
    let mut a = [0; 256];
    let mut b = [0; 256];
    let mut c = [0; 256];
    let mut routes = [
        RouteSlot::new(&mut a),
        RouteSlot::new(&mut b),
        RouteSlot::new(&mut c),
    ];
    let mut paths = [PathSlot::default(); 4];
    let mut output = [0; 256];
    let mut gap = gap::Router::new(
        &mut gap_id,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let first = gap.attach([1; 32])?;
    let second = gap.attach([2; 32])?;
    let mut id = storage::Instance::new();
    let mut peers = [storage::PeerSlot::new(); 3];
    let mut cache_bytes = [0; 256];
    let mut cache = [storage::CacheSlot::new(&mut cache_bytes)];
    let mut migration_bytes = [0; 256];
    let mut other_migration_bytes = [0; 256];
    let mut migrations = [
        storage::MigrationSlot::new(&mut migration_bytes),
        storage::MigrationSlot::new(&mut other_migration_bytes),
    ];
    let mut owner = storage::Owner::new(
        &mut id,
        &mut peers,
        &mut cache,
        &mut migrations,
        storage::Limits {
            caching: false,
            ..storage::Limits::default()
        },
    )?;
    owner.attach(first, [1; 32])?;
    owner.attach(second, [2; 32])?;
    let Some(storage::Command::Replication(selection)) = owner.next_command(0)? else {
        return Err(Error::NotReady);
    };
    let mut encrypted = [0; 128];
    let (key, length) = block(&mut encrypted)?;
    let data = Data {
        reservation: 0,
        kind: 1,
        priority: 9,
        anonymity: 3,
        replication: 7,
        uid: 55,
        expiration: AbsoluteTime::from_micros(storage::YEAR_US),
        key: &key,
        value: &encrypted[..length],
    };
    owner.selected(selection, Some(data), 1)?;
    let Some(push) = owner.next_push(1)? else {
        return Err(Error::NotReady);
    };
    assert_eq!(push.metadata.uid, 55);
    assert_eq!(push.metadata.replication, 7);
    assert_eq!(push.metadata.anonymity, 3);
    let token = push.token;
    let target = push.neighbor;
    let queued = gap.queue_push(target, push.frame, push.metadata.anonymity, 1)?;
    owner.bind_push(token, target, queued.path)?;
    assert!(gap.unsolicited(queued.path)?);
    assert!(
        gap.next_lookup().is_none(),
        "replication must not invent a source GET"
    );
    assert_eq!(gap.reply_requirement(queued.path)?.level(), Some(3));
    assert_eq!(gap.prepare_reply(queued.path), Err(Error::NotReady));
    // A genuine ordinary consumer is separately owned and is still serviceable.
    let ordinary = gap.start(
        gap::Selection {
            kind: BlockType::DBLOCK,
            query: key,
        },
        9,
        1,
        1,
        60,
        1,
    )?;
    let lookup = gap.next_lookup().ok_or(Error::NotReady)?;
    assert_eq!(lookup.route, ordinary.route);
    let mut wire = [0; 256];
    let n = Put {
        block_type: BlockType::DBLOCK,
        expiration: data.expiration,
        block: data.value,
    }
    .encode(&mut wire)?;
    gap.source_finished_local(ordinary.route, Some(&wire[..n]), 1)?;
    owner.pause(target, RelativeTime::from_micros(1_000_000), 10)?;
    assert!(owner.blocked(target, 1_000_009));
    assert!(!owner.blocked(target, 1_000_010));
    gap.cancel(queued.path)?;
    owner.retire_path(queued.path)?;
    assert!(gap.local_result(ordinary.path)?.is_some());
    assert_eq!(owner.report().push_written, 0);
    assert_eq!(owner.report().push_retired, 1);
    let Some(next) = owner.next_push(11)? else {
        return Err(Error::NotReady);
    };
    assert_ne!(
        next.neighbor, target,
        "old target attempt must not replay on another epoch"
    );
    owner.pause(target, RelativeTime::FOREVER, 12)?;
    assert!(owner.blocked(target, u64::MAX));
    owner.pause(target, RelativeTime::ZERO, 13)?;
    assert!(!owner.blocked(target, 13));
    // Actual selected-score uncertainty is not a no-block response or retry.
    let Some(storage::Command::Replication(unknown)) = owner.next_command(100_001)? else {
        return Err(Error::NotReady);
    };
    owner.failed(unknown, true, 100_002)?;
    assert!(owner.fenced());
    assert_eq!(owner.report().unknown, 1);
    assert!(owner.next_command(100_003)?.is_none());
    owner.request_shutdown();
    assert!(owner.quiesced());
    gap.request_shutdown();
    assert!(gap.quiesced());
    Ok(())
}
