//! Deterministic codec/ownership models; no CORE/socket/native service.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Models assert exact official shapes and original bounded query/source/send generations"
)]
use gnunet_fs::{
    content::encode_data,
    gap::{self, Entropy, NeighborSlot, PathSlot, ResultState, RouteSlot, Router, Selection},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    fs::BlockType,
    fs_gap::{GET_PREFIX, Get, MigrationStop, Put, RETURN_TO, TRANSMIT_TO},
};
struct Zero;
impl Entropy for Zero {
    fn uniform(&mut self, upper: u32) -> Result<u32, Error> {
        if upper == 0 {
            Err(Error::InvalidInput)
        } else {
            Ok(0)
        }
    }
}

#[test]
fn official_get_identity_order_signed_seconds_and_put_have_no_private_fields() -> Result<(), Error>
{
    let key = [0x11; 64];
    let mut identities = [0; 96];
    identities[..32].fill(1);
    identities[32..64].fill(2);
    identities[64..].fill(3);
    let bloom = [0x55; 12];
    let mut bytes = [0xa5; 256];
    let get = Get {
        block_type: BlockType::DBLOCK,
        priority: 42,
        ttl_seconds: -12345,
        reserved: 0,
        bitmap: 7,
        query: &key,
        identities: &identities,
        bloom: &bloom,
    };
    let length = get.encode(&mut bytes)?;
    assert_eq!(length, GET_PREFIX + 96 + 12);
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 137);
    assert_eq!(&bytes[12..16], &(-12345_i32).to_be_bytes());
    assert_eq!(&bytes[24..88], &key);
    let decoded = Get::decode(&bytes[..length])?;
    assert_eq!(decoded, get);
    assert_eq!(decoded.identity(RETURN_TO)?, Some(&[1; 32]));
    assert_eq!(decoded.identity(TRANSMIT_TO)?, Some(&[3; 32]));
    let mut unchanged = [0xa5; 256];
    assert_eq!(
        Get {
            bloom: &[1, 2, 3],
            ..get
        }
        .encode(&mut unchanged),
        Err(Error::Malformed)
    );
    assert_eq!(unchanged, [0xa5; 256]);
    let put = Put {
        block_type: BlockType::IBLOCK,
        expiration: AbsoluteTime::from_micros(777),
        block: b"original encrypted bytes",
    };
    let length = put.encode(&mut bytes)?;
    assert_eq!(length, 16 + put.block.len());
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 138);
    assert_eq!(Put::decode(&bytes[..length])?, put);
    assert_eq!(
        Put {
            block_type: BlockType::new(6),
            ..put
        }
        .encode(&mut unchanged),
        Err(Error::Unsupported)
    );
    assert_eq!(unchanged, [0xa5; 256]);
    let stop = MigrationStop {
        reserved: 0,
        duration: gnunet_wire::official::RelativeTime::from_micros(0x0102_0304_0506_0708),
    };
    let length = stop.encode(&mut bytes)?;
    assert_eq!(length, 16);
    assert_eq!(
        &bytes[..16],
        &[0, 16, 0, 139, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(MigrationStop::decode(&bytes[..length])?, stop);
    assert_eq!(MigrationStop::decode(&bytes[..8]), Err(Error::Truncated));
    assert_eq!(
        MigrationStop::decode(&[0, 8, 0, 139, 0, 0, 0, 0]),
        Err(Error::Malformed)
    );
    let forever = MigrationStop {
        duration: gnunet_wire::official::RelativeTime::FOREVER,
        ..stop
    };
    forever.encode(&mut bytes)?;
    assert_eq!(MigrationStop::decode(&bytes[..16])?, forever);
    let mut too_short = [0xa5; 15];
    assert_eq!(forever.encode(&mut too_short), Err(Error::Capacity));
    assert_eq!(too_short, [0xa5; 15]);
    Ok(())
}

#[test]
fn routed_content_return_path_elapsed_ttl_and_original_loss_are_bounded() -> Result<(), Error> {
    let mut instance = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 4];
    let mut data = [[0; 2048]; 4];
    let mut routes = data.each_mut().map(|bytes| RouteSlot::new(bytes));
    let mut paths = [PathSlot::default(); 8];
    let mut output = [0; 2048];
    let mut router = Router::new(
        &mut instance,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let ingress = router.attach([1; 32])?;
    let reverse = router.attach([2; 32])?;
    let onward = router.attach([3; 32])?;
    let mut ciphertext = [0; 128];
    let encoded = encode_data(b"real encrypted GAP block", &mut ciphertext)?;
    let selection = Selection {
        kind: BlockType::DBLOCK,
        query: encoded.key().query,
    };
    let mut ids = [0; 64];
    ids[..32].fill(2);
    ids[32..].fill(3);
    let get = Get {
        block_type: selection.kind,
        priority: 15000,
        ttl_seconds: 60000,
        reserved: 0,
        bitmap: RETURN_TO | TRANSMIT_TO,
        query: &selection.query,
        identities: &ids,
        bloom: &[],
    };
    let mut query_wire = [0; 256];
    let qsize = get.encode(&mut query_wire)?;
    let original = router.receive_get(ingress, &query_wire[..qsize], 0, &mut Zero)?;
    let duplicate = router.receive_get(ingress, &query_wire[..qsize], 0, &mut Zero)?;
    assert_eq!(router.next_deadline(0), Some(60_000_000));
    assert_eq!(duplicate.route, original.route);
    assert_eq!(duplicate.path, original.path);
    assert!(duplicate.joined);
    let source = router.next_lookup().ok_or(Error::NotFound)?;
    assert_eq!(source.selection, selection);
    assert!(router.next_lookup().is_none());
    assert_eq!(
        router.prepare_query(original.route, onward, 0, &mut Zero),
        Err(Error::NotReady)
    );
    assert_eq!(
        router.source_finished(source.route, None)?,
        ResultState::NoBlock
    );
    assert_eq!(
        router.prepare_query(original.route, ingress, 0, &mut Zero),
        Err(Error::PermissionDenied)
    );
    let tx = router.prepare_query(original.route, onward, 2_500_000, &mut Zero)?;
    let (target, wire) = router.send_bytes(tx)?;
    assert_eq!(target, onward);
    let forwarded = Get::decode(wire)?;
    assert_eq!(forwarded.ttl_seconds, 49997); // 60000 - C10000 decrement - actual elapsed2.5s, truncation.
    assert_eq!(forwarded.query, &selection.query);
    assert_eq!(forwarded.bitmap, 0);
    assert!(forwarded.identities.is_empty());
    assert_eq!(router.written(tx), Err(Error::NotReady));
    router.admitted(tx)?;
    router.exposed(tx)?;
    let written = router.written(tx)?;
    assert!(written.written);
    assert_eq!(
        router.prepare_query(original.route, onward, 2_500_000, &mut Zero),
        Err(Error::PermissionDenied)
    );
    // A real source-clock rollback keeps the same absolute wire target; it is
    // neither clamped nor replaced by a hidden monotonic clock.
    let extra = router.attach([8; 32])?;
    let rolled = router.prepare_query(original.route, extra, 1_500_000, &mut Zero)?;
    assert_eq!(
        Get::decode(router.send_bytes(rolled)?.1)?.ttl_seconds,
        49998
    );
    let stopped = router.send_failed(rolled)?;
    assert!(!stopped.admitted && !stopped.exposed && !stopped.written);
    let put = Put {
        block_type: selection.kind,
        expiration: AbsoluteTime::from_micros(987654321),
        block: encoded.bytes(),
    };
    let mut reply = [0; 256];
    let size = put.encode(&mut reply)?;
    assert_eq!(
        router.receive_put(onward, &reply[..size])?,
        ResultState::Retained
    );
    assert_eq!(
        router.receive_put(onward, &reply[..size])?,
        ResultState::Duplicate
    );
    // Actual positive ownership survives an elapsed local residence while a
    // consumer is blocked; expiry must not erase observed real result bytes.
    assert!(router.expire(61_000_000)?.is_none());
    assert_eq!(router.next_deadline(61_000_000), None);
    let back = router.prepare_reply(original.path)?;
    let (target, wire) = router.send_bytes(back)?;
    assert_eq!(target, reverse);
    assert_eq!(wire, &reply[..size]);
    router.admitted(back)?;
    router.exposed(back)?;
    router.retire_neighbor_paths(reverse)?;
    assert_eq!(router.pending_send(), Some(back));
    assert_eq!(router.send_bytes(back)?.1, &reply[..size]);
    let loss = router.disconnect(reverse)?;
    let pending = loss.pending.ok_or(Error::NotFound)?;
    assert_eq!(pending.transmit, back);
    assert!(pending.admitted && pending.exposed && !pending.written);
    let replacement = router.attach([4; 32])?;
    assert_ne!(replacement, reverse);
    assert_eq!(router.peer(reverse), Err(Error::StaleGeneration));
    assert_eq!(router.prepare_reply(original.path), Err(Error::Closed));
    assert_eq!(router.send_bytes(back), Err(Error::StaleGeneration));

    // Negative signed TTL is still forwardable. A real source failure is
    // explicitly distinct from an original no-transferable-block terminal.
    let negative = router.start(
        Selection {
            kind: BlockType::DBLOCK,
            query: [9; 64],
        },
        90,
        1,
        1,
        -1,
        3_000_000,
    )?;
    let failed_source = router.next_lookup().ok_or(Error::NotFound)?;
    assert_eq!(failed_source.route, negative.route);
    assert_eq!(
        router.source_failed(failed_source.route)?,
        ResultState::SourceFailed
    );
    let unsent = router.prepare_query(negative.route, onward, 5_000_000, &mut Zero)?;
    assert_eq!(Get::decode(router.send_bytes(unsent)?.1)?.ttl_seconds, -3);
    let refused = router.send_failed(unsent)?;
    assert!(!refused.admitted && !refused.exposed && !refused.written);
    router.cancel(negative.path)?;

    let local = router.start(
        Selection {
            kind: BlockType::IBLOCK,
            ..selection
        },
        77,
        1,
        1,
        -1,
        5_000_000,
    )?;
    let source = router.next_lookup().ok_or(Error::NotFound)?;
    assert_eq!(source.route, local.route);
    router.cancel(local.path)?;
    assert_eq!(
        router.collect(local.route, 65_000_001),
        Err(Error::WouldBlock)
    );
    let size = Put {
        block_type: BlockType::IBLOCK,
        ..put
    }
    .encode(&mut reply)?;
    assert_eq!(
        router.source_finished(source.route, Some(&reply[..size]))?,
        ResultState::Retired
    );
    router.collect(local.route, 65_000_001)?;
    assert_eq!(
        router.source_finished(source.route, None),
        Err(Error::StaleGeneration)
    );
    assert!(router.start(selection, 88, 2, 1, 0, 65_000_001).is_err());
    router.request_shutdown();
    assert!(router.quiesced());
    router.collect(original.route, 65_000_001)?;
    router.collect(negative.route, 65_000_001)?;
    Ok(())
}

#[test]
fn repeated_content_get_uses_a_fresh_local_owner_before_old_residence_ends() -> Result<(), Error> {
    let mut instance = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 2];
    let mut data = [[0; 512]; 4];
    let mut routes = data.each_mut().map(|bytes| RouteSlot::new(bytes));
    let mut paths = [PathSlot::default(); 8];
    let mut output = [0; 512];
    let mut router = Router::new(
        &mut instance,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let peer = router.attach([1; 32])?;
    let mut ciphertext = [0; 128];
    let encoded = encode_data(b"the same file block at two positions", &mut ciphertext)?;
    let selection = Selection {
        kind: BlockType::DBLOCK,
        query: encoded.key().query,
    };
    let first = router.start_with_seen(selection, 1, 0, 1, 0, 0, &[], &mut Zero)?;
    let source = router.next_lookup().ok_or(Error::NotFound)?;
    assert_eq!(source.route, first.route);
    assert_eq!(
        router.source_finished(source.route, None)?,
        ResultState::NoBlock
    );
    let old_send = router.prepare_query(first.route, peer, 0, &mut Zero)?;
    assert_eq!(
        Get::decode(router.send_bytes(old_send)?.1)?.query,
        &selection.query
    );
    router.admitted(old_send)?;
    router.exposed(old_send)?;
    let mut reply = [0; 256];
    let size = Put {
        block_type: selection.kind,
        expiration: AbsoluteTime::from_micros(987654321),
        block: encoded.bytes(),
    }
    .encode(&mut reply)?;
    assert_eq!(
        router.receive_put(peer, &reply[..size])?,
        ResultState::Retained
    );
    assert_eq!(router.local_result(first.path)?, Some((1, &reply[..size])));
    router.commit_local(first.path)?;
    assert!(router.retiring(first.route)?);
    assert!(router.local_result(first.path)?.is_none());
    assert_eq!(router.pending_send(), Some(old_send));
    // Reusing the old identity or receiving a neighbor replay still cannot
    // revive its terminal path, even though a new local identity may proceed.
    assert!(matches!(
        router.start_with_seen(selection, 1, 0, 1, 0, 0, &[], &mut Zero),
        Err(Error::Closed)
    ));
    let mut request = [0; 128];
    let qsize = Get {
        block_type: selection.kind,
        priority: 1,
        ttl_seconds: 0,
        reserved: 0,
        bitmap: 0,
        query: &selection.query,
        identities: &[],
        bloom: &[],
    }
    .encode(&mut request)?;
    assert!(matches!(
        router.receive_get(peer, &request[..qsize], 0, &mut Zero),
        Err(Error::Closed)
    ));
    let second = router.start_with_seen(selection, 2, 0, 1, 0, 0, &[], &mut Zero)?;
    assert!(!second.joined);
    assert_ne!(second.route, first.route);
    assert_eq!(router.pending_send(), Some(old_send));
    let concurrent = router.start_with_seen(selection, 3, 0, 1, 0, 0, &[], &mut Zero)?;
    assert!(concurrent.joined);
    assert_eq!(concurrent.route, second.route);
    let source = router.next_lookup().ok_or(Error::NotFound)?;
    assert_eq!(source.route, second.route);
    assert_eq!(
        router.source_finished(source.route, None)?,
        ResultState::NoBlock
    );
    // Only the real old completion releases its original native send slot.
    assert!(router.written(old_send)?.written);
    let new_send = router.prepare_query(second.route, peer, 0, &mut Zero)?;
    assert_eq!(
        Get::decode(router.send_bytes(new_send)?.1)?.query,
        &selection.query
    );
    router.admitted(new_send)?;
    router.exposed(new_send)?;
    assert!(router.written(new_send)?.written);
    assert_eq!(
        router.receive_put(peer, &reply[..size])?,
        ResultState::Retained
    );
    assert!(router.local_result(first.path)?.is_none());
    assert_eq!(router.local_result(second.path)?, Some((2, &reply[..size])));
    assert_eq!(
        router.local_result(concurrent.path)?,
        Some((3, &reply[..size]))
    );
    router.commit_local(second.path)?;
    assert!(router.local_result(second.path)?.is_none());
    assert_eq!(
        router.local_result(concurrent.path)?,
        Some((3, &reply[..size]))
    );
    router.commit_local(concurrent.path)?;
    assert!(router.retiring(second.route)?);
    assert!(router.local_result(concurrent.path)?.is_none());
    assert!(router.retiring(first.route)?);
    Ok(())
}
