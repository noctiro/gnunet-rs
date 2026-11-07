//! Pure FS service leases and official result bytes over bounded caller storage.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible owner tests assert exact wire output, no partial state and original lease lifetime"
)]
use gnunet_crypto::hash512;
use gnunet_fs::service::*;
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::Data,
    fs::{BlockType, ClientPut, Response, SEARCH_CONTINUED, SEARCH_LOOPBACK_ONLY, Search},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn search(query: [u8; 64], kind: BlockType, options: u32) -> Search<'static> {
    Search {
        options,
        block_type: kind,
        anonymity: 1,
        target: [0; 32],
        query,
        seen: &[],
    }
}
fn data<'a>(key: &'a [u8; 64], kind: u32, uid: u64, value: &'a [u8]) -> Data<'a> {
    Data {
        reservation: 0,
        kind,
        priority: 1,
        anonymity: 1,
        replication: 0,
        uid,
        expiration: AbsoluteTime::UNIX_EPOCH,
        key,
        value,
    }
}
fn reply<'id>(value: LocalResult<'id>) -> Result<PreparedReply<'id>, Error> {
    match value {
        LocalResult::Reply(reply) => Ok(reply),
        _ => Err(Error::InvalidInput),
    }
}
fn skip<'id>(value: LocalResult<'id>) -> Result<Advance<'id>, Error> {
    match value {
        LocalResult::Skip(advance) => Ok(advance),
        _ => Err(Error::InvalidInput),
    }
}
#[test]
fn continued_assembly_output_admission_and_disconnect_keep_original_authority() -> TestResult {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::default(); 1];
    let mut hashes_a = [[0; 64]; 2];
    let mut hashes_b = [[0; 64]; 2];
    let mut slots = [QuerySlot::new(&mut hashes_a), QuerySlot::new(&mut hashes_b)];
    let mut core = Service::new(&mut instance, &mut clients, &mut slots, Limits::default())?;
    let client = core.connect()?;
    let a = b"first encrypted body";
    let b = b"second encrypted body";
    let ka = hash512(a);
    let kb = hash512(b);
    let initial = [3; 64];
    let mut full = [4; 128];
    full[64..].fill(5);
    let final_seen = [2; 64];
    let first = core.admit(
        client,
        Search {
            seen: &initial,
            ..search(ka, BlockType::ANY, SEARCH_CONTINUED)
        },
    )?;
    assert!(first.assembling && !first.merged);
    assert!(core.next_local()?.is_none());
    assert!(matches!(
        core.admit(
            client,
            Search {
                seen: &full,
                ..search(ka, BlockType::ANY, SEARCH_CONTINUED)
            }
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(core.seen(first.query)?, &[initial]);
    let second = core.admit(client, search(kb, BlockType::DBLOCK, 0))?;
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    assert_eq!(lookup.query_id(), second.query);
    assert_eq!(lookup.block_type(), BlockType::ANY);
    let mut output = [0xa5; 128];
    assert!(matches!(
        core.prepare_local(
            lookup,
            data(&kb, 1, 10, b),
            &mut output[..4],
            AbsoluteTime::UNIX_EPOCH
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(output, [0xa5; 128]);
    assert!(core.next_local()?.is_none());
    let bad_key = [0; 64];
    let advance = skip(core.prepare_local(
        lookup,
        data(&bad_key, 1, 10, b),
        &mut output,
        AbsoluteTime::UNIX_EPOCH,
    )?)?;
    assert_eq!(advance.reason(), SkipReason::Invalid(Error::Authentication));
    assert!(core.next_local()?.is_none());
    core.skip(advance)?;
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    assert_eq!(lookup.next_uid(), 11);
    let prepared = reply(core.prepare_local(
        lookup,
        data(&kb, 1, 11, b),
        &mut output,
        AbsoluteTime::UNIX_EPOCH,
    )?)?;
    assert!(!core.completed(second.query)?);
    assert!(core.commit_reply(prepared)?);
    assert!(matches!(core.commit_reply(prepared), Err(Error::Stale)));
    assert!(
        matches!(Response::decode(&output[..prepared.bytes()])?,Response::Put(found) if found.block==b && found.last_transmission==AbsoluteTime::NEVER)
    );
    core.release(second.query)?;
    let final_part = core.admit(
        client,
        Search {
            seen: &final_seen,
            ..search(ka, BlockType::ANY, 0)
        },
    )?;
    assert!(final_part.merged && !final_part.assembling);
    assert_eq!(first.query, final_part.query);
    assert_eq!(core.seen(first.query)?.len(), 2);
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    let prepared = reply(core.prepare_local(
        lookup,
        data(&ka, 1, 0, a),
        &mut output,
        AbsoluteTime::UNIX_EPOCH,
    )?)?;
    assert!(core.commit_reply(prepared)?);
    core.release(first.query)?;
    let third = core.admit(client, search(kb, BlockType::DBLOCK, 0))?;
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    core.disconnect(client)?;
    assert!(matches!(core.local_end(lookup), Err(Error::Stale)));
    assert!(matches!(core.descriptor(third.query), Err(Error::Stale)));
    let replacement = core.connect()?;
    assert_ne!(replacement, client);
    assert!(matches!(
        core.admit(client, search(ka, BlockType::DBLOCK, 0)),
        Err(Error::Stale)
    ));
    Ok(())
}
#[test]
fn ublock_authentication_precedes_seen_and_live_route_rescan_preserves_dedup() -> TestResult {
    let body = include_bytes!("ublock_vectors/c-keyword.bin");
    let key = hash512(&body[72..104]);
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::default(); 1];
    let mut hashes = [[0; 64]; 2];
    let mut slots = [QuerySlot::new(&mut hashes)];
    let mut core = Service::new(&mut instance, &mut clients, &mut slots, Limits::default())?;
    let client = core.connect()?;
    let admitted = core.admit(client, search(key, BlockType::UBLOCK, 0))?;
    let mut output = [0xa5; 65535];
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    let prepared = reply(core.prepare_local(
        lookup,
        data(&key, 9, 1, body),
        &mut output,
        AbsoluteTime::from_micros(500),
    )?)?;
    assert!(core.seen(admitted.query)?.is_empty());
    assert!(!core.commit_reply(prepared)?);
    assert_eq!(core.seen(admitted.query)?, &[hash512(body)]);
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    let advance = skip(core.prepare_local(
        lookup,
        data(&key, 9, 2, body),
        &mut output,
        AbsoluteTime::from_micros(500),
    )?)?;
    assert_eq!(advance.reason(), SkipReason::Duplicate);
    core.skip(advance)?;
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    assert_eq!(lookup.next_uid(), 3);
    core.local_end(lookup)?;
    let route = core.next_route()?.ok_or(Error::NotFound)?;
    assert_eq!(route.query_id(), admitted.query);
    assert_eq!(route.search().query, key);
    let incoming = ClientPut {
        block_type: BlockType::UBLOCK,
        expiration: AbsoluteTime::UNIX_EPOCH,
        last_transmission: AbsoluteTime::NEVER,
        num_transmissions: 0,
        respect_offered: 0,
        block: body,
    };
    assert!(matches!(
        core.prepare_peer(route, incoming, &mut output, AbsoluteTime::UNIX_EPOCH)?,
        PeerResult::Ignored(SkipReason::Duplicate)
    ));
    let mut tampered = body.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        core.prepare_peer(
            route,
            ClientPut {
                block: &tampered,
                ..incoming
            },
            &mut output,
            AbsoluteTime::UNIX_EPOCH
        )?,
        PeerResult::Ignored(SkipReason::Invalid(_))
    ));
    core.route_idle(route)?;
    assert!(core.next_route()?.is_none());
    core.retry_route(admitted.query)?;
    let replacement = core.next_route()?.ok_or(Error::NotFound)?;
    assert!(matches!(
        core.prepare_peer(route, incoming, &mut output, AbsoluteTime::UNIX_EPOCH),
        Err(Error::Stale)
    ));
    core.rescan(admitted.query)?;
    assert_eq!(core.seen(admitted.query)?, &[hash512(body)]);
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    assert_eq!(lookup.next_uid(), 0);
    core.local_end(lookup)?;
    assert!(core.next_route()?.is_none());
    core.disconnect(client)?;
    assert!(matches!(
        core.prepare_peer(replacement, incoming, &mut output, AbsoluteTime::UNIX_EPOCH),
        Err(Error::Stale)
    ));
    Ok(())
}
#[test]
fn expiry_policy_ondemand_and_foreign_owner_do_not_fabricate_wire_completion() -> TestResult {
    let body = include_bytes!("ublock_vectors/c-keyword.bin");
    let key = hash512(&body[72..104]);
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::default(); 1];
    let mut hashes = [[0; 64]; 2];
    let mut slots = [QuerySlot::new(&mut hashes)];
    let mut core = Service::new(
        &mut instance,
        &mut clients,
        &mut slots,
        Limits {
            expire_ublocks: true,
            ..Limits::default()
        },
    )?;
    let client = core.connect()?;
    let admitted = core.admit(client, search(key, BlockType::UBLOCK, SEARCH_LOOPBACK_ONLY))?;
    let mut output = [0xa5; 65535];
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    let advance = skip(core.prepare_local(
        lookup,
        data(&key, 9, 0, body),
        &mut output,
        AbsoluteTime::UNIX_EPOCH,
    )?)?;
    assert_eq!(advance.reason(), SkipReason::Expired);
    core.skip(advance)?;
    assert!(core.seen(admitted.query)?.is_empty());
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    core.local_end(lookup)?;
    assert!(core.completed(admitted.query)?);
    assert!(core.next_route()?.is_none());
    assert!(output.iter().all(|byte| *byte == 0xa5));
    core.release(admitted.query)?;
    let cipher = b"encoded on-demand bytes";
    let key = hash512(cipher);
    let query = core.admit(client, search(key, BlockType::DBLOCK, 0))?.query;
    let lookup = core.next_local()?.ok_or(Error::NotFound)?;
    let mut descriptor = [0; 72];
    descriptor[..64].fill(5);
    descriptor[64..].copy_from_slice(&99_u64.to_be_bytes());
    assert!(
        matches!(core.prepare_local(lookup,data(&key,6,u64::MAX,&descriptor),&mut output,AbsoluteTime::UNIX_EPOCH)?,LocalResult::OnDemand(value) if value.file_id==[5;64] && value.offset==99)
    );
    let mut other_instance = Instance::new();
    let mut other_clients = [ClientSlot::default(); 1];
    let mut other_hashes = [];
    let mut other_slots = [QuerySlot::new(&mut other_hashes)];
    let mut other = Service::new(
        &mut other_instance,
        &mut other_clients,
        &mut other_slots,
        Limits::default(),
    )?;
    let foreign = other.connect()?;
    assert!(matches!(other.local_end(lookup), Err(Error::Stale)));
    assert!(matches!(core.disconnect(foreign), Err(Error::Stale)));
    let advance = core.skip_local(lookup, u64::MAX, SkipReason::Invalid(Error::Io))?;
    core.skip(advance)?;
    assert!(!core.completed(query)?);
    assert!(core.next_local()?.is_none());
    assert!(core.next_route()?.is_some());
    assert!(output.iter().all(|byte| *byte == 0xa5));
    Ok(())
}

#[test]
fn current_route_snapshot_borrows_committed_seen_and_rejects_old_authority() -> TestResult {
    let body = include_bytes!("ublock_vectors/c-keyword.bin");
    let key = hash512(&body[72..104]);
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::default(); 1];
    let mut hashes = [[0; 64]; 2];
    let mut slots = [QuerySlot::new(&mut hashes)];
    let mut core = Service::new(&mut instance, &mut clients, &mut slots, Limits::default())?;
    let client = core.connect()?;
    let original = core.admit(client, search(key, BlockType::UBLOCK, 0))?;
    let local = core.next_local()?.ok_or(Error::NotFound)?;
    core.local_end(local)?;
    let route = core.next_route()?.ok_or(Error::NotFound)?;
    assert!(core.route_snapshot(route)?.1.is_empty());
    let mut output = [0; 65535];
    let incoming = ClientPut {
        block_type: BlockType::UBLOCK,
        expiration: AbsoluteTime::NEVER,
        last_transmission: AbsoluteTime::NEVER,
        num_transmissions: 0,
        respect_offered: 0,
        block: body,
    };
    let PeerResult::Reply(reply) =
        core.prepare_peer(route, incoming, &mut output, AbsoluteTime::UNIX_EPOCH)?
    else {
        return Err(Error::InvalidInput.into());
    };
    assert!(core.route_snapshot(route)?.1.is_empty());
    assert!(!core.commit_reply(reply)?);
    let (actual, seen) = core.route_snapshot(route)?;
    assert_eq!(actual.query, key);
    assert_eq!(actual.block_type, BlockType::UBLOCK);
    assert_eq!(seen, &[hash512(body)]);
    core.route_idle(route)?;
    assert!(matches!(core.route_snapshot(route), Err(Error::Stale)));
    core.retry_route(original.query)?;
    let current = core.next_route()?.ok_or(Error::NotFound)?;
    assert!(matches!(core.route_snapshot(route), Err(Error::Stale)));
    assert_eq!(core.route_snapshot(current)?.1, &[hash512(body)]);
    core.disconnect(client)?;
    assert!(matches!(core.route_snapshot(current), Err(Error::Stale)));
    Ok(())
}
