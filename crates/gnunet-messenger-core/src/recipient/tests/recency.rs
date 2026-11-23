//! Genuine RECENT notifications are distinct from authenticated history/GETs.
use super::derivation::join_epoch;
use super::*;

fn written_get<'id>(
    core: &mut Core<'id>,
    address: (Room<'id>, Source<'id>),
    hash: Hash,
) -> Result<Operation<'id>, Error> {
    let operation = core.request_missing(address.1, hash, 100, 10_000)?;
    let Work::Wire { binding, frame, .. } = core.take_work(address.0)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, operation);
    core.write_progress(binding, frame.expose().len(), true)?;
    Ok(operation)
}
fn deliver<'id>(
    core: &mut Core<'id>,
    source: Source<'id>,
    signer: &SecretKey,
    bytes: &[u8],
    epoch: &Hash,
    flags: u32,
) -> Result<Hash, Error> {
    let hash = gnunet_crypto::hash512(&bytes[68..]);
    core.on_notification(
        source,
        wire::Response::Receive {
            key: &ROOM,
            sender: &gnunet_crypto::hash512(&signer.public_key()?),
            context: &[0; 64],
            hash: &hash,
            epoch,
            flags,
            message: wire::SensitiveBytes::new(bytes),
        },
        100,
    )?;
    Ok(hash)
}

#[test]
fn nonrecent_signed_epoch_history_cannot_change_the_live_cursor_or_sync_roots() -> Result<(), Error>
{
    let local = identity(81)?;
    let remote = identity(82)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address = open(&mut core, &local)?;
    let (live, _) = join_epoch(&mut core, address, &local, &LOCAL, &[0; 64])?;
    let mut hpke = [0; 36];
    crypto::EcdheSecret::from_bytes([83; 32])
        .public_key()
        .encode_hpke(&mut hpke)?;
    let public = remote.public_key()?;
    let body = Body::Join {
        epoch: &live,
        public_key: wire::PublicKey::new(&public)?,
        hpke_key: wire::keys::HpkePublicKey::new(&hpke)?,
    };
    let bytes = signed(&remote, &REMOTE, &live, body, 0)?;
    let historical = gnunet_crypto::hash512(&bytes.expose()[68..]);
    deliver(
        &mut core,
        address.1,
        &remote,
        bytes.expose(),
        &historical,
        0,
    )?;
    drain(&mut core, address.0)?;
    let row = core.rooms.get(address.0.slot)?;
    assert_eq!((row.last_message, row.current_epoch), (live, live));
    assert_eq!(row.queues.frontier.as_slice(), &[live]);
    let mut members = core.epoch_members(address.0, &historical)?;
    assert_eq!(members.len(), 2);
    let first = members.next().ok_or(Fault::NotFound)?;
    let last = members.next_back().ok_or(Fault::NotFound)?;
    assert_eq!(core.contact_public(first)?, &local.public_key()?);
    assert_eq!(core.contact_public(last)?, &public);
    assert!(!core.frontier_sync_required(address.0)?);
    Ok(())
}

#[test]
fn authenticated_recent_duplicate_promotes_once_even_when_it_matches_a_get() -> Result<(), Error> {
    let local = identity(84)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address = open(&mut core, &local)?;
    let (epoch, _) = join_epoch(&mut core, address, &local, &LOCAL, &[0; 64])?;
    let bytes = signed(
        &local,
        &LOCAL,
        &epoch,
        Body::Name {
            name: Text::new(b"original signed name")?,
        },
        10,
    )?;
    let hash = gnunet_crypto::hash512(&bytes.expose()[68..]);
    let first = written_get(&mut core, address, hash)?;
    deliver(&mut core, address.1, &local, bytes.expose(), &epoch, 0)?;
    drain(&mut core, address.0)?;
    core.retire_operation(first)?;
    assert_eq!(core.rooms.get(address.0.slot)?.last_message, epoch);
    let before = core.frontier_version(address.0)?;
    let second = written_get(&mut core, address, hash)?;
    deliver(&mut core, address.1, &local, bytes.expose(), &epoch, 8)?;
    assert_eq!(core.operation_phase(second)?, OperationPhase::Complete);
    drain(&mut core, address.0)?;
    let row = core.rooms.get(address.0.slot)?;
    let node = row
        .nodes
        .get(row.find_node(&hash).ok_or(Fault::NotFound)?)?;
    assert!(node.requested && node.frontier_recent && node.frontier_applied);
    assert_eq!(node.meta.flags, 0);
    assert_eq!(
        core.message(address.0, &hash)?.origin().live(),
        Some(address.1)
    );
    assert_eq!((row.last_message, row.current_epoch), (hash, epoch));
    assert_eq!(core.frontier_version(address.0)?, before + 1);
    deliver(&mut core, address.1, &local, bytes.expose(), &epoch, 8)?;
    drain(&mut core, address.0)?;
    assert_eq!(core.frontier_version(address.0)?, before + 1);
    Ok(())
}
