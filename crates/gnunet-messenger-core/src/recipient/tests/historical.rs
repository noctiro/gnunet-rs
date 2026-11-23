//! Actual signed historical ANNOUNCEMENT/APPEAL/ACCESS and SECRET AEAD.
//! Native writes/SYNC replies are explicit Core port observations, not IPC tests.
use super::*;
use wire::envelope::Kind;
const IDENTIFIER: ShortHash = [0; 32];

fn join_after<'id>(
    core: &mut Core<'id>,
    address: (Room<'id>, Source<'id>),
    signer: &SecretKey,
    id: &ShortHash,
    previous: &Hash,
    parent: &Hash,
) -> Result<Hash, Error> {
    let hpke = crypto::EcdheSecret::from_bytes([id[0] + 40; 32]);
    let mut public = [0; 36];
    hpke.public_key().encode_hpke(&mut public)?;
    let signing = signer.public_key()?;
    let body = Body::Join {
        epoch: parent,
        public_key: wire::PublicKey::new(&signing)?,
        hpke_key: wire::keys::HpkePublicKey::new(&public)?,
    };
    let bytes = signed(signer, id, previous, body, 0)?;
    let hash = gnunet_crypto::hash512(&bytes.expose()[68..]);
    let source = core
        .rooms
        .get(address.1.room)?
        .sources
        .get(address.1.slot)?;
    let actual = if source.public == Some(signing)
        && source.member_id == Some(*id)
        && !core.source_joined(address.1)?
    {
        assert_eq!(core.rooms.get(address.1.room)?.last_message, *previous);
        assert_eq!(core.rooms.get(address.1.room)?.current_epoch, *parent);
        owned_join(core, address, signer, public)?
    } else {
        receive(core, address, signer, id, previous, hash, body)?
    };
    assert_eq!(actual, hash);
    Ok(hash)
}
fn notification<'id>(
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
fn write_wire<'id>(core: &mut Core<'id>, room: Room<'id>) -> Result<Binding<'id>, Error> {
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    core.write_progress(binding, frame.expose().len(), true)?;
    Ok(binding)
}
fn sign_and_write<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    key: &SecretKey,
    epoch: &Hash,
) -> Result<SensitiveBuffer<8192>, Error> {
    let Work::Sign {
        binding,
        kind,
        body,
        sender,
        previous,
        timestamp,
        ..
    } = core.take_work(room)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.epoch(), epoch);
    assert_eq!(&previous, epoch); // Canonical old epoch anchor used by official C.
    let bytes = signed(
        key,
        &sender,
        &previous,
        Body::decode(kind, body.expose(), PROFILE)?,
        timestamp,
    )?;
    core.complete_signature(
        binding,
        OwnedBytes::copy_from(bytes.expose())?,
        padding::Decode::Absent,
        100,
    )
    .map_err(|e| e.error)?;
    assert_eq!(write_wire(core, room)?.operation(), binding.operation());
    Ok(bytes)
}

fn direct<'id>(
    core: &mut Core<'id>,
    address: (Room<'id>, Source<'id>),
    bytes: &[u8],
    epoch: Hash,
) -> Result<Hash, Error> {
    let hash = core
        .receive_owned(
            address.1,
            ReceiveMeta {
                epoch,
                flags: 8,
                requested: true,
                sender_hash: None,
                context: None,
            },
            OwnedBytes::copy_from(bytes)?,
        )
        .map_err(|error| error.error)?;
    drain(core, address.0)?;
    Ok(hash)
}
mod recovery;
mod rejections;

mod bootstrap;

mod replay;

mod echo;
