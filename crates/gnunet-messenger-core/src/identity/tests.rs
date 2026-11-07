//! Actual peer signatures and trusted owned-history projection, without native
//! PILS/CADET/storage receipts. Configure/rotate are explicit local source facts.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Real cryptographic core cases assert original bytes, historical attribution and refusal atomicity"
)]
use super::*;
use crate::archive::CommittedArchive;
use gnunet_identity::SecretKey;
use gnunet_types::AbsoluteTime;
use wire::{body::Body, envelope::Kind, padding, profile::Profile};
use zeroize::Zeroizing;
const PROFILE: Profile = Profile::LITTLE_255;
fn key(seed: u8) -> Result<SecretKey, Error> {
    let mut bytes = Zeroizing::new([seed; 36]);
    bytes[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    Ok(SecretKey::from_serialized(&bytes[..])?)
}
fn peer(key: &SecretKey) -> Result<[u8; 32], Error> {
    key.public_key()?[4..]
        .try_into()
        .map_err(|_| Fault::Malformed.into())
}
fn limits() -> Limits {
    Limits {
        own_signers: 4,
        rooms: 2,
        contacts: 4,
        sources_per_room: 4,
        sessions_per_room: 4,
        messages_per_room: 16,
        epochs_per_room: 4,
        groups_per_epoch: 4,
        subscriptions_per_room: 4,
        operations_per_room: 4,
        events: 64,
        missing_per_room: 4,
        nonce_per_epoch: 4,
        total_bytes: 4 * 1024 * 1024,
        ..Limits::default()
    }
}
fn drain<'id>(core: &mut Core<'id>, room: Room<'id>) -> Result<(), Error> {
    for _ in 0..8 {
        core.advance(room, 100)?;
        while core.pop_event().is_some() {}
    }
    Ok(())
}
fn signed_peer<'id>(
    core: &mut Core<'id>,
    source: Source<'id>,
    key: &SecretKey,
    now: u64,
) -> Result<(Binding<'id>, OwnedBytes), Error> {
    let peer = peer(key)?;
    let op = core.prepare_peer(source, peer, Body::Peer { peer: &peer }, now, 1000)?;
    let Some(ServiceSignWork {
        binding,
        kind,
        public,
        sender,
        previous,
        timestamp,
        ..
    }) = core.take_service_signing_work(core.event_room(source.room))?
    else {
        return Err(Fault::NotReady.into());
    };
    assert_eq!(binding.operation(), op);
    assert_eq!(kind, Kind::PEER);
    assert_eq!(public, key.public_key()?);
    let mut signed = SensitiveBuffer::<1024>::new();
    signed.encode_signed(
        key,
        crypto::signature::SigningHeader {
            timestamp: AbsoluteTime::from_micros(timestamp),
            sender_id: &sender,
            previous: &previous,
        },
        Body::Peer { peer: &peer },
        PROFILE,
        padding::Encode::Absent,
    )?;
    Ok((binding, OwnedBytes::copy_from(signed.expose())?))
}
struct Trusted(Zeroizing<Vec<u8>>);
impl CommittedArchive for Trusted {
    fn generation(&self) -> u64 {
        1
    }
    fn expose_committed(&self) -> &[u8] {
        &self.0
    }
}

#[test]
fn two_healthy_identities_preserve_signed_history_and_restore_no_current_authority()
-> Result<(), Error> {
    let a = key(31)?;
    let b = key(32)?;
    let remote = key(33)?;
    let fresh = key(34)?;
    let pa = peer(&a)?;
    let pb = peer(&b)?;
    let pr = peer(&remote)?;
    let pf = peer(&fresh)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Service, limits(), PROFILE)?;
    core.configure_local_peer(pa)?;
    let room = core.room([1; 64], None)?;
    let source = core.attach_source(
        room,
        SourceRole::ServiceSigner(pa),
        padding::Decode::Absent,
        None,
    )?;
    let original_source = source.observation();
    let (old, bytes) = signed_peer(&mut core, source, &a, 10)?;
    let original_a = Zeroizing::new(bytes.expose().to_vec());
    let charge = core.charged_bytes();
    assert!(matches!(
        core.rotate_local_peer(pb),
        Err(Error::Protocol(Fault::NotReady))
    ));
    assert_eq!(core.charged_bytes(), charge);
    core.complete_signature(old, bytes, padding::Decode::Absent, 11)
        .map_err(|e| e.error)?;
    let original_wire = match &core.check_binding(old)?.job {
        Job::Wire {
            frame: Some(frame), ..
        } => (frame.expose().as_ptr(), frame.expose().len()),
        _ => return Err(Fault::Conflict.into()),
    };
    assert!(core.take_service_signing_work(room)?.is_none());
    assert_eq!(
        core.operation_phase(old.operation())?,
        OperationPhase::Prepared
    );
    let preserved_wire = match &core.check_binding(old)?.job {
        Job::Wire {
            frame: Some(frame), ..
        } => (frame.expose().as_ptr(), frame.expose().len()),
        _ => return Err(Fault::Conflict.into()),
    };
    assert_eq!(preserved_wire, original_wire);
    // A verified signature awaiting actual local commit is still original work.
    assert!(matches!(
        core.rotate_local_peer(pb),
        Err(Error::Protocol(Fault::NotReady))
    ));
    let ha = core.service_commit_signature(old, 12)?;
    core.retire_operation(old.operation())?;
    drain(&mut core, room)?;
    assert!(core.rotate_local_peer(pb)?);
    assert!(!core.rotate_local_peer(pb)?);
    assert_eq!(source.observation(), original_source);
    assert!(core.is_own_signer(&pa) && core.is_own_signer(&pb));
    assert!(matches!(
        core.attach_source(
            room,
            SourceRole::ServiceSigner(pa),
            padding::Decode::Absent,
            None
        ),
        Err(Error::Permission)
    ));
    let (new, bytes) = signed_peer(&mut core, source, &b, 20)?;
    let original_b = Zeroizing::new(bytes.expose().to_vec());
    core.complete_signature(new, bytes, padding::Decode::Absent, 21)
        .map_err(|e| e.error)?;
    let hb = core.service_commit_signature(new, 22)?;
    core.retire_operation(new.operation())?;
    drain(&mut core, room)?;
    let foreign = core.attach_source(room, SourceRole::Peer(pr), padding::Decode::Absent, None)?;
    let mut signed = SensitiveBuffer::<1024>::new();
    signed.encode_signed(
        &remote,
        crypto::signature::SigningHeader {
            timestamp: AbsoluteTime::from_micros(30),
            sender_id: &pr,
            previous: &hb,
        },
        Body::Peer { peer: &pr },
        PROFILE,
        padding::Encode::Absent,
    )?;
    core.receive_owned(
        foreign,
        ReceiveMeta {
            epoch: [0; 64],
            flags: 0,
            requested: false,
            sender_hash: None,
            context: None,
        },
        OwnedBytes::copy_from(signed.expose())?,
    )
    .map_err(|e| e.error)?;
    drain(&mut core, room)?;
    assert!(!core.is_own_signer(&pr));
    let image = core.prepare_archive(1 << 20)?;
    assert_eq!(image.historical_peer(), Some(pb));
    let mut restored_instance = Instance::new();
    let (mut restored, generation, historical) = Core::recover_archive(
        &mut restored_instance,
        &Trusted(image.into_body()),
        limits(),
        PROFILE,
        1 << 20,
    )?
    .into_parts();
    assert_eq!((generation, historical), (1, Some(pb)));
    let restored_room = restored.retained_rooms().next().ok_or(Fault::NotFound)?;
    assert!(restored.local_peer.is_none());
    assert!(restored.rooms.get(restored_room.slot)?.sources.len() == 0);
    assert!(restored.rooms.get(restored_room.slot)?.operations.len() == 0);
    for (hash, signer, bytes) in [
        (ha, pa, original_a.as_slice()),
        (hb, pb, original_b.as_slice()),
    ] {
        let message = restored
            .retained_messages(restored_room)?
            .find(|m| m.hash() == &hash)
            .ok_or(Fault::NotFound)?;
        assert!(message.original().is_some_and(|raw| raw == bytes));
        assert_eq!(
            message.provenance().role(),
            SourceRole::ServiceSigner(signer)
        );
        assert!(matches!(message.original_signer(), Some(OriginalSigner::Peer(p)) if p == signer));
        assert!(message.origin().live().is_none());
    }
    assert!(matches!(
        restored.attach_source(
            restored_room,
            SourceRole::ServiceSigner(pb),
            padding::Decode::Absent,
            None
        ),
        Err(Error::Permission)
    ));
    assert!(restored.check_source(source).is_err());
    // A fresh actual local observation can differ from every historical peer;
    // it does not certify a shared master or recover an old live source.
    restored.configure_local_peer(pf)?;
    restored.attach_source(
        restored_room,
        SourceRole::ServiceSigner(pf),
        padding::Decode::Absent,
        None,
    )?;
    assert!(!restored.is_own_signer(&pr));
    assert!(
        restored.is_own_signer(&pa) && restored.is_own_signer(&pb) && restored.is_own_signer(&pf)
    );
    Ok(())
}

#[test]
fn identity_capacity_refusal_preserves_all_room_leases_and_original_signing_permission()
-> Result<(), Error> {
    let a = key(41)?;
    let b = key(42)?;
    let pa = peer(&a)?;
    let pb = peer(&b)?;
    let mut instance = Instance::new();
    let mut limits = limits();
    limits.own_signers = 1;
    let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
    core.configure_local_peer(pa)?;
    // Even a history with no rooms retains only historical lineage on load;
    // exporting a new cut cannot invent its absent current local authority.
    let empty_history = Trusted(core.prepare_archive(1 << 20)?.into_body());
    let mut restored_instance = Instance::new();
    let (restored, _, historical) = Core::recover_archive(
        &mut restored_instance,
        &empty_history,
        limits,
        PROFILE,
        1 << 20,
    )?
    .into_parts();
    assert_eq!(historical, Some(pa));
    assert!(restored.local_peer.is_none());
    assert!(matches!(
        restored.prepare_archive(1 << 20),
        Err(Error::Protocol(Fault::NotReady))
    ));
    let room_a = core.room([1; 64], None)?;
    let room_b = core.room([2; 64], None)?;
    let source_a = core.attach_source(
        room_a,
        SourceRole::ServiceSigner(pa),
        padding::Decode::Absent,
        None,
    )?;
    let source_b = core.attach_source(
        room_b,
        SourceRole::ServiceSigner(pa),
        padding::Decode::Absent,
        None,
    )?;
    let before = core.prepare_archive(1 << 20)?.into_body();
    let charge = core.charged_bytes();
    assert!(matches!(
        core.rotate_local_peer(pb),
        Err(Error::Protocol(Fault::Capacity))
    ));
    assert_eq!(core.charged_bytes(), charge);
    assert!(!core.is_own_signer(&pb));
    assert!(before.as_slice() == core.prepare_archive(1 << 20)?.into_body().as_slice());
    for source in [source_a, source_b] {
        let (binding, bytes) = signed_peer(&mut core, source, &a, 10)?;
        core.complete_signature(binding, bytes, padding::Decode::Absent, 11)
            .map_err(|e| e.error)?;
        core.service_commit_signature(binding, 12)?;
        core.retire_operation(binding.operation())?;
    }
    assert!(matches!(
        core.configure_local_peer(pb),
        Err(Error::Permission)
    ));
    Ok(())
}
