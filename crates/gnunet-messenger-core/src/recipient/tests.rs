//! Real member signatures, HPKE and record AEAD through the public core. Local
//! CREATE/OPEN/write observations are explicit pure port inputs, not native IPC
//! or interoperability receipts. No contact/authentication rows are fabricated.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible real-crypto fixtures assert recipient provenance and original ownership"
)]
use crate::*;
use gnunet_identity::SecretKey;
use gnunet_types::{AbsoluteTime, Error as Fault};
use wire::{
    body::{Body, Text},
    padding,
    profile::Profile,
};
use zeroize::Zeroizing;
const PROFILE: Profile = Profile::LITTLE_255;
const ROOM: Hash = [1; 64];
const LOCAL: ShortHash = [1; 32];
const REMOTE: ShortHash = [2; 32];

struct Entropy(u8);
impl crypto::Entropy for Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Fault> {
        for byte in out {
            self.0 = self.0.wrapping_add(17);
            *byte = self.0;
        }
        Ok(())
    }
}
fn identity(seed: u8) -> Result<SecretKey, Error> {
    let mut bytes = Zeroizing::new([seed; 36]);
    bytes[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    Ok(SecretKey::from_serialized(&bytes[..])?)
}
fn limits() -> Limits {
    Limits {
        rooms: 2,
        contacts: 16,
        sources_per_room: 4,
        sessions_per_room: 16,
        messages_per_room: 32,
        epochs_per_room: 16,
        groups_per_epoch: 4,
        subscriptions_per_room: 8,
        operations_per_room: 8,
        events: 128,
        missing_per_room: 16,
        nonce_per_epoch: 16,
        work_per_turn: 64,
        total_bytes: 16 * 1024 * 1024,
        ..Limits::default()
    }
}
fn drain<'id>(core: &mut Core<'id>, room: Room<'id>) -> Result<(), Error> {
    for _ in 0..4 {
        core.advance(room, 100)?;
        while core.pop_event().is_some() {}
    }
    Ok(())
}
fn open<'id>(core: &mut Core<'id>, key: &SecretKey) -> Result<(Room<'id>, Source<'id>), Error> {
    let public = key.public_key()?;
    let room = core.room(ROOM, Some(public))?;
    let source = core.attach_source(
        room,
        SourceRole::Client,
        padding::Decode::Absent,
        Some(public),
    )?;
    core.create_submitted(source)?;
    core.on_notification(
        source,
        wire::Response::MemberId {
            key: &ROOM,
            id: &LOCAL,
            reset: 1,
        },
        1,
    )?;
    let operation = core.open(source, 10_000)?;
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    core.write_progress(binding, frame.expose().len(), true)?;
    core.on_notification(
        source,
        wire::Response::Open(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous: &[0; 64],
            epoch: &[0; 64],
        }),
        2,
    )?;
    core.retire_operation(operation)?;
    while core.pop_event().is_some() {}
    Ok((room, source))
}
fn signed(
    key: &SecretKey,
    id: &ShortHash,
    previous: &Hash,
    body: Body<'_>,
    timestamp: u64,
) -> Result<SensitiveBuffer<8192>, Error> {
    let mut bytes = SensitiveBuffer::new();
    bytes.encode_signed(
        key,
        crypto::signature::SigningHeader {
            timestamp: AbsoluteTime::from_micros(timestamp),
            sender_id: id,
            previous,
        },
        body,
        PROFILE,
        padding::Encode::Absent,
    )?;
    Ok(bytes)
}
fn receive<'id>(
    core: &mut Core<'id>,
    (room, source): (Room<'id>, Source<'id>),
    key: &SecretKey,
    id: &ShortHash,
    previous: &Hash,
    epoch: Hash,
    body: Body<'_>,
) -> Result<Hash, Error> {
    let timestamp = if crate::graph::epoch_kind(body.kind()) {
        0
    } else {
        10
    };
    let bytes = signed(key, id, previous, body, timestamp)?;
    let hash = core
        .receive_owned(
            source,
            ReceiveMeta {
                epoch,
                flags: 0,
                requested: false,
                sender_hash: None,
                context: None,
            },
            OwnedBytes::copy_from(bytes.expose())?,
        )
        .map_err(|e| e.error)?;
    drain(core, room)?;
    Ok(hash)
}
fn join<'id>(
    core: &mut Core<'id>,
    (room, source): (Room<'id>, Source<'id>),
    key: &SecretKey,
    id: &ShortHash,
    previous: &Hash,
    epoch: Hash,
    hpke: &crypto::EcdheSecret,
) -> Result<(Hash, MemberSession<'id>, Contact<'id>), Error> {
    let mut public = [0; 36];
    hpke.public_key().encode_hpke(&mut public)?;
    let signing = key.public_key()?;
    let hash = receive(
        core,
        (room, source),
        key,
        id,
        previous,
        epoch,
        Body::Join {
            epoch: &epoch,
            public_key: wire::PublicKey::new(&signing)?,
            hpke_key: wire::keys::HpkePublicKey::new(&public)?,
        },
    )?;
    let (member, contact) = core
        .members(room)?
        .find_map(|(member, contact, actual, phase)| {
            (actual == *id && phase == SessionPhase::Active).then_some((member, contact))
        })
        .ok_or(Fault::NotReady)?;
    Ok((hash, member, contact))
}
fn private(key: crypto::EcdhePublic, text: &[u8]) -> Result<SensitiveBuffer<8192>, Error> {
    let mut ciphertext = SensitiveBuffer::new();
    ciphertext.seal_private(
        key,
        Body::Text {
            text: Text::new(text)?,
        },
        PROFILE,
        &mut SensitiveBuffer::<8192>::new(),
        &mut Entropy(7),
    )?;
    Ok(ciphertext)
}

#[test]
fn incoming_private_keeps_the_actual_key_owner_after_identity_rotation_and_failed_aead()
-> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let replacement = identity(33)?;
    let old_public = local.public_key()?;
    let old_key = crypto::EcdheSecret::from_bytes([41; 32]);
    let remote_key = crypto::EcdheSecret::from_bytes([42; 32]);
    let next_key = crypto::EcdheSecret::from_bytes([43; 32]);
    let old_hpke = old_key.public_key();
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let (room, source) = open(&mut core, &local)?;
    let (local_join, local_member, recipient) = join(
        &mut core,
        (room, source),
        &local,
        &LOCAL,
        &[0; 64],
        [0; 64],
        &old_key,
    )?;
    let (remote_join, _, sender) = join(
        &mut core,
        (room, source),
        &remote,
        &REMOTE,
        &local_join,
        local_join,
        &remote_key,
    )?;
    core.retain_recipient_key(local_member, old_key)?;
    let encrypted = private(old_hpke, b"before identity rotation")?;
    let message = receive(
        &mut core,
        (room, source),
        &remote,
        &REMOTE,
        &remote_join,
        remote_join,
        crypto::message::private_body(&encrypted),
    )?;
    assert!(core.recipient(room, &message)?.is_none());
    core.decrypt_message(room, &message, &mut SensitiveBuffer::<8192>::new())?;
    drain(&mut core, room)?;
    assert!(core.message(room, &message)?.sender() == Some(sender));
    assert!(core.recipient(room, &message)? == Some(recipient));
    assert!(sender != recipient);
    let lineage = core
        .message(room, &message)?
        .recipient_attribution()
        .ok_or(Fault::NotReady)?
        .member_lineage();
    let mut hpke = [0; 36];
    next_key.public_key().encode_hpke(&mut hpke)?;
    let next_public = replacement.public_key()?;
    let refresh = receive(
        &mut core,
        (room, source),
        &local,
        &LOCAL,
        &message,
        remote_join,
        Body::Key {
            public_key: wire::PublicKey::new(&next_public)?,
            hpke_key: wire::keys::HpkePublicKey::new(&hpke)?,
        },
    )?;
    let current = core.local_member(room)?.ok_or(Fault::NotReady)?;
    core.retain_recipient_key(current, next_key)?;
    assert_eq!(core.contact_public(recipient)?, &next_public);
    assert_eq!(
        core.message(room, &message)?.private_recipient(),
        Some(&old_public)
    );
    assert_eq!(
        core.message(room, &message)?
            .recipient_attribution()
            .ok_or(Fault::NotReady)?
            .member_lineage(),
        lineage
    );
    let encrypted = private(old_hpke, b"old retained recipient key")?;
    let second = receive(
        &mut core,
        (room, source),
        &remote,
        &REMOTE,
        &refresh,
        remote_join,
        crypto::message::private_body(&encrypted),
    )?;
    core.decrypt_message(room, &second, &mut SensitiveBuffer::<8192>::new())?;
    drain(&mut core, room)?;
    assert!(core.recipient(room, &second)? == Some(recipient));
    assert_eq!(
        core.message(room, &second)?.private_recipient(),
        Some(&old_public)
    );
    let wrong = private(
        crypto::EcdheSecret::from_bytes([99; 32]).public_key(),
        b"unrelated key",
    )?;
    let rejected = receive(
        &mut core,
        (room, source),
        &remote,
        &REMOTE,
        &second,
        remote_join,
        crypto::message::private_body(&wrong),
    )?;
    let charged = core.charged_bytes();
    assert_eq!(
        core.decrypt_message(room, &rejected, &mut SensitiveBuffer::<8192>::new()),
        Err(Fault::Authentication.into())
    );
    assert_eq!(core.charged_bytes(), charged);
    assert!(
        core.message(room, &rejected)?
            .recipient_attribution()
            .is_none()
    );
    assert!(core.message(room, &rejected)?.is_private());
    Ok(())
}

#[test]
fn recovered_zone_resolves_only_after_the_real_matching_join_arrives() -> Result<(), Error> {
    let local = identity(51)?;
    let remote = identity(52)?;
    let recovered = crypto::EcdheSecret::from_bytes([53; 32]);
    let remote_key = crypto::EcdheSecret::from_bytes([54; 32]);
    let root = crypto::records::RecordSecret::from_bytes([55; 64]);
    let record =
        crypto::records::EncryptionRecord::seal(&root, &ROOM, &recovered, &mut Entropy(4))?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let (room, source) = open(&mut core, &local)?;
    let (remote_join, _, _) = join(
        &mut core,
        (room, source),
        &remote,
        &REMOTE,
        &[0; 64],
        [0; 64],
        &remote_key,
    )?;
    assert!(core.recover_encryption_record(source, local.public_key()?, &root, record.record())?);
    assert!(!core.recover_encryption_record(
        source,
        local.public_key()?,
        &root,
        record.record()
    )?);
    let encrypted = private(recovered.public_key(), b"historical recipient material")?;
    let message = receive(
        &mut core,
        (room, source),
        &remote,
        &REMOTE,
        &remote_join,
        remote_join,
        crypto::message::private_body(&encrypted),
    )?;
    core.decrypt_message(room, &message, &mut SensitiveBuffer::<8192>::new())?;
    drain(&mut core, room)?;
    assert!(core.recipient(room, &message)?.is_none());
    assert!(core.message(room, &message)?.is_private());
    assert_eq!(
        core.message(room, &message)?
            .recipient_attribution()
            .ok_or(Fault::NotReady)?
            .evidence(),
        RecipientEvidence::RecoveredZone
    );
    assert_eq!(core.members(room)?.count(), 1);
    let (_, _, recipient) = join(
        &mut core,
        (room, source),
        &local,
        &LOCAL,
        &message,
        remote_join,
        &recovered,
    )?;
    assert!(core.recipient(room, &message)? == Some(recipient));
    assert_eq!(
        core.decrypt_message(room, &message, &mut SensitiveBuffer::<8192>::new()),
        Err(Fault::NotReady.into())
    );
    Ok(())
}

// Perform actual signing/codec work for one taken draft. Only the pure local
// write/echo ports below are modeled; they cannot establish native MQ success.
fn submit<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    source: Source<'id>,
    key: &SecretKey,
    epoch: Hash,
) -> Result<Hash, Error> {
    let Work::Sign {
        binding,
        kind,
        body,
        public,
        sender,
        previous,
        timestamp,
    } = core.take_work(room)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(key.public_key()?, public);
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
    let Work::Wire {
        binding: written,
        frame,
        ..
    } = core.take_work(room)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    core.write_progress(written, frame.expose().len(), true)?;
    let hash = core
        .receive_owned(
            source,
            ReceiveMeta {
                epoch,
                flags: 0,
                requested: false,
                sender_hash: None,
                context: None,
            },
            OwnedBytes::copy_from(bytes.expose())?,
        )
        .map_err(|e| e.error)?;
    drain(core, room)?;
    Ok(hash)
}

#[test]
fn original_outgoing_target_and_own_transcript_recipient_stay_distinct() -> Result<(), Error> {
    let local = identity(61)?;
    let remote = identity(62)?;
    let local_key = crypto::EcdheSecret::from_bytes([63; 32]);
    let remote_key = crypto::EcdheSecret::from_bytes([64; 32]);
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let (room, source) = open(&mut core, &local)?;
    let (local_join, local_member, self_contact) = join(
        &mut core,
        (room, source),
        &local,
        &LOCAL,
        &[0; 64],
        [0; 64],
        &local_key,
    )?;
    let (epoch, recipient_member, recipient) = join(
        &mut core,
        (room, source),
        &remote,
        &REMOTE,
        &local_join,
        local_join,
        &remote_key,
    )?;
    core.retain_recipient_key(local_member, local_key)?;
    let body = Body::Text {
        text: Text::new(b"original private target")?,
    };
    core.prepare_private(
        source,
        local_member,
        recipient_member,
        body,
        &mut SensitiveBuffer::<8192>::new(),
        &mut SensitiveBuffer::<8192>::new(),
        &mut Entropy(8),
        100,
        10_000,
    )?;
    let original = submit(&mut core, room, source, &local, epoch)?;
    let remote_public = remote.public_key()?;
    assert_eq!(
        core.message(room, &original)?.private_recipient(),
        Some(&remote_public)
    );
    let mut transcript = SensitiveBuffer::<8192>::new();
    transcript.encode_transcript(
        &original,
        wire::PublicKey::new(&remote_public)?,
        body,
        PROFILE,
    )?;
    let transcript_body = Body::decode(
        wire::envelope::Kind::TRANSCRIPT,
        transcript.expose(),
        PROFILE,
    )?;
    core.prepare_private(
        source,
        local_member,
        local_member,
        transcript_body,
        &mut SensitiveBuffer::<8192>::new(),
        &mut SensitiveBuffer::<8192>::new(),
        &mut Entropy(9),
        100,
        10_000,
    )?;
    let own_copy = submit(&mut core, room, source, &local, epoch)?;
    core.decrypt_message(room, &own_copy, &mut SensitiveBuffer::<8192>::new())?;
    drain(&mut core, room)?;
    assert!(core.recipient(room, &original)? == Some(recipient));
    assert!(core.recipient(room, &own_copy)? == Some(self_contact));
    assert!(core.message(room, &original)?.sender() == Some(self_contact));
    assert!(core.message(room, &original)?.transcript() == Some(&own_copy));
    assert_eq!(
        core.message(room, &original)?.private_recipient(),
        Some(&remote_public)
    );
    Ok(())
}
