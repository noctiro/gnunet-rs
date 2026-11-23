//! Peer INFO admission with real signatures and independent channel sources.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check public service admission outcomes"
)]

use gnunet_identity::SecretKey;
use gnunet_messenger_core::{
    Core, Error, Instance, Limits, Mode, OwnedBytes, ReceiveMeta, SensitiveBuffer, SourceRole,
    carrier,
    crypto::signature::SigningHeader,
    wire::{KeyType, body::Body, padding, profile::Profile},
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use zeroize::Zeroizing;

const PROFILE: Profile = Profile::LITTLE_255;
const META: ReceiveMeta = ReceiveMeta {
    epoch: [0; 64],
    flags: 4,
    requested: false,
    sender_hash: None,
    context: None,
};

fn key(seed: u8) -> Result<SecretKey, Error> {
    let mut bytes = Zeroizing::new([seed; 36]);
    bytes[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    Ok(SecretKey::from_serialized(&bytes[..])?)
}

fn peer_key(key: &SecretKey) -> Result<[u8; 32], Error> {
    Ok(key.public_key()?[4..]
        .try_into()
        .map_err(|_| Fault::Malformed)?)
}

fn info(key: &SecretKey, peer: &[u8; 32], timestamp: u64) -> Result<OwnedBytes, Error> {
    let mut buffer = SensitiveBuffer::<256>::new();
    buffer.encode_signed(
        key,
        SigningHeader {
            timestamp: AbsoluteTime::from_micros(timestamp),
            sender_id: peer,
            previous: &[0; 64],
        },
        Body::Info {
            version: carrier::VERSION,
        },
        PROFILE,
        padding::Encode::Absent,
    )?;
    OwnedBytes::copy_from(buffer.expose())
}

#[test]
fn info_admission_requires_the_channel_peer() -> Result<(), Error> {
    let limits = Limits {
        rooms: 1,
        contacts: 2,
        sources_per_room: 2,
        messages_per_room: 4,
        sessions_per_room: 2,
        epochs_per_room: 2,
        groups_per_epoch: 2,
        operations_per_room: 2,
        subscriptions_per_room: 2,
        missing_per_room: 2,
        nonce_per_epoch: 2,
        ..Limits::default()
    };
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
    let room = core.room([8; 64], None)?;
    let signer = key(7)?;
    let peer = peer_key(&signer)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let hash = core
        .receive_owned(source, META, info(&signer, &peer, 10)?)
        .map_err(|rejected| rejected.error)?;
    core.advance(room, 10)?;
    let attribution = core.service_attribution(room, &hash)?;
    assert_eq!(attribution.source, Some(source));
    assert_eq!(attribution.sender, gnunet_crypto::hash512(&peer));

    let another = core.attach_source(
        room,
        SourceRole::Peer(peer_key(&key(9)?)?),
        padding::Decode::Absent,
        None,
    )?;
    let wrong_peer = core.receive_owned(another, META, info(&signer, &peer, 11)?);
    assert!(
        matches!(wrong_peer, Err(rejection) if rejection.error == Error::Crypto(
            gnunet_messenger_core::crypto::Error::Protocol(Fault::Authentication)
        ))
    );
    Ok(())
}
