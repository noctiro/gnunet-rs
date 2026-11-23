//! Client IPC shares the frame custody boundary with hosted ingress.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Check authority and exact retention of real signed MESSENGER frames"
)]

use super::*;
use crypto::signature::{SigningHeader, encode_signed_peer, message_hash};
use gnunet_crypto::eddsa::EddsaPrivateKey;
use gnunet_types::AbsoluteTime;
use wire::{Response, SensitiveBytes, profile::Profile};

mod detached;
mod reclamation;
mod recovered_miss;
mod route_loss;

const PROFILE: Profile = Profile::LITTLE_255;
const FRAME_BYTES: usize = 512;
const ZERO: Hash = [0; 64];

struct SignedPeer {
    frame: [u8; FRAME_BYTES],
    len: usize,
    hash: Hash,
    sender: Hash,
}

impl SignedPeer {
    fn new(seed: u8, timestamp: u64) -> Result<Self, Error> {
        Self::with_parent(seed, timestamp, &ZERO)
    }

    fn with_parent(seed: u8, timestamp: u64, previous: &Hash) -> Result<Self, Error> {
        let key = EddsaPrivateKey::from_seed([seed; 32]);
        let peer = *key.public_key().as_bytes();
        let mut frame = [0; FRAME_BYTES];
        let len = encode_signed_peer(
            &key,
            SigningHeader {
                timestamp: AbsoluteTime::from_micros(timestamp),
                sender_id: &peer,
                previous,
            },
            Kind::PEER,
            SensitiveBytes::new(&peer),
            PROFILE,
            padding::Encode::Absent,
            &mut frame,
        )?;
        let hash = message_hash(Message::decode(
            &frame[..len],
            PROFILE,
            padding::Decode::Absent,
        )?);
        Ok(Self {
            frame,
            len,
            hash,
            sender: hash512(&peer),
        })
    }

    fn bytes(&self) -> &[u8] {
        &self.frame[..self.len]
    }

    fn receive<'a>(&'a self, key: &'a Hash, claimed: &'a Hash) -> Response<'a> {
        Response::Receive {
            key,
            sender: &self.sender,
            context: &self.sender,
            hash: claimed,
            epoch: &ZERO,
            flags: 4,
            message: SensitiveBytes::new(self.bytes()),
        }
    }
}

#[test]
fn client_receive_reuses_fixed_history_without_retaining_refused_originals() -> Result<(), Error> {
    let mut pool_instance = OriginalPoolInstance::new();
    let mut pool_slots = [OriginalSlot::EMPTY];
    let mut storage = [0; FRAME_BYTES];
    let mut workspace = [0; FRAME_BYTES];
    let mut instance = Instance::new();
    let limits = Limits {
        rooms: 2,
        sources_per_room: 1,
        messages_per_room: 2,
        frame_bytes: FRAME_BYTES,
        name_bytes: FRAME_BYTES,
        ..Limits::default()
    };
    let mut core = Core::new(&mut instance, Mode::Client, limits, PROFILE)?;
    let pool = OriginalPool::new(&mut pool_instance, &mut pool_slots, &mut storage);
    core.frames = FrameStore::fixed(pool, &mut workspace);
    let keys = [[1; 64], [2; 64]];
    let room = core.room(keys[0], None)?;
    let other = core.room(keys[1], None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    let other_source =
        core.attach_source(other, SourceRole::Client, padding::Decode::Absent, None)?;
    core.create_submitted(source)?;
    core.create_submitted(other_source)?;
    let first = SignedPeer::new(7, 10)?;
    let second = SignedPeer::new(8, 11)?;
    let baseline = core.charged_bytes();

    assert_eq!(
        core.on_notification(source, first.receive(&keys[0], &ZERO), 10),
        Err(Fault::Authentication.into())
    );
    assert_eq!(core.charged_bytes(), baseline);
    let received = first.receive(&keys[0], &first.hash);
    core.on_notification(source, received, 10)?;
    assert!(core.message(room, &first.hash)?.original() == Some(first.bytes()));
    core.on_notification(source, received, 10)?;
    assert_eq!(core.charged_bytes(), baseline + first.len);

    let received = second.receive(&keys[1], &second.hash);
    assert_eq!(
        core.on_notification_profiled(other_source, received, ClientLayout::same(PROFILE), 11),
        Err(Fault::Capacity.into())
    );
    assert_eq!(core.charged_bytes(), baseline + first.len);
    assert!(matches!(
        core.message(other, &second.hash),
        Err(Error::Protocol(Fault::NotFound))
    ));

    core.source_stopped(source)?;
    core.forget_room(room)?;
    core.on_notification_profiled(other_source, received, ClientLayout::same(PROFILE), 11)?;
    assert!(core.message(other, &second.hash)?.original() == Some(second.bytes()));
    Ok(())
}

#[test]
fn hosted_app_sources_do_not_apply_client_notifications() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Service, Limits::default(), PROFILE)?;
    let key = [1; 64];
    let room = core.room(key, None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    let member = [2; 32];
    let response = Response::MemberId {
        key: &key,
        id: &member,
        reset: 0,
    };
    assert_eq!(
        core.on_notification(source, response, 10),
        Err(Error::Permission)
    );
    assert_eq!(
        core.on_notification_profiled(source, response, ClientLayout::same(PROFILE), 10),
        Err(Error::Permission)
    );
    assert_eq!(core.service_client(source), Err(Fault::NotReady.into()));
    Ok(())
}
