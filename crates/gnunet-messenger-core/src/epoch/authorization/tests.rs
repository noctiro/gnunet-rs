//! Actual body cryptography over explicitly staged admitted-state metadata.
//! Signature admission is outside this focused state transition fixture.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Original key/state promotion and refusal outcomes are asserted"
)]
use super::*;
use crate::model::{node, structural_core};
use wire::{
    envelope::{Header, Kind, Signature},
    padding::{Decode, Encode},
};

const EPOCH: Hash = [1; 64];
const EVENT: Hash = [2; 64];
const WRAP: ShortHash = [3; 32];
const TARGET: ShortHash = [8; 32];

fn encoded(body: Body<'_>) -> Result<OwnedBytes, Error> {
    let mut storage = SensitiveBuffer::<512>::new();
    let mut sig = [0; 68];
    sig[..4].copy_from_slice(&65556u32.to_be_bytes());
    storage.encode_message(
        Header {
            signature: Signature::new(&sig)?,
            timestamp: gnunet_wire::official::AbsoluteTime::from_micros(10),
            sender_id: &[2; 32],
            previous: &[0; 64],
            kind: body.kind(),
        },
        body,
        wire::profile::Profile::LITTLE_255,
        Encode::Absent,
    )?;
    OwnedBytes::copy_from(storage.expose())
}

struct Scope<'id> {
    room: Slot,
    epoch: Slot,
    target: Slot,
    announcement: Slot,
    input: Slot,
    source: Source<'id>,
    sender: Slot,
}

fn setup<'id>(core: &mut Core<'id>) -> Result<Scope<'id>, Error> {
    let contact = core
        .contacts
        .insert(ContactRow {
            key: [3; 36],
            name: None,
            anonymous_context: None,
            local: false,
            canonical: true,
            rooms: 1,
        })
        .map_err(|(e, _)| e)?;
    let room = core.room([1; 64], None)?;
    let source = core.attach_source(room, SourceRole::Client, Decode::Absent, None)?;
    core.create_submitted(source)?;
    let r = room.slot;
    let mut epoch = EpochRow {
        hash: EPOCH,
        parents: [[0; 64]; 2],
        mutation: EpochMutation::Merge,
        members: crate::epoch::members::Snapshot::from_contacts([contact]),
        complete: true,
        groups: Slots::new(4)?,
        historical_groups: 0,
        nonces: Vec::with_capacity(4),
        revision: 1,
        ephemeral: None,
        best_announcement: None,
        best_group: None,
    };
    let group = |identifier, key: Option<crypto::AeadKey>| GroupRow {
        identifier,
        identifier_order: Endian::Little,
        target: 1,
        valid: true,
        phase: if key.is_some() {
            KeyPhase::Present
        } else {
            KeyPhase::Missing
        },
        key,
        key_custody: GroupKeyCustody::Retained,
        confirmations: Vec::with_capacity(2),
        expires: u64::MAX,
        appeal: None,
        appeal_until: 0,
        proposal: None,
        generation: 1,
        derived_from: None,
    };
    epoch
        .groups
        .insert(group(WRAP, Some(crypto::AeadKey::from_bytes([5; 32]))))
        .map_err(|(e, _)| e)?;
    let mut target = group(TARGET, None);
    target.confirmations.push(Confirmation {
        contact,
        message: EVENT,
        verified_mac: false,
    });
    let target = epoch.groups.insert(target).map_err(|(e, _)| e)?;
    let e = core
        .rooms
        .get_mut(r)?
        .epochs
        .insert(epoch)
        .map_err(|(e, _)| e)?;
    core.rooms.get_mut(r)?.current_epoch = EPOCH;
    let key = crypto::AeadKey::from_bytes([9; 32]);
    let draft = Body::Announcement {
        identifier: &TARGET,
        public_key: &[0; 32],
        nonce: &[7; 32],
        timeout: gnunet_wire::official::RelativeTime::from_micros(100),
        hmac: &[0; 64],
    };
    let hmac = crypto::group::message_mac(draft, &key)?;
    let announcement_body = Body::Announcement {
        identifier: &TARGET,
        public_key: &[0; 32],
        nonce: &[7; 32],
        timeout: gnunet_wire::official::RelativeTime::from_micros(100),
        hmac: &hmac,
    };
    let mut announcement = node(core.instance, 2, 0, 1, 1, 1)?;
    announcement.origin = NodeOrigin::from_source(source, SourceRole::Client);
    announcement.epoch = EPOCH;
    announcement.kind = Kind::ANNOUNCEMENT;
    announcement.frame = Some(encoded(announcement_body)?.into());
    announcement
        .auth
        .as_mut()
        .ok_or(Fault::Conflict)?
        .owner
        .as_mut()
        .ok_or(Fault::Conflict)?
        .contact = contact;
    let announcement = core.rooms.get_mut(r)?.insert_node(announcement)?;
    let mut input = node(core.instance, 3, 2, 1, 1, 2)?;
    input.origin = NodeOrigin::from_source(source, SourceRole::Client);
    input.epoch = EPOCH;
    input
        .auth
        .as_mut()
        .ok_or(Fault::Conflict)?
        .owner
        .as_mut()
        .ok_or(Fault::Conflict)?
        .contact = contact;
    let input = core.rooms.get_mut(r)?.insert_node(input)?;
    core.events.clear();
    Ok(Scope {
        room: r,
        epoch: e,
        target,
        announcement,
        input,
        source,
        sender: contact,
    })
}

fn apply<'id>(core: &mut Core<'id>, scope: &Scope<'id>, corrupt: bool) -> Result<(), Error> {
    apply_event(core, scope, EVENT, corrupt, 10)
}

fn apply_event<'id>(
    core: &mut Core<'id>,
    scope: &Scope<'id>,
    event: Hash,
    corrupt: bool,
    now: u64,
) -> Result<(), Error> {
    let wrapping = crypto::AeadKey::from_bytes([5; 32]);
    let shared = crypto::AeadKey::from_bytes([9; 32]);
    let authorization = crypto::group::Authorization::seal(&WRAP, &event, &wrapping, &shared)?;
    let mut body = [0; 192];
    authorization.body().encode(core.profile, &mut body)?;
    if corrupt {
        body[128] ^= 1;
    }
    let frame = encoded(Body::decode(Kind::AUTHORIZATION, &body, core.profile)?)?;
    let message = Message::decode(frame.expose(), core.profile, Decode::Absent)?;
    core.apply_authorization(
        scope.room,
        scope.epoch,
        scope.input,
        message,
        WRAP,
        event,
        scope.sender,
        now,
    )
}

mod group;

#[test]
fn failed_mac_and_stale_context_never_promote_original_target_state() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let scope = setup(&mut core)?;
    let revision = core
        .rooms
        .get(scope.room)?
        .epochs
        .get(scope.epoch)?
        .revision;
    assert!(matches!(
        apply(&mut core, &scope, true),
        Err(Error::Crypto(crypto::Error::Protocol(
            Fault::Authentication
        )))
    ));
    let epoch = core.rooms.get(scope.room)?.epochs.get(scope.epoch)?;
    assert_eq!(epoch.revision, revision);
    assert_eq!(epoch.groups.get(scope.target)?.phase, KeyPhase::Missing);
    assert!(epoch.groups.get(scope.target)?.key.is_none());
    assert!(core.events.is_empty());
    core.rooms
        .get_mut(scope.room)?
        .nodes
        .get_mut(scope.announcement)?
        .epoch = [4; 64];
    assert!(matches!(
        apply(&mut core, &scope, false),
        Err(Error::AttributionConflict)
    ));
    core.rooms
        .get_mut(scope.room)?
        .nodes
        .get_mut(scope.announcement)?
        .epoch = EPOCH;
    core.rooms
        .get_mut(scope.room)?
        .sources
        .get_mut(scope.source.slot)?
        .attached = false;
    assert!(matches!(
        apply(&mut core, &scope, false),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert!(
        core.rooms
            .get(scope.room)?
            .epochs
            .get(scope.epoch)?
            .groups
            .get(scope.target)?
            .key
            .is_none()
    );
    assert!(core.events.is_empty());
    Ok(())
}

#[test]
fn valid_key_promotes_once_and_conflicting_existing_key_remains_original() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let scope = setup(&mut core)?;
    apply(&mut core, &scope, false)?;
    let epoch = core.rooms.get(scope.room)?.epochs.get(scope.epoch)?;
    let revision = epoch.revision;
    assert_eq!(epoch.groups.get(scope.target)?.phase, KeyPhase::Present);
    assert!(
        epoch
            .groups
            .get(scope.target)?
            .key
            .as_ref()
            .ok_or(Fault::Conflict)?
            .constant_time_eq(&crypto::AeadKey::from_bytes([9; 32]))
    );
    core.events.clear();
    apply(&mut core, &scope, false)?;
    assert_eq!(
        core.rooms
            .get(scope.room)?
            .epochs
            .get(scope.epoch)?
            .revision,
        revision
    );
    assert!(core.events.is_empty());
    core.rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?
        .key = Some(crypto::AeadKey::from_bytes([11; 32]));
    assert!(matches!(
        apply(&mut core, &scope, false),
        Err(Error::Protocol(Fault::Conflict))
    ));
    let key = core
        .rooms
        .get(scope.room)?
        .epochs
        .get(scope.epoch)?
        .groups
        .get(scope.target)?
        .key
        .as_ref()
        .ok_or(Fault::Conflict)?;
    assert!(key.constant_time_eq(&crypto::AeadKey::from_bytes([11; 32])));
    assert!(core.events.is_empty());
    Ok(())
}
