use super::*;
use gnunet_conversation::wire::Message;
use gnunet_pils::{HelloLimits, MasterKey, Profile, Service, client};
use gnunet_wire::official::AbsoluteTime;

type Observer<'p> = client::Client<'p, 1, 512, 512>;
const HELLO: HelloLimits = HelloLimits {
    maximum_input_bytes: 512,
    maximum_address_bytes: 512,
    maximum_addresses: 8,
};

fn check(value: bool) -> Result<(), Fault> {
    if value { Ok(()) } else { Err(Fault::Conflict) }
}

/// Obtain the typed observation through real PILS signing, decoding and
/// verification. No test constructor fabricates an epoch or verified identity.
fn announce<'p>(
    observer: &mut Observer<'p>,
    seed: u8,
    now: u64,
) -> Result<PilsIdentity<'p>, Fault> {
    let limits = HELLO;
    let service = Service::<512>::new(
        MasterKey::from_seed([seed; 32]),
        Profile::Reference029,
        now,
        limits,
    )?;
    let mut bytes = service.announcement().to_vec();
    let mut scratch = [0; 512];
    let epoch = observer.epoch().ok_or(Fault::NotReady)?;
    match observer.receive(
        epoch,
        &mut bytes,
        &mut scratch,
        AbsoluteTime::from_micros(now),
    )? {
        client::Inbound::Identity { identity, .. } => Ok(identity),
        _ => Err(Fault::Malformed),
    }
}

#[test]
fn same_source_refresh_keeps_original_core_and_pending_registration() -> Result<(), Fault> {
    let mut pils_instance = client::Instance::new();
    let mut observer = Observer::new(&mut pils_instance, Profile::Reference029, HELLO)?;
    observer.begin_connection(AbsoluteTime::from_micros(10))?;
    let first = announce(&mut observer, 7, 10)?;
    let mut instance = Instance::new();
    let mut owner = LineSession::new(&mut instance);
    check(owner.core().is_none() && owner.observed().is_none())?;
    check(owner.observe(first, Limits::default(), 10)? == Observation::Initial)?;
    let core = owner.core_mut().ok_or(Fault::NotReady)?;
    let original = core.identity();
    let port = [9; 64];
    core.client_request(
        &original,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        10,
    )?;
    let effect = core.effect().ok_or(Fault::NotReady)?.id();
    core.admit_effect(effect)?;
    let refreshed = announce(&mut observer, 7, 11)?;
    check(first.expiration() != refreshed.expiration())?;
    check(owner.observe(refreshed, Limits::default(), 11)? == Observation::Refresh)?;
    let core = owner.core().ok_or(Fault::NotReady)?;
    check(owner.observed() == Some(refreshed) && core.identity() == original)?;
    let pending = core.effect().ok_or(Fault::NotReady)?;
    check(pending.id() == effect && pending.admitted())
}

#[test]
fn healthy_changes_keep_core_but_equal_serials_do_not_replace_source() -> Result<(), Fault> {
    let mut first_instance = client::Instance::new();
    let mut first_observer = Observer::new(&mut first_instance, Profile::Reference029, HELLO)?;
    first_observer.begin_connection(AbsoluteTime::from_micros(10))?;
    let original = announce(&mut first_observer, 7, 10)?;
    let mut instance = Instance::new();
    let mut owner = LineSession::new(&mut instance);
    owner.observe(original, Limits::default(), 10)?;
    let changed = announce(&mut first_observer, 8, 11)?;
    check(owner.observe(changed, Limits::default(), 11)? == Observation::PeerChanged)?;
    check(owner.observed() == Some(changed))?;
    check(owner.core().ok_or(Fault::NotReady)?.identity().peer() == changed.peer().as_bytes())?;
    // A retained old token cannot roll the same observer back to an earlier
    // announcement. A real later return to A is a different observation.
    check(matches!(
        owner.observe(original, Limits::default(), 12),
        Err(Fault::StaleGeneration)
    ))?;
    check(owner.observed() == Some(changed))?;
    let returned = announce(&mut first_observer, 7, 12)?;
    check(owner.observe(returned, Limits::default(), 12)? == Observation::PeerChanged)?;

    let mut second_instance = client::Instance::new();
    let mut second_observer = Observer::new(&mut second_instance, Profile::Reference029, HELLO)?;
    second_observer.begin_connection(AbsoluteTime::from_micros(10))?;
    let same_peer = announce(&mut second_observer, 7, 10)?;
    check(
        same_peer.peer() == original.peer()
            && same_peer.epoch().value() == original.epoch().value(),
    )?;
    check(matches!(
        owner.observe(same_peer, Limits::default(), 13),
        Err(Fault::StaleGeneration)
    ))?;
    check(owner.observed() == Some(returned))?;
    check(
        owner.core().ok_or(Fault::NotReady)?.identity()
            == Identity::new(*original.peer().as_bytes(), original.epoch().value())?,
    )
}

#[test]
fn failed_initialization_cannot_publish_identity_or_reuse_brand() -> Result<(), Fault> {
    let mut pils_instance = client::Instance::new();
    let mut observer = Observer::new(&mut pils_instance, Profile::Reference029, HELLO)?;
    observer.begin_connection(AbsoluteTime::from_micros(10))?;
    let observed = announce(&mut observer, 7, 10)?;
    let mut instance = Instance::new();
    let mut owner = LineSession::new(&mut instance);
    let invalid = Limits {
        calls: 0,
        ..Limits::default()
    };
    check(matches!(
        owner.observe(observed, invalid, 10),
        Err(Fault::InvalidInput)
    ))?;
    check(owner.core().is_none() && owner.observed().is_none())?;
    check(matches!(
        owner.observe(observed, Limits::default(), 11),
        Err(Fault::Conflict)
    ))
}
