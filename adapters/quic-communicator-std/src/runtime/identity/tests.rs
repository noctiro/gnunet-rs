//! Real signed pure PILS observations; no native daemon or TLS-peer claim.
use super::*;
use gnunet_pils::{HelloLimits, MasterKey, Profile, Service, client};
type Test = Result<(), Box<dyn std::error::Error>>;
const LIMITS: HelloLimits = HelloLimits {
    maximum_input_bytes: 512,
    maximum_address_bytes: 512,
    maximum_addresses: 8,
};
type Client<'p> = client::Client<'p, 1, 512, 512>;
fn check(value: bool) -> Test {
    if value {
        Ok(())
    } else {
        Err("QUIC identity ownership regression".into())
    }
}
fn announce<'p>(
    source: &mut Client<'p>,
    seed: u8,
) -> Result<Identity<'p>, Box<dyn std::error::Error>> {
    let service = Service::<512>::new(
        MasterKey::from_seed([seed; 32]),
        Profile::Reference029,
        100,
        LIMITS,
    )?;
    source.receive(
        source.epoch().ok_or(Protocol::NotReady)?,
        &mut service.announcement().to_vec(),
        &mut [0; 512],
        gnunet_types::AbsoluteTime::from_micros(100),
    )?;
    Ok(source.identity().ok_or(Protocol::NotReady)?)
}
#[test]
fn coalescing_and_changes_during_restoration_keep_original_bounds_and_real_observer() -> Test {
    let mut instance = client::Instance::new();
    let mut source = Client::new(&mut instance, Profile::Reference029, LIMITS)?;
    source.begin_connection(gnunet_types::AbsoluteTime::UNIX_EPOCH)?;
    let a = announce(&mut source, 7)?;
    let hard = Instant::now() + Duration::from_secs(60);
    let mut owner = Owner::new();
    owner.observe(a, 100, hard, 60_000_100)?;
    check(owner.selected() == Some(*a.peer().as_bytes()))?;
    let b = announce(&mut source, 8)?;
    check(matches!(
        owner.observe(b, 101, hard, 60_000_100)?,
        Change::Begin { .. }
    ))?;
    let bound = owner.bound();
    check(owner.selected().is_none())?;
    let returned = announce(&mut source, 7)?;
    owner.observe(returned, 102, hard, 60_000_100)?;
    check(owner.bound() == bound && owner.retiring())?;
    let (original, target) = owner.admit()?;
    check(original == Some(target) && target == *a.peer().as_bytes())?;
    let b = announce(&mut source, 8)?;
    owner.observe(b, 103, hard, 60_000_100)?;
    check(owner.bound() == bound && owner.retiring())?;
    let mut foreign_instance = client::Instance::new();
    let mut foreign = Client::new(&mut foreign_instance, Profile::Reference029, LIMITS)?;
    foreign.begin_connection(gnunet_types::AbsoluteTime::UNIX_EPOCH)?;
    let other = announce(&mut foreign, 8)?;
    check(other.epoch().value() == a.epoch().value())?;
    check(matches!(
        owner.observe(other, 104, hard, 60_000_100),
        Err(Fault::Protocol(Protocol::StaleGeneration))
    ))?;
    check(owner.bound() == bound)?;
    owner.admit()?;
    check(owner.restored()? && owner.bound().is_none())
}
#[test]
fn exact_expiry_and_native_deadline_cannot_be_refreshed_into_new_authority() -> Test {
    let mut instance = client::Instance::new();
    let mut source = Client::new(&mut instance, Profile::Reference029, LIMITS)?;
    source.begin_connection(gnunet_types::AbsoluteTime::UNIX_EPOCH)?;
    let a = announce(&mut source, 7)?;
    let b = announce(&mut source, 8)?;
    let hard = Instant::now() + Duration::from_secs(60);
    let mut owner = Owner::new();
    owner.observe(a, 100, hard, 60_000_100)?;
    check(matches!(
        owner.observe(b, b.expiration().as_micros(), hard, 60_000_100),
        Err(Fault::IdentityLost)
    ))?;
    owner.observe(b, 101, hard, 60_000_100)?;
    if let Phase::Retiring { window, .. } = &mut owner.phase {
        window.hard = Instant::now() - Duration::from_micros(1);
    }
    check(matches!(
        owner.guard_native(),
        Err(Fault::Protocol(Protocol::Deadline))
    ))?;
    check(owner.admit().is_err())
}

#[test]
fn source_replacement_needs_a_same_client_successor_and_keeps_first_failure_and_bound() -> Test {
    let mut instance = client::Instance::new();
    let mut source = Client::new(&mut instance, Profile::Reference029, LIMITS)?;
    let now = gnunet_types::AbsoluteTime::UNIX_EPOCH;
    let epoch = source.begin_connection(now)?;
    let original = announce(&mut source, 7)?;
    let hard = Instant::now() + Duration::from_secs(60);
    let mut owner = Owner::new();
    owner.observe(original, 100, hard, 60_000_100)?;
    let _retired = source.prepare_connection_lost(epoch)?;
    check(matches!(
        owner.lose(
            epoch,
            ConnectionLoss::Io(std::io::ErrorKind::ConnectionReset.into()),
            101,
            hard,
            60_000_100
        )?,
        Change::Begin { next: None, .. }
    ))?;
    let bound = owner.bound();
    check(
        owner.source_lost()
            && owner.selected().is_none()
            && !owner.can_admit()
            && owner.admit().is_err(),
    )?;
    check(owner.observe(original, 102, hard, 60_000_100).is_err())?;
    source.register_retry(now)?;
    let unsigned = source.begin_connection(now)?;
    owner.connected(unsigned)?;
    let _retired = source.prepare_connection_lost(unsigned)?;
    check(matches!(
        owner.lose(unsigned, ConnectionLoss::Eof, 103, hard, 60_000_100)?,
        Change::Refresh
    ))?;
    check(
        owner.bound() == bound
            && matches!(&owner.source_loss,Some(loss) if loss.first_epoch==epoch && matches!(&loss.first,ConnectionLoss::Io(error) if error.kind()==std::io::ErrorKind::ConnectionReset)),
    )?;
    let mut other = client::Instance::new();
    let mut other = Client::new(&mut other, Profile::Reference029, LIMITS)?;
    other.begin_connection(now)?;
    for time in [0, 2000] {
        let _retired = other.prepare_connection_lost(other.epoch().ok_or(Protocol::NotReady)?)?;
        other.register_retry(now)?;
        other.begin_connection(gnunet_types::AbsoluteTime::from_micros(time))?;
    }
    let foreign = announce(&mut other, 7)?;
    check(
        foreign.epoch().value() > unsigned.value()
            && owner.observe(foreign, 104, hard, 60_000_100).is_err(),
    )?;
    source.register_retry(now)?;
    source.begin_connection(gnunet_types::AbsoluteTime::from_micros(2000))?;
    let next = announce(&mut source, 7)?;
    check(matches!(
        owner.observe(next, 105, hard, 60_000_100)?,
        Change::Refresh
    ))?;
    check(owner.can_admit() && owner.selected().is_none() && owner.bound() == bound)?;
    owner.admit()?;
    check(owner.selected() == Some(*next.peer().as_bytes()) && owner.bound() == bound)?;
    check(owner.restored()? && owner.bound().is_none() && owner.source_loss.is_none())
}
