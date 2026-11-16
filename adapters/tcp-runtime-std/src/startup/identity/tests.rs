use super::*;
use gnunet_pils::{HelloLimits, MasterKey, Profile, Service, client};
use std::task::Context;
const HELLO: HelloLimits = HelloLimits {
    maximum_input_bytes: 512,
    maximum_address_bytes: 512,
    maximum_addresses: 8,
};
type Observer<'p> = client::Client<'p, 32, 512, 512>;
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Error::Conflict.into())
    }
}
fn receive_announcement<'p>(
    observer: &mut Observer<'p>,
    seed: u8,
) -> Result<client::Inbound<'p>, Failure> {
    let now = gnunet_service_runtime::clock::SystemClock.sample()?.now;
    let service = Service::<512>::new(
        MasterKey::from_seed([seed; 32]),
        Profile::Reference029,
        now.as_micros(),
        HELLO,
    )?;
    let mut frame = service.announcement().to_vec();
    let mut scratch = [0; 512];
    let epoch = observer.epoch().ok_or(Error::NotReady)?;
    Ok(observer.receive(epoch, &mut frame, &mut scratch, now)?)
}
fn announced<'p>(observer: &mut Observer<'p>, seed: u8) -> Result<Identity<'p>, Failure> {
    match receive_announcement(observer, seed)? {
        client::Inbound::Identity { identity, .. } => Ok(identity),
        _ => Err(Error::Malformed.into()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn repeated_verified_changes_keep_original_bound_and_actual_source() -> Result<(), Failure> {
    let source: Arc<dyn RuntimeClock> = Arc::new(gnunet_service_runtime::clock::SystemClock);
    let mut instance = client::Instance::new();
    let mut observer = Observer::new(&mut instance, Profile::Reference029, HELLO)?;
    observer.begin_connection(source.sample()?.now)?;
    let a = announced(&mut observer, 7)?;
    let mut continuity = Continuity::new(a);
    check(continuity.activate())?;
    let b = announced(&mut observer, 8)?;
    continuity.changing(b, source.clone())?;
    let original = continuity.bounds().ok_or(Error::NotReady)?;
    let returned = announced(&mut observer, 7)?;
    continuity.changing(returned, source.clone())?;
    check(continuity.bounds() == Some(original))?;
    let mut second_instance = client::Instance::new();
    let mut second = Observer::new(&mut second_instance, Profile::Reference029, HELLO)?;
    second.begin_connection(source.sample()?.now)?;
    let foreign = announced(&mut second, 7)?;
    check(foreign.epoch().value() == a.epoch().value())?;
    check(continuity.changing(foreign, source).is_err())?;
    check(continuity.bounds() == Some(original))?;
    check(!continuity.activate() && continuity.bounds().is_none())
}

#[tokio::test(flavor = "current_thread")]
async fn native_expiry_is_checked_without_a_timer_driver_turn() -> Result<(), Failure> {
    let source: Arc<dyn RuntimeClock> = Arc::new(gnunet_service_runtime::clock::SystemClock);
    let mut window = Window::new(source)?;
    // Keep the real original alarm unready while the native deadline is past.
    // A busy ready-IO loop must not be able to bypass the direct hard check.
    window.hard = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .ok_or(Error::Overflow)?;
    let mut cx = Context::from_waker(std::task::Waker::noop());
    check(window.guard(&mut cx).is_err())
}

/// Pure-client transition coverage; the foreground fixture covers native EOF.
#[tokio::test(flavor = "current_thread")]
async fn source_loss_keeps_first_failure_and_bound_and_refuses_foreign_successors()
-> Result<(), Failure> {
    let clock: Arc<dyn RuntimeClock> = Arc::new(gnunet_service_runtime::clock::SystemClock);
    let mut instance = client::Instance::new();
    let mut observer = Observer::new(&mut instance, Profile::Reference029, HELLO)?;
    let epoch = observer.begin_connection(clock.sample()?.now)?;
    let original = announced(&mut observer, 7)?;
    let mut continuity = Continuity::new(original);
    let report = observer.prepare_connection_lost(epoch)?;
    check(continuity.observe(
        Progress::Lost {
            epoch,
            cause: LossCause::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            report,
        },
        &mut |_| {},
        clock.clone(),
    )?)?;
    let bound = continuity.bounds().ok_or(Error::NotReady)?;
    check(continuity.paused() && continuity.verify(original, clock.as_ref()).is_err())?;
    let now = clock.sample()?.now;
    observer.register_retry(now)?;
    let epoch = observer.begin_connection(now)?;
    let report = observer.prepare_connection_lost(epoch)?;
    check(continuity.observe(
        Progress::Lost {
            epoch,
            cause: LossCause::Eof,
            report,
        },
        &mut |_| {},
        clock.clone(),
    )?)?;
    check(
        continuity.bounds() == Some(bound)
            && matches!(&continuity.first_loss,Some(ConnectionLoss::Io(error)) if error.kind()==std::io::ErrorKind::ConnectionReset),
    )?;
    let mut foreign = client::Instance::new();
    let mut foreign = Observer::new(&mut foreign, Profile::Reference029, HELLO)?;
    foreign.begin_connection(now)?;
    let _retired = foreign.prepare_connection_lost(foreign.epoch().ok_or(Error::NotReady)?)?;
    foreign.register_retry(now)?;
    foreign.begin_connection(now)?;
    let _retired = foreign.prepare_connection_lost(foreign.epoch().ok_or(Error::NotReady)?)?;
    foreign.register_retry(now)?;
    foreign.begin_connection(AbsoluteTime::from_micros(now.as_micros() + 2000))?;
    let foreign = announced(&mut foreign, 7)?;
    check(foreign.epoch().value() > epoch.value())?;
    check(continuity.verify(foreign, clock.as_ref()).is_err())?;
    // Advancing a pure client's retry input authorizes no native socket action.
    observer.register_retry(now)?;
    observer.begin_connection(AbsoluteTime::from_micros(now.as_micros() + 2000))?;
    let next = receive_announcement(&mut observer, 7)?;
    check(!continuity.observe(Progress::Inbound(next), &mut |_| {}, clock)?)?;
    check(
        !continuity.paused()
            && continuity.bounds() == Some(bound)
            && continuity.first_loss.is_some(),
    )?;
    continuity.activate();
    check(continuity.bounds().is_none() && continuity.first_loss.is_none())
}
