use super::*;
use gnunet_pils::{HelloLimits, MasterKey, Profile, Service, client};
use std::task::Context;
const HELLO: HelloLimits = HelloLimits {
    maximum_input_bytes: 512,
    maximum_address_bytes: 512,
    maximum_addresses: 8,
};
type Observer<'p> = client::Client<'p, 1, 512, 512>;
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Error::Conflict.into())
    }
}
fn announced<'p>(observer: &mut Observer<'p>, seed: u8) -> Result<Identity<'p>, Failure> {
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
    match observer.receive(epoch, &mut frame, &mut scratch, now)? {
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
