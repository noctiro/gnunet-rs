//! Real pure PILS observation branding and clock-independent native deadline.
use super::*;
use gnunet_pils::{
    HelloLimits, MasterKey, Profile, Service,
    client::{Client as Pure, Instance},
};
use gnunet_service_runtime::clock::SystemClock;
use std::{fs, future::poll_fn, os::unix::fs::DirBuilderExt, path::PathBuf};
type Test = Result<(), Cause>;
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn original_observer_brand_and_expiry_are_required_even_with_equal_numeric_epoch() -> Test {
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce)?;
    let scratch = Scratch(
        std::env::temp_dir().join(format!("udp-identity-{:016x}", u64::from_be_bytes(nonce))),
    );
    fs::DirBuilder::new().mode(0o700).create(&scratch.0)?;
    let limits = HelloLimits {
        maximum_input_bytes: 4096,
        maximum_address_bytes: 1024,
        maximum_addresses: 16,
    };
    let service = Service::<2048>::new(
        MasterKey::from_seed([17; 32]),
        Profile::ReferenceDeterministic,
        100,
        limits,
    )?;
    let mut first = Instance::new();
    let mut other = Instance::new();
    let mut first =
        Pure::<4, 1024, 2048>::new(&mut first, Profile::ReferenceDeterministic, limits)?;
    let mut other =
        Pure::<4, 1024, 2048>::new(&mut other, Profile::ReferenceDeterministic, limits)?;
    for client in [&mut first, &mut other] {
        let epoch = client.begin_connection(AbsoluteTime::UNIX_EPOCH)?;
        client.receive(
            epoch,
            &mut service.announcement().to_vec(),
            &mut [0; 1024],
            AbsoluteTime::from_micros(100),
        )?;
        client.enable_local_key(MasterKey::from_seed([17; 32]))?;
    }
    let binding = IdentityEpoch::from_client(&first, AbsoluteTime::from_micros(100))?;
    let epoch = binding.observation().epoch();
    let namespace = Namespace::open(&scratch.0)?;
    let journal = namespace.journal(binding.peer(), 2)?;
    let state = State {
        namespace,
        phase: Phase::Active(Generation { binding, journal }),
        epoch,
        peers: 2,
        clock: Arc::new(SystemClock),
        window: None,
    };
    let current = first.identity().ok_or(Error::NotReady)?;
    let foreign = other.identity().ok_or(Error::NotReady)?;
    if current.epoch().value() != foreign.epoch().value() || current.epoch() == foreign.epoch() {
        return Err("actual source witness differs".into());
    }
    state.verify(current, AbsoluteTime::from_micros(100))?;
    if state.verify(foreign, AbsoluteTime::from_micros(100)) != Err(Error::StaleGeneration)
        || state.verify(current, current.expiration()) != Err(Error::Timeout)
    {
        return Err("identity authority guard failed".into());
    }
    Ok(())
}
#[test]
fn elapsed_native_bound_refuses_recovery_while_original_alarm_is_still_future() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut window = Window::new(Arc::new(SystemClock))?;
            let alarm = window.native.deadline();
            window.hard = Instant::now()
                .checked_sub(Duration::from_micros(1))
                .ok_or(Error::Overflow)?;
            if alarm <= Instant::now() {
                return Err("original alarm was not future".into());
            }
            if poll_fn(|cx| Poll::Ready(window.guard(cx))).await.is_ok() {
                return Err("elapsed native guard admitted recovery".into());
            }
            Ok(())
        })
}
