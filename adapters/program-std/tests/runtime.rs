//! Actual scoped polling, timer wake, capacity and cleanup witnesses.
#![cfg(feature = "runtime")]
use gnunet_config::{Configuration, Installation, Limits, ProjectData};
use gnunet_program_host::{
    getopt::Options,
    logging::Logger,
    program::{
        self, Defaults, Environment, Failure, Invocation, NlsDisabled, Preparation, Prepared,
        ResolverConnect,
    },
    shared_clock::SharedClock,
};
use gnunet_types::Error;
use std::{
    cell::{Cell, RefCell},
    ffi::OsString,
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
fn ready(clock: &SharedClock, interval: &[u8], delta: Option<&[u8]>) -> Result<Prepared, Failure> {
    let mut cfg = Configuration::with_installation(
        Arc::new(ProjectData::default()),
        Installation::empty(),
        Limits::default(),
    )?;
    cfg.set_value(b"testing", b"SPEEDUP_INTERVAL", Some(interval))?;
    if let Some(delta) = delta {
        cfg.set_value(b"testing", b"SPEEDUP_DELTA", Some(delta))?;
    }
    let mut logger = Logger::new(b"owned", 7, true)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    match program::prepare(
        cfg,
        Invocation {
            binary_name: b"owned",
            help: None,
            select_default_filename: false,
            defaults: Defaults::Explicit(None),
        },
        Options::new(),
        [OsString::from("owned")],
        &Environment {
            arguments: None,
            posixly_correct: false,
            logging: Default::default(),
        },
        &mut NlsDisabled,
        &mut logger,
        clock,
        &mut out,
        &mut err,
    )? {
        Preparation::Ready(v) => Ok(*v),
        Preparation::Stopped(_) => Err(Error::Conflict.into()),
    }
}
struct Resolver;
impl ResolverConnect for Resolver {
    fn connect(&mut self, _: Configuration) -> Result<(), Failure> {
        Ok(())
    }
}
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions validate the actual PROGRAM source lifecycle; all setup remains fallible"
)]
fn source_ready_tick_shutdown_disabled_missing_and_repeat_offsets() -> Result<(), Failure> {
    let rt = runtime()?;
    for (interval, delta, shutdown, expected) in [
        (
            b"100ms".as_slice(),
            Some(b"2s".as_slice()),
            false,
            2_000_000,
        ),
        (b"100ms", Some(b"2s"), true, 5_000_000),
        (b"0", Some(b"2s"), false, 5_000_000),
        (b"100ms", Some(b"0"), false, 5_000_000),
        (b"100ms", None, false, 5_000_000),
        (b"forever", Some(b"2s"), false, 2_000_000),
    ] {
        let clock = SharedClock::native(1)?;
        clock.set_offset(5_000_000)?;
        let prepared = ready(&clock, interval, delta)?;
        let clock_read = clock.clone();
        let mut resolver = Resolver;
        let ret = rt.block_on(prepared.run_scheduled(
            &mut resolver,
            clock.clone(),
            0,
            move |_, scope| {
                assert_eq!(clock_read.offset(), Ok(5_000_000));
                if shutdown {
                    assert_eq!(scope.shutdown(), Ok(()));
                }
            },
        ))?;
        assert_eq!(ret, 1);
        assert_eq!(clock.offset()?, expected);
        assert_eq!(clock.stop()?, None);
    }
    let clock = SharedClock::native(1)?;
    let mut resolver = Resolver;
    for expected in [2_000_000, 4_000_000] {
        clock.set_offset(5_000_000)?;
        rt.block_on(ready(&clock, b"100ms", Some(b"2s"))?.run_scheduled(
            &mut resolver,
            clock.clone(),
            0,
            |_, _| {},
        ))?;
        assert_eq!(clock.offset()?, expected);
    }
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Actual real timer witnesses that source SPEEDUP advances an existing logical deadline"
)]
fn speedup_revises_already_pending_logical_timer_instead_of_only_changing_log_text()
-> Result<(), Failure> {
    let rt = runtime()?;
    let clock = SharedClock::native(2)?;
    let prepared = ready(&clock, b"2ms", Some(b"1s"))?;
    let completed = Rc::new(Cell::new(false));
    let result = Rc::clone(&completed);
    let mut resolver = Resolver;
    rt.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(300),
            prepared.run_scheduled(&mut resolver, clock.clone(), 1, move |_, scope| {
                let delay = scope.delay(gnunet_types::RelativeTime::from_micros(3_000_000));
                assert!(delay.is_ok());
                if let Ok(delay) = delay {
                    assert!(
                        scope
                            .spawn(async move {
                                assert_eq!(delay.await, Ok(()));
                                result.set(true);
                            })
                            .is_ok()
                    );
                }
            }),
        )
        .await
        .map_err(|_| Error::WouldBlock)?
    })?;
    assert!(completed.get());
    assert!(clock.offset()? >= 3_000_000);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Capacity must remain reserved while the future is temporarily leased for callback polling"
)]
fn leased_callback_cannot_overadmit_and_cancelled_original_ticket_cannot_retire_replacement()
-> Result<(), Failure> {
    let rt = runtime()?;
    let clock = SharedClock::native(1)?;
    let mut resolver = Resolver;
    let observations = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&observations);
    rt.block_on(ready(&clock, b"0", Some(b"0"))?.run_scheduled(
        &mut resolver,
        clock.clone(),
        1,
        move |_, scope| {
            let retired = scope.spawn(std::future::pending());
            assert!(retired.is_ok());
            if let Ok(retired) = retired {
                assert_eq!(scope.cancel(retired), Ok(()));
                assert_eq!(scope.cancel(retired), Err(Error::StaleGeneration));
                let context = scope.clone();
                let current = scope.spawn(async move {
                    observed.borrow_mut().push(context.spawn(async {}).err());
                });
                assert!(current.is_ok());
                assert_eq!(scope.cancel(retired), Err(Error::StaleGeneration));
            }
        },
    ))?;
    assert_eq!(*observations.borrow(), [Some(Error::Capacity)]);
    Ok(())
}
struct Marker(Rc<Cell<usize>>);
impl Drop for Marker {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Dropping a polled run must break captured Scope cycles and retire its clock task"
)]
fn cancelling_run_releases_pending_futures_and_exact_speedup_ticket_without_callback()
-> Result<(), Failure> {
    let rt = runtime()?;
    let entered = rt.enter();
    let clock = SharedClock::native(1)?;
    let prepared = ready(&clock, b"1s", Some(b"1s"))?;
    let drops = Rc::new(Cell::new(0));
    let mark = Marker(Rc::clone(&drops));
    let mut resolver = Resolver;
    let mut run =
        Box::pin(
            prepared.run_scheduled(&mut resolver, clock.clone(), 1, move |_, scope| {
                let retained = scope.clone();
                assert!(
                    scope
                        .spawn(async move {
                            let _mark = mark;
                            let _retained = retained;
                            std::future::pending::<()>().await;
                        })
                        .is_ok()
                );
            }),
        );
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(matches!(Pin::as_mut(&mut run).poll(&mut cx), Poll::Pending));
    assert_eq!(drops.get(), 0);
    drop(run);
    assert_eq!(drops.get(), 1);
    assert_eq!(clock.stop()?, None);
    drop(entered);
    Ok(())
}
