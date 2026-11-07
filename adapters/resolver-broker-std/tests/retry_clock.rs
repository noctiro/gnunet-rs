//! Actual pre-connect failures preserve original MQ authority in one clock domain.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite owned native-socket tests assert source registration and callback ownership"
)]
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
use gnunet_client::{statistics::Selector, statistics_handle::GetFlow};
use gnunet_config::Configuration;
use gnunet_ipc_unix::handle::{Event, Progress, StatisticsHandle};
use gnunet_resolver_broker::{
    DriverEvent, Family, FamilyProfile, Limits, LiveConfiguration, broker,
};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock, SystemClock};
use gnunet_types::{AbsoluteTime, Duration as CoreDuration, Error};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::UnixListener,
    time::{Instant, timeout},
};
type Test = Result<(), Box<dyn StdError>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gnunet-retry-clock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
fn profile() -> Result<FamilyProfile, Box<dyn StdError>> {
    let p = gnunet_resolver_broker::native_profile()?;
    Ok(FamilyProfile::new(
        p.encode(gnunet_resolver_broker::Family::V4),
        p.encode(gnunet_resolver_broker::Family::V6),
    )?)
}
fn config(section: &[u8], path: &std::path::Path) -> Result<Configuration, Box<dyn StdError>> {
    let mut c = Configuration::default();
    c.set_value(
        section,
        b"UNIXPATH",
        Some(path.as_os_str().as_encoded_bytes()),
    )?;
    Ok(c)
}
type Stats<'owner> = StatisticsHandle<'owner, 4, 64, 2, 64, 8>;
async fn alongside<'owner, F: Future>(
    host: &mut Stats<'owner>,
    future: F,
) -> Result<F::Output, Box<dyn StdError>> {
    let mut future = std::pin::pin!(future);
    Ok(timeout(
        Duration::from_secs(3),
        poll_fn(|cx| {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                return Poll::Ready(Ok(result));
            }
            let mut drive = std::pin::pin!(host.drive(None, |_, _| GetFlow::Continue));
            match drive.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(Progress::Activity)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                _ => Poll::Pending,
            }
        }),
    )
    .await??)
}
async fn statistics(rollback: bool) -> Test {
    let dir = Dir::new()?;
    let path = dir.0.join("statistics");
    let clock = Arc::new(clock_source::Adjustable::advancing(1_000_000, 4)?);
    let (context, _driver) = broker::<4, 64>(
        LiveConfiguration::new(config(b"resolver", &dir.0.join("unused-resolver"))?),
        Limits::default(),
        profile()?,
        clock.clone(),
    )?;
    let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
    let mut host = Stats::from_config(
        &mut statistics_instance_1,
        &config(b"statistics", &path)?,
        context.resolution_context(),
        b"fixture",
        Default::default(),
    )?
    .ok_or("disabled")?;
    let selector = Selector {
        subsystem: b"fixture",
        name: b"value",
    };
    let get = host.get(selector)?;
    let epoch = host.connection_epoch().ok_or("missing MQ")?;
    let until = Instant::now() + Duration::from_secs(3);
    let mut failures = 0;
    while failures < 8 {
        host.drive(Some(until), |event, _| {
            if let Event::ConnectRetry {
                epoch: original, ..
            } = event
            {
                assert_eq!(original, epoch);
            }
            GetFlow::Continue
        })
        .await?;
        if let Some(e) = host.take_io_error() {
            assert_eq!(e.kind(), io::ErrorKind::NotFound);
            failures += 1;
        }
        assert!(Instant::now() < until);
    }
    let listener = UnixListener::bind(&path)?;
    if rollback {
        clock.set_offset(-1_000_000)?;
        assert!(
            alongside(
                &mut host,
                timeout(Duration::from_millis(350), listener.accept())
            )
            .await?
            .is_err(),
            "elapsed native256ms cannot override original logical retry after rollback"
        );
    }
    clock.set_offset(1_000_000)?;
    let accepted = alongside(
        &mut host,
        timeout(Duration::from_millis(100), listener.accept()),
    )
    .await?;
    assert!(
        accepted.is_ok(),
        "logical revision past original retry must not wait old native256ms target"
    );
    let (mut socket, _) = accepted??;
    let mut expected = [0; 128];
    let n = selector.encode_get(&mut expected)?;
    let mut actual = vec![0; n];
    alongside(&mut host, socket.read_exact(&mut actual)).await??;
    assert_eq!(actual, &expected[..n]);
    assert_eq!(host.connection_epoch(), Some(epoch));
    assert!(host.get_callbacks_enabled(get));
    assert!(
        alongside(
            &mut host,
            timeout(Duration::from_millis(20), socket.read(&mut [0]))
        )
        .await?
        .is_err(),
        "no replay after clock revision"
    );
    host.destroy(false)?;
    drop(host);
    assert_eq!(socket.read(&mut [0]).await?, 0);
    Ok(())
}
#[test]
fn statistics_native_retry_forward_revision_preserves_get_epoch_and_original_bytes() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(statistics(false))
}
#[test]
fn statistics_native_retry_rollback_keeps_original_logical_target_and_can_resume() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(statistics(true))
}
#[test]
fn broker_native_retry_deadline_samples_source_after_the_actual_socket_failure() -> Test {
    struct Source {
        now: AtomicU64,
        advance_after_read: AtomicBool,
    }
    impl RuntimeClock for Source {
        fn sample(&self) -> Result<ClockSample, Error> {
            let now = self.now.load(Ordering::SeqCst);
            if self.advance_after_read.swap(false, Ordering::SeqCst) {
                self.now.store(now + 1_000_000, Ordering::SeqCst);
            }
            Ok(ClockSample {
                now: AbsoluteTime::from_micros(now),
                revision: 0,
            })
        }
        // Explicit native-wall profile: time may progress between reads without a
        // PROGRAM revision notification. This never changes the actual OS clock.
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            RuntimeClock::subscribe(&SystemClock)
        }
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
  let dir=Dir::new()?;let source=Arc::new(Source{now:AtomicU64::new(1_000_000),advance_after_read:AtomicBool::new(false)});
  let (context,mut driver)=broker::<4,64>(LiveConfiguration::new(config(b"resolver",&dir.0.join("missing"))?),Limits::default(),profile()?,source.clone())?;
  let query=context.ip_get(b"remote-fixture",Family::Any,CoreDuration(30_000_000))?;
  source.now.store(2_000_000,Ordering::SeqCst);
  source.advance_after_read.store(true,Ordering::SeqCst);let mut deadline=None;let until=Instant::now()+Duration::from_secs(1);
  while deadline.is_none(){driver.drive(Some(until),|event|{if let DriverEvent::SocketRetry{at,..}=event{deadline=Some(at);}}).await?;assert!(Instant::now()<until);}
  assert_eq!(driver.take_io_error().ok_or("missing original native error")?.kind(),io::ErrorKind::NotFound);
  assert_eq!(deadline,Some(AbsoluteTime::from_micros(3_002_000)),"source add_delayed samples after actual ENOENT, not before polling its native connect");
  drop(query);Ok(())
 })
}

async fn statistics_registration_refusal(capacity: bool) -> Test {
    use gnunet_client_host::resolution::PortError;
    use gnunet_resolver_broker::BrokerError;
    struct Source {
        clock: clock_source::Adjustable,
        failed: AtomicBool,
        arm_time_refusal: AtomicBool,
    }
    impl RuntimeClock for Source {
        fn sample(&self) -> Result<ClockSample, Error> {
            if self.failed.load(Ordering::SeqCst) {
                Err(Error::Io)
            } else {
                self.clock.sample()
            }
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            let lease = self.clock.subscribe()?;
            // Only native retry registration (after the consumed ENOENT) is
            // refused. The new persistent owner subscription is independent.
            if self.arm_time_refusal.swap(false, Ordering::SeqCst) {
                self.failed.store(true, Ordering::SeqCst);
            }
            Ok(lease)
        }
    }
    let dir = Dir::new()?;
    let path = dir.0.join("registration");
    let source = Arc::new(Source {
        clock: clock_source::Adjustable::frozen(1_000_000, 3)?,
        failed: AtomicBool::new(false),
        arm_time_refusal: AtomicBool::new(false),
    });
    let (context, _driver) = broker::<4, 64>(
        LiveConfiguration::new(config(b"resolver", &dir.0.join("unused"))?),
        Limits::default(),
        profile()?,
        source.clone(),
    )?;
    let mut held = if capacity {
        Some(source.subscribe()?)
    } else {
        None
    };
    let mut statistics_instance_2 = gnunet_client::statistics_handle::Instance::new();
    let mut host = Stats::from_config(
        &mut statistics_instance_2,
        &config(b"statistics", &path)?,
        context.resolution_context(),
        b"fixture",
        Default::default(),
    )?
    .ok_or("disabled")?;
    let selector = Selector {
        subsystem: b"fixture",
        name: b"value",
    };
    let get = host.get(selector)?;
    let epoch = host.connection_epoch();
    if !capacity {
        source.arm_time_refusal.store(true, Ordering::SeqCst);
    }
    let mut callbacks = 0;
    let error = match host
        .drive(None, |_, _| {
            callbacks += 1;
            GetFlow::Continue
        })
        .await
    {
        Err(gnunet_ipc_unix::IpcError::Io(e)) => e,
        other => {
            return Err(
                format!("registration refusal was not original boundary: {other:?}").into(),
            );
        }
    };
    assert_eq!(callbacks, 0);
    let marker = PortError::from_io(&error).ok_or("lost port origin")?;
    let cause = marker
        .cause()
        .get_ref()
        .and_then(|e| e.downcast_ref::<BrokerError>())
        .ok_or("lost original cause")?;
    assert!(matches!(
        (capacity, cause),
        (true, BrokerError::Core(Error::Capacity)) | (false, BrokerError::Core(Error::Io))
    ));
    assert_eq!(host.connection_epoch(), epoch);
    assert!(host.get_callbacks_enabled(get));
    assert!(host.take_io_error().is_none());
    let listener = UnixListener::bind(&path)?;
    drop(held.take());
    source.failed.store(false, Ordering::SeqCst);
    source.clock.set(2_000_000)?;
    let mut retried = 0;
    host.drive(None, |event, _| {
        if let Event::ConnectRetry {
            epoch: original,
            retry_after,
        } = event
        {
            assert_eq!(Some(original), epoch);
            assert_eq!(retry_after, Duration::from_millis(2));
            retried += 1;
        }
        GetFlow::Continue
    })
    .await?;
    assert_eq!(retried, 1);
    assert_eq!(
        host.take_io_error().ok_or("lost original ENOENT")?.kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(source.clock.listeners()?, 3);
    source.clock.set(2_001_999)?;
    assert!(
        alongside(
            &mut host,
            timeout(Duration::from_millis(20), listener.accept())
        )
        .await?
        .is_err(),
        "registration recovery must retain exactly2ms, without another increment/native effect"
    );
    source.clock.set(2_002_000)?;
    let (mut socket, _) = alongside(&mut host, listener.accept()).await??;
    let mut expected = [0; 128];
    let n = selector.encode_get(&mut expected)?;
    let mut actual = vec![0; n];
    alongside(&mut host, socket.read_exact(&mut actual)).await??;
    assert_eq!(actual, &expected[..n]);
    assert_eq!(
        source.clock.listeners()?,
        2,
        "the completed retry returns its own waiter while broker and owner retain theirs"
    );
    assert_eq!(host.connection_epoch(), epoch);
    assert!(host.get_callbacks_enabled(get));
    host.destroy(false)?;
    drop(host);
    assert_eq!(socket.read(&mut [0]).await?, 0);
    Ok(())
}
#[test]
fn statistics_retry_registration_capacity_preserves_original_error_until_only_registration_can_resume()
-> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(statistics_registration_refusal(true))
}
#[test]
fn statistics_retry_registration_time_error_preserves_original_error_and_releases_refused_waiter()
-> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(statistics_registration_refusal(false))
}

#[test]
fn broker_post_error_sample_failure_retries_only_registration_and_preserves_original_frame() -> Test
{
    struct Source {
        now: AtomicU64,
        armed: AtomicBool,
        fail_next: AtomicBool,
    }
    impl RuntimeClock for Source {
        fn sample(&self) -> Result<ClockSample, Error> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(Error::Io);
            }
            let now = self.now.load(Ordering::SeqCst);
            if self.armed.swap(false, Ordering::SeqCst) {
                self.now.store(3_000_000, Ordering::SeqCst);
                self.fail_next.store(true, Ordering::SeqCst);
            }
            Ok(ClockSample {
                now: AbsoluteTime::from_micros(now),
                revision: 0,
            })
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            RuntimeClock::subscribe(&SystemClock)
        }
    }
    async fn alongside<F: Future>(
        driver: &mut gnunet_resolver_broker::Driver<4, 64>,
        future: F,
    ) -> Result<F::Output, Box<dyn StdError>> {
        let mut future = std::pin::pin!(future);
        Ok(timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                if let Poll::Ready(result) = future.as_mut().poll(cx) {
                    return Poll::Ready(Ok(result));
                }
                let mut drive = std::pin::pin!(driver.drive(None, |_| {}));
                match drive.as_mut().poll(cx) {
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(_)) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await??)
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Dir::new()?;
            let path = dir.0.join("broker-post-error");
            let source = Arc::new(Source {
                now: AtomicU64::new(1_000_000),
                armed: AtomicBool::new(false),
                fail_next: AtomicBool::new(false),
            });
            let (context, mut driver) = broker::<4, 64>(
                LiveConfiguration::new(config(b"resolver", &path)?),
                Limits::default(),
                profile()?,
                source.clone(),
            )?;
            let query =
                context.ip_get(b"original-fixture", Family::Any, CoreDuration(30_000_000))?;
            source.now.store(2_000_000, Ordering::SeqCst);
            source.armed.store(true, Ordering::SeqCst);
            let result = driver.drive(None, |_| {}).await;
            assert!(
                matches!(
                    result,
                    Err(gnunet_resolver_broker::BrokerError::Core(Error::Io))
                ),
                "post-ENOENT sample failure must remain explicit: {result:?}"
            );
            assert!(driver.take_io_error().is_none());
            let listener = UnixListener::bind(&path)?;
            let mut retries = Vec::new();
            driver
                .drive(None, |event| {
                    if let DriverEvent::SocketRetry { at, .. } = event {
                        retries.push(at);
                    }
                })
                .await?;
            assert_eq!(retries, [AbsoluteTime::from_micros(3_002_000)]);
            assert_eq!(
                driver.take_io_error().ok_or("lost original ENOENT")?.kind(),
                io::ErrorKind::NotFound
            );
            assert!(
                alongside(
                    &mut driver,
                    timeout(Duration::from_millis(20), listener.accept())
                )
                .await?
                .is_err(),
                "resource recovery may register time, never reconnect early"
            );
            source.now.store(3_002_000, Ordering::SeqCst);
            let (mut socket, _) = alongside(&mut driver, listener.accept()).await??;
            let mut header = [0; 4];
            alongside(&mut driver, socket.read_exact(&mut header)).await??;
            let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let mut bytes = vec![0; len];
            bytes[..4].copy_from_slice(&header);
            alongside(&mut driver, socket.read_exact(&mut bytes[4..])).await??;
            let request = gnunet_client::resolver::Request::decode(
                gnunet_wire::official::Frame::decode(&bytes)?,
                profile()?,
            )?;
            assert!(matches!(
                request.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"original-fixture",
                    ..
                }
            ));
            drop(query);
            drop(driver);
            assert_eq!(socket.read(&mut [0]).await?, 0);
            Ok(())
        })
}

#[test]
fn canceled_statistics_drive_retains_original_retry_and_destroy_returns_only_its_waiter_credit()
-> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Dir::new()?;
            let clock = Arc::new(clock_source::Adjustable::frozen(1_000_000, 3)?);
            let (context, driver) = broker::<4, 64>(
                LiveConfiguration::new(config(b"resolver", &dir.0.join("unused"))?),
                Limits::default(),
                profile()?,
                clock.clone(),
            )?;
            let mut statistics_instance_3 = gnunet_client::statistics_handle::Instance::new();
            let mut host = Stats::from_config(
                &mut statistics_instance_3,
                &config(b"statistics", &dir.0.join("missing"))?,
                context.resolution_context(),
                b"fixture",
                Default::default(),
            )?
            .ok_or("disabled")?;
            let get = host.get(Selector {
                subsystem: b"fixture",
                name: b"value",
            })?;
            let epoch = host.connection_epoch();
            host.drive(None, |_, _| GetFlow::Continue).await?;
            assert_eq!(
                host.take_io_error().ok_or("missing native failure")?.kind(),
                io::ErrorKind::NotFound
            );
            assert_eq!(clock.listeners()?, 3);
            {
                let mut wait = std::pin::pin!(host.drive(None, |_, _| GetFlow::Continue));
                assert!(
                    wait.as_mut()
                        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                        .is_pending()
                );
            }
            assert_eq!(clock.listeners()?, 3);
            assert_eq!(host.connection_epoch(), epoch);
            host.get_cancel(get)?;
            assert_eq!(
                clock.listeners()?,
                3,
                "cancel only suppresses this original callback, not the immutable MQ retry"
            );
            host.destroy(false)?;
            assert_eq!(clock.listeners()?, 1);
            let replacement = context.resolution_context().timer(Duration::MAX)?;
            assert_eq!(clock.listeners()?, 2);
            let mut report = false;
            host.drive(None, |event, _| {
                if let Event::Destroyed(_) = event {
                    report = true;
                }
                GetFlow::Continue
            })
            .await?;
            assert!(report);
            drop(host);
            assert_eq!(clock.listeners()?, 2);
            drop(replacement);
            assert_eq!(clock.listeners()?, 1);
            drop(driver);
            assert_eq!(clock.listeners()?, 0);
            Ok(())
        })
}

#[test]
fn broker_initial_ready_at_max_runs_once_but_saturated_delayed_retry_remains_never() -> Test {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let dir=Dir::new()?;let clock=Arc::new(clock_source::Adjustable::frozen(1_000_000,2)?);
        let(context,mut driver)=broker::<4,64>(LiveConfiguration::new(config(b"resolver",&dir.0.join("missing-at-max"))?),Limits::default(),profile()?,clock.clone())?;
        let query=context.ip_get(b"remote-fixture",Family::Any,CoreDuration(u64::MAX))?;
        clock.set(u64::MAX)?;let mut retries=Vec::new();
        assert_eq!(driver.drive(Some(Instant::now()+Duration::from_secs(1)),|event|{if let DriverEvent::SocketRetry{at,..}=event{retries.push(at);}}).await?,gnunet_resolver_broker::Progress::Activity);
        assert_eq!(retries,[AbsoluteTime::from_micros(u64::MAX)],"initial already-ready CLIENT creation must still run at MAX");
        assert_eq!(driver.take_io_error().ok_or("initial ready attempt did not perform actual ENOENT")?.kind(),io::ErrorKind::NotFound);
        retries.clear();let result=driver.drive(Some(Instant::now()+Duration::from_millis(20)),|event|{if let DriverEvent::SocketRetry{at,..}=event{retries.push(at);}}).await?;
        assert_eq!(result,gnunet_resolver_broker::Progress::WaitDeadline,"a saturated delayed retry is not initial ready work; public NEVER profile must hold after independent wake at MAX");
        assert!(retries.is_empty());assert!(driver.take_io_error().is_none());drop(query);Ok(())
    })
}
