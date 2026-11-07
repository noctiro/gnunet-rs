//! Actual pre-connect CLIENT socket retries follow the original logical target.
use gnunet_arm_core::{FrameSlot, monitor::Monitor};
use gnunet_arm_host::{Clock, Limits, MonitorHost, Progress};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::UnixListener, time::Instant};
type Test = Result<(), Box<dyn StdError>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gnunet-arm-physical-clock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
use clock_source::Adjustable;
async fn alongside<F: Future>(
    host: &mut MonitorHost<'_>,
    future: F,
) -> Result<F::Output, Box<dyn StdError>> {
    let mut future = std::pin::pin!(future);
    Ok(tokio::time::timeout(
        Duration::from_secs(3),
        poll_fn(|cx| {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                return Poll::Ready(Ok(result));
            }
            let mut drive = std::pin::pin!(host.drive(None, |_, _| {}));
            match drive.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(Progress::Activity)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Ok(_)) => Poll::Pending,
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await??)
}
async fn profile(rollback: bool) -> Test {
    let directory = Directory::new()?;
    let path = directory.0.join("arm.sock");
    let mut frames = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 16];
    let core = Monitor::new(&mut frames, &mut bytes, 1)?;
    let source = Arc::new(Adjustable::advancing(1_000_000, 8)?);
    let mut host = MonitorHost::start_unix(
        core,
        path.clone(),
        Limits::default(),
        Clock::new(source.clone())?,
        |_| {},
    )?;
    // These are actual ENOENT socket effects. The original logical MQ remains
    // admitted while its physical CLIENT retry grows to a 256ms wait.
    let until = Instant::now() + Duration::from_secs(3);
    let mut failures = 0;
    while failures < 8 {
        assert!(
            Instant::now() < until,
            "eight native socket failures must be finite"
        );
        let _progress = host.drive(Some(until), |_, _| {}).await?;
        if let Some(error) = host.take_io_error() {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            failures += 1;
        }
    }
    assert_eq!(
        host.retry_backoff(),
        0,
        "physical failures must retain original logical MONITOR MQ"
    );
    let listener = UnixListener::bind(&path)?;
    if rollback {
        source.set_offset(-1_000_000)?;
        let premature = alongside(
            &mut host,
            tokio::time::timeout(Duration::from_millis(350), listener.accept()),
        )
        .await?;
        assert!(
            premature.is_err(),
            "native elapsed256ms cannot override the original logical CLIENT retry after rollback"
        );
    }
    source.set_offset(1_000_000)?;
    let accepted = alongside(
        &mut host,
        tokio::time::timeout(Duration::from_millis(100), listener.accept()),
    )
    .await?;
    assert!(
        accepted.is_ok(),
        "logical revision past the original CLIENT retry must connect without waiting its old native deadline"
    );
    let (mut stream, _) = accepted??;
    let mut header = [0; 4];
    alongside(&mut host, stream.read_exact(&mut header)).await??;
    assert_eq!(
        header,
        [0, 4, 0, 14],
        "exact original MONITOR frame must survive pre-connect retries"
    );
    assert_eq!(host.retry_backoff(), 0);
    let mut extra = [0];
    let duplicate = alongside(
        &mut host,
        tokio::time::timeout(Duration::from_millis(15), stream.read(&mut extra)),
    )
    .await?;
    assert!(
        duplicate.is_err(),
        "no repeated subscription may be invented by clock changes"
    );
    host.stop();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut extra)).await??,
        0
    );
    Ok(())
}
#[test]
fn physical_client_retry_forward_revision_keeps_mq_and_original_subscription() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(profile(false))
}
#[test]
fn physical_client_retry_rollback_keeps_original_absolute_target_and_can_resume() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(profile(true))
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "A closed owner retained by its caller must return only its original waiter credit"
)]
fn stopped_monitor_releases_subscription_before_the_host_value_is_dropped() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let directory = Directory::new()?;
            let source = Arc::new(Adjustable::frozen(1_000_000, 1)?);
            let mut slots = [FrameSlot::EMPTY; 1];
            let mut bytes = [0; 16];
            let core = Monitor::new(&mut slots, &mut bytes, 1)?;
            let mut host = MonitorHost::start_unix(
                core,
                directory.0.join("never-connected"),
                Limits::default(),
                Clock::new(source.clone())?,
                |_| {},
            )?;
            assert_eq!(source.listeners()?, 1);
            host.stop();
            assert!(host.is_closed());
            assert_eq!(
                source.listeners()?,
                0,
                "stop must return the unique subscription even while caller retains the closed host"
            );
            let replacement = Clock::new(source.clone())?;
            assert_eq!(source.listeners()?, 1);
            assert_eq!(host.drive(None, |_, _| {}).await?, Progress::Closed);
            assert_eq!(
                source.listeners()?,
                1,
                "a repeated closed drive cannot release another owner's reused credit"
            );
            drop(host);
            assert_eq!(source.listeners()?, 1);
            drop(replacement);
            assert_eq!(source.listeners()?, 0);
            Ok(())
        })
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Disconnect drains the original callback and releases its waiter before retained-host reuse"
)]
fn disconnected_client_releases_subscription_and_closed_drive_does_not_sample_again() -> Test {
    use gnunet_arm_core::{
        client::{Client, Event, Inbound, OperationSlot},
        wire::ArmAbi,
    };
    use gnunet_arm_host::{ChildRegistry, ClientHost, LaunchLimits, LocalLauncher};
    use gnunet_config::Configuration;
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
    use gnunet_types::Error;
    use std::sync::atomic::AtomicBool;
    struct Source {
        clock: Adjustable,
        failed: AtomicBool,
        samples: AtomicU64,
    }
    impl RuntimeClock for Source {
        fn sample(&self) -> Result<ClockSample, Error> {
            self.samples.fetch_add(1, Ordering::SeqCst);
            if self.failed.load(Ordering::SeqCst) {
                Err(Error::Io)
            } else {
                self.clock.sample()
            }
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            self.clock.subscribe()
        }
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let directory = Directory::new()?;
            let path = directory.0.join("never-connected-client");
            let mut config = Configuration::default();
            config.set_value(
                b"arm",
                b"UNIXPATH",
                Some(path.as_os_str().as_encoded_bytes()),
            )?;
            let source = Arc::new(Source {
                clock: Adjustable::frozen(1_000_000, 1)?,
                failed: AtomicBool::new(false),
                samples: AtomicU64::new(0),
            });
            let mut registry = ChildRegistry::new(1)?;
            let launcher = LocalLauncher::new(
                config,
                PathBuf::from(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
                LaunchLimits::default(),
                &mut registry,
            )?;
            let mut ops = [OperationSlot::EMPTY; 1];
            let mut slots = [FrameSlot::EMPTY; 2];
            let mut bytes = [0; 128];
            let core = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
            let mut host = ClientHost::connect_unix(
                core,
                path,
                launcher,
                Limits::default(),
                Clock::new(source.clone())?,
                |_| {},
            )?;
            let id = host.request_service_list()?;
            let mut callbacks = 0;
            host.disconnect(|event, _| {
                if let Inbound::Event(Event::ListDisconnected { operation }) = event {
                    assert_eq!(operation, id);
                    callbacks += 1;
                }
            })?;
            assert_eq!(callbacks, 1);
            assert_eq!(source.clock.listeners()?, 0);
            let replacement = Clock::new(source.clone())?;
            source.failed.store(true, Ordering::SeqCst);
            let old_samples = source.samples.load(Ordering::SeqCst);
            assert_eq!(host.drive(None, |_, _| {}).await?, Progress::Closed);
            assert_eq!(
                source.samples.load(Ordering::SeqCst),
                old_samples,
                "fully closed drive must not consult a failed clock source"
            );
            assert_eq!(source.clock.listeners()?, 1);
            drop(host);
            assert_eq!(source.clock.listeners()?, 1);
            drop(replacement);
            assert_eq!(source.clock.listeners()?, 0);
            assert_eq!(registry.pending_children(), 0);
            Ok(())
        })
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Real immediate ENOENT and staged source failure must keep the original error until its post-failure deadline can be registered"
)]
fn native_failure_waits_for_post_failure_clock_sample_without_reconnecting_or_rebasing() -> Test {
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
    use gnunet_types::Error;
    struct Source {
        clock: Adjustable,
        samples: AtomicU64,
    }
    impl RuntimeClock for Source {
        fn sample(&self) -> Result<ClockSample, Error> {
            // Constructor, host poll, preflight, then actual ENOENT's add_delayed
            // read point. The native Unix connect is immediate on a missing path.
            if self.samples.fetch_add(1, Ordering::SeqCst) == 3 {
                Err(Error::Io)
            } else {
                self.clock.sample()
            }
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            self.clock.subscribe()
        }
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let directory = Directory::new()?;
            let path = directory.0.join("post-failure");
            let source = Arc::new(Source {
                clock: Adjustable::frozen(1_000_000, 1)?,
                samples: AtomicU64::new(0),
            });
            let mut frames = [FrameSlot::EMPTY; 1];
            let mut bytes = [0; 16];
            let core = Monitor::new(&mut frames, &mut bytes, 1)?;
            let mut host = MonitorHost::start_unix(
                core,
                path.clone(),
                Limits::default(),
                Clock::new(source.clone())?,
                |_| {},
            )?;
            let result = host.drive(None, |_, _| {}).await;
            assert!(
                matches!(result, Err(gnunet_arm_host::HostError::Core(Error::Io))),
                "post-failure time error must be a boundary, not native retry progress: {result:?}"
            );
            assert_eq!(source.samples.load(Ordering::SeqCst), 4);
            assert!(host.take_io_error().is_none());
            assert_eq!(host.retry_backoff(), 0);
            let listener = UnixListener::bind(&path)?;
            source.clock.set(2_000_000)?;
            assert_eq!(host.drive(None, |_, _| {}).await?, Progress::Activity);
            assert_eq!(
                host.take_io_error().ok_or("lost original ENOENT")?.kind(),
                io::ErrorKind::NotFound
            );
            source.clock.set(2_001_999)?;
            assert!(
                alongside(
                    &mut host,
                    tokio::time::timeout(Duration::from_millis(20), listener.accept())
                )
                .await?
                .is_err(),
                "retry must preserve the original post-failure 2M+2ms target"
            );
            source.clock.set(2_002_000)?;
            let (mut stream, _) = alongside(&mut host, listener.accept()).await??;
            let mut header = [0; 4];
            alongside(&mut host, stream.read_exact(&mut header)).await??;
            assert_eq!(header, [0, 4, 0, 14]);
            assert!(host.take_io_error().is_none());
            host.stop();
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok(())
        })
}
