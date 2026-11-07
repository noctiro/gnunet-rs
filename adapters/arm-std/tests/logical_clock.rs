//! Real Unix reconnects under the original adjustable PROGRAM clock domain.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual original socket and deadline assertions distinguish native progress from a planned retry"
)]
use gnunet_arm_core::{FrameSlot, monitor::Monitor};
use gnunet_arm_host::{Clock, HostError, Limits, MonitorHost, Progress};
use gnunet_types::Error;
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
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
};
type Test = Result<(), Box<dyn StdError>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gnunet-arm-logical-{}-{}",
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
    let mut driver = std::pin::pin!(async {
        loop {
            if host.drive(None, |_, _| {}).await? == Progress::Closed {
                return Err::<(), HostError>(Error::Closed.into());
            }
        }
    });
    Ok(tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            if let Poll::Ready(value) = future.as_mut().poll(cx) {
                return Poll::Ready(Ok(value));
            }
            match driver.as_mut().poll(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => Poll::Ready(Err(Error::Closed.into())),
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await??)
}
async fn subscribed(
    host: &mut MonitorHost<'_>,
    listener: &UnixListener,
) -> Result<UnixStream, Box<dyn StdError>> {
    let (mut stream, _) = alongside(host, listener.accept()).await??;
    let mut header = [0; 4];
    let _count = alongside(host, stream.read_exact(&mut header)).await??;
    assert_eq!(header, [0, 4, 0, 14]);
    Ok(stream)
}
#[test]
fn logical_monitor_reconnect_keeps_original_deadline_across_rollback_and_revision_wakes_pending_drive()
-> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let directory = Directory::new()?;
            let path = directory.0.join("arm.sock");
            let listener = UnixListener::bind(&path)?;
            let mut frames = [FrameSlot::EMPTY; 1];
            let mut bytes = [0; 16];
            let core = Monitor::new(&mut frames, &mut bytes, 1)?;
            let clock = Arc::new(Adjustable::frozen(1_000_000, 8)?);
            let mut host = MonitorHost::start_unix(
                core,
                path,
                Limits::default(),
                Clock::new(clock.clone())?,
                |_| {},
            )?;
            let first = subscribed(&mut host, &listener).await?;
            drop(first);
            let second = subscribed(&mut host, &listener).await?;
            assert_eq!(host.retry_backoff(), 2000);
            drop(second);
            let none = alongside(
                &mut host,
                tokio::time::timeout(Duration::from_millis(15), listener.accept()),
            )
            .await?;
            assert!(none.is_err());
            assert_eq!(host.retry_backoff(), 4000);
            clock.set(900_000)?;
            let none = alongside(
                &mut host,
                tokio::time::timeout(Duration::from_millis(15), listener.accept()),
            )
            .await?;
            assert!(
                none.is_err(),
                "rollback cannot move the original 1002000 deadline"
            );
            clock.set(1_001_999)?;
            let none = alongside(
                &mut host,
                tokio::time::timeout(Duration::from_millis(10), listener.accept()),
            )
            .await?;
            assert!(
                none.is_err(),
                "one logical microsecond before original target cannot mint a new MQ"
            );
            let (mut third, _) = alongside(&mut host, async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                clock.set(1_002_000).map_err(io::Error::other)?;
                listener.accept().await
            })
            .await??;
            let mut header = [0; 4];
            let _count = alongside(&mut host, third.read_exact(&mut header)).await??;
            assert_eq!(header, [0, 4, 0, 14]);
            host.stop();
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), third.read(&mut byte)).await??,
                0
            );
            Ok(())
        })
}

#[test]
fn logical_startup_deadline_reports_original_starting_while_real_child_keeps_signal_pipe_open()
-> Test {
    use gnunet_arm_core::{
        client::{Client, Event, Inbound, OperationSlot, StdioInheritance},
        wire::{ArmAbi, RequestStatus, ResultCode},
    };
    use gnunet_arm_host::{ChildRegistry, ClientHost, LaunchLimits, LocalLauncher};
    use gnunet_config::Configuration;
    use tokio::time::Instant;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let directory = Directory::new()?;
            let binary = directory.0.join("child");
            let trace = directory.0.join("trace");
            let source =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/arm_fixture.c");
            let compile = std::process::Command::new("cc")
                .arg(&source)
                .arg("-o")
                .arg(&binary)
                .output()?;
            assert!(
                compile.status.success(),
                "{}",
                String::from_utf8_lossy(&compile.stderr)
            );
            let path = directory.0.join("no-server");
            let mut config = Configuration::default();
            config.set_value(
                b"arm",
                b"UNIXPATH",
                Some(path.as_os_str().as_encoded_bytes()),
            )?;
            config.set_value(
                b"arm",
                b"BINARY",
                Some(binary.as_os_str().as_encoded_bytes()),
            )?;
            config.set_value(
                b"arm",
                b"OPTIONS",
                Some(format!("--output {} --hold-ms 2000", trace.display()).as_bytes()),
            )?;
            config.set_value(b"TESTING", b"WEAKRANDOM", Some(b"YES"))?;
            let mut children = ChildRegistry::new(8)?;
            let launcher = LocalLauncher::new(
                config,
                PathBuf::from(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
                LaunchLimits::default(),
                &mut children,
            )?;
            let mut ops = [OperationSlot::EMPTY; 2];
            let mut frames = [FrameSlot::EMPTY; 4];
            let mut bytes = [0; 256];
            let core = Client::new(&mut ops, &mut frames, &mut bytes, 1, ArmAbi::U64Align8)?;
            let clock = Arc::new(Adjustable::frozen(1_000_000, 8)?);
            let mut host = ClientHost::connect_unix(
                core,
                path,
                launcher,
                Limits::default(),
                Clock::new(clock.clone())?,
                |_| {},
            )?;
            let operation = host.request_service_start(b"arm", StdioInheritance(8))?;
            let mut result = None;
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                let progress = host
                    .drive(
                        Some(Instant::now() + Duration::from_millis(5)),
                        |event, _| {
                            if let Inbound::Event(Event::Result {
                                operation: original,
                                status,
                                result: code,
                            }) = event
                            {
                                result = Some((original, status, code));
                            }
                        },
                    )
                    .await?;
                assert!(
                    Instant::now() < until,
                    "owned child never entered its actual hold"
                );
                if progress == Progress::WaitDeadline
                    && std::fs::read_to_string(&trace).is_ok_and(|text| text.contains("started"))
                {
                    break;
                }
            }
            assert_eq!(result, None);
            assert_eq!(host.launcher_mut().pending_children(), 1);
            clock.set(900_000)?;
            let _progress = host
                .drive(
                    Some(Instant::now() + Duration::from_millis(10)),
                    |event, _| {
                        if let Inbound::Event(Event::Result {
                            operation: original,
                            status,
                            result: code,
                        }) = event
                        {
                            result = Some((original, status, code));
                        }
                    },
                )
                .await?;
            assert_eq!(result, None);
            clock.set(60_999_999)?;
            let wait_until = Instant::now() + Duration::from_millis(10);
            loop {
                if host
                    .drive(Some(wait_until), |event, _| {
                        if let Inbound::Event(Event::Result {
                            operation: original,
                            status,
                            result: code,
                        }) = event
                        {
                            result = Some((original, status, code));
                        }
                    })
                    .await?
                    == Progress::WaitDeadline
                {
                    break;
                }
            }
            assert_eq!(
                result, None,
                "logical time before original target cannot complete startup"
            );
            let real_start = Instant::now();
            clock.set(61_000_000)?;
            while result.is_none() {
                let _progress = host
                    .drive(Some(real_start + Duration::from_millis(100)), |event, _| {
                        if let Inbound::Event(Event::Result {
                            operation: original,
                            status,
                            result: code,
                        }) = event
                        {
                            result = Some((original, status, code));
                        }
                    })
                    .await?;
                assert!(
                    Instant::now() < real_start + Duration::from_millis(100),
                    "source logical deadline did not dispatch promptly"
                );
            }
            assert_eq!(
                result,
                Some((operation, RequestStatus::SentOk, Some(ResultCode::STARTING)))
            );
            assert!(!host.owns_operation(operation));
            assert_eq!(host.launcher_mut().pending_children(), 1);
            assert!(
                !std::fs::read_to_string(&trace)?.contains("released"),
                "actual pipe EOF must not explain the logical-deadline callback"
            );
            host.disconnect(|_, _| {})?;
            tokio::time::timeout(Duration::from_secs(3), host.launcher_mut().drain_children())
                .await??;
            assert_eq!(host.launcher_mut().pending_children(), 0);
            assert!(std::fs::read_to_string(&trace)?.contains("released"));
            Ok(())
        })
}
