//! Actual owned-child launch, signal-credit and original-PID wait regressions.
#![expect(
    clippy::panic,
    reason = "These test-only callbacks deliberately fail on unexpected invocation or result shape."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual owned child/socket invariants are asserted while OS failures propagate"
)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_arm_core::{
    FrameSlot,
    client::{Client, Event, Inbound, OperationSlot, StdioInheritance},
    wire::{ArmAbi, RequestStatus, ResultCode},
};
use gnunet_arm_host::{
    ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LocalLauncher, Progress,
};
use gnunet_config::Configuration;
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::time::{Instant, timeout};
type Test = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(2000);
struct Dir(PathBuf);
impl Dir {
    fn new() -> io::Result<Self> {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = PathBuf::from(format!("/tmp/gnunet-arm-start-{}-{id}", std::process::id()));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
fn fixture() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = std::env::var_os("ARM_FIXTURE") {
        return Ok(PathBuf::from(path));
    }
    static BUILT: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    let result = BUILT.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("gnunet-arm-owned-fixture-{}", std::process::id()));
        std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
        let binary = dir.join("fixture");
        let source =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/arm_fixture.c");
        let compiled = std::process::Command::new("cc")
            .arg(source)
            .arg("-o")
            .arg(&binary)
            .output()
            .map_err(|e| e.to_string())?;
        if !compiled.status.success() {
            return Err(String::from_utf8_lossy(&compiled.stderr).into_owned());
        }
        Ok(binary)
    });
    result.clone().map_err(|e| e.into())
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn cfg(
    dir: &Dir,
    binary: Option<&std::path::Path>,
    options: &[u8],
) -> Result<Configuration, Box<dyn Error>> {
    let mut c = Configuration::new(Default::default());
    c.set_value(
        b"arm",
        b"UNIXPATH",
        Some(dir.0.join("no-server").as_os_str().as_encoded_bytes()),
    )?;
    if let Some(binary) = binary {
        c.set_value(
            b"arm",
            b"BINARY",
            Some(binary.as_os_str().as_encoded_bytes()),
        )?;
    }
    c.set_value(b"arm", b"OPTIONS", Some(options))?;
    c.set_value(b"TESTING", b"WEAKRANDOM", Some(b"YES"))?;
    Ok(c)
}
fn core<'a>(
    ops: &'a mut [OperationSlot],
    slots: &'a mut [FrameSlot],
    pool: &'a mut [u8],
) -> Result<Client<'a>, Box<dyn Error>> {
    Ok(Client::new(
        ops,
        slots,
        pool,
        NEXT.fetch_add(1, Ordering::Relaxed),
        ArmAbi::U64Align8,
    )?)
}
fn launch<'r>(
    c: &Configuration,
    registry: &'r mut ChildRegistry,
) -> Result<LocalLauncher<'r>, Box<dyn Error>> {
    Ok(LocalLauncher::new(
        c.duplicate()?,
        PathBuf::from(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
        LaunchLimits::default(),
        registry,
    )?)
}
async fn result(
    host: &mut ClientHost<'_, '_>,
) -> Result<(RequestStatus, Option<ResultCode>), Box<dyn Error>> {
    let mut result = None;
    let until = Instant::now() + Duration::from_secs(3);
    while result.is_none() {
        assert_ne!(
            host.drive(Some(until), |event, _| {
                if let Inbound::Event(Event::Result {
                    status,
                    result: code,
                    ..
                }) = event
                {
                    result = Some((status, code));
                }
            })
            .await?,
            Progress::WaitDeadline
        );
    }
    Ok(result.ok_or("missing")?)
}
#[test]
fn actual_fixture_readiness_eof_is_starting_and_child_is_reaped() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let trace = dir.0.join("trace");
        let c = cfg(
            &dir,
            Some(fixture()?.as_path()),
            format!("--output {} --hold-ms 30", trace.display()).as_bytes(),
        )?;
        let mut registry = ChildRegistry::new(64)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 512];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            c.duplicate()?,
            domain.resolution(),
            launch(&c, &mut registry)?,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let op = host.request_service_start(b"aRm", StdioInheritance(8))?;
        assert_eq!(
            result(&mut host).await?,
            (RequestStatus::SentOk, Some(ResultCode::STARTING))
        );
        assert!(!host.owns_operation(op));
        timeout(Duration::from_secs(2), host.launcher_mut().drain_children()).await??;
        let data = std::fs::read_to_string(trace)?;
        assert!(data.contains("released"));
        assert!(data.contains("\"control\":\"") && !data.contains("\"control\":\"\""));
        host.disconnect(|_, _| {})?;
        Ok(())
    })
}
#[test]
fn missing_binary_nonexecutable_and_late_exec_failure_are_distinct() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        use std::os::unix::fs::PermissionsExt;
        let dir = Dir::new()?;
        let late = dir.0.join("bad-interpreter");
        std::fs::write(&late, b"#!/gnunet-owned-fixture-no-such-interpreter\n")?;
        std::fs::set_permissions(&late, std::fs::Permissions::from_mode(0o700))?;
        let notexec = dir.0.join("nonexec");
        std::fs::write(&notexec, b"not executable")?;
        for (binary, expected, children) in [
            (None, ResultCode::IS_NOT_KNOWN, 0),
            (Some(notexec.as_path()), ResultCode::START_FAILED, 0),
            (Some(late.as_path()), ResultCode::STARTING, 1),
        ] {
            let c = cfg(&dir, binary, b"")?;
            let mut registry = ChildRegistry::new(64)?;
            let mut ops = [OperationSlot::EMPTY; 4];
            let mut slots = [FrameSlot::EMPTY; 8];
            let mut pool = [0; 512];
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                c.duplicate()?,
                domain.resolution(),
                launch(&c, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            host.request_service_start(b"arm", StdioInheritance(0))?;
            let mut observed_spawn = false;
            let mut got = None;
            let until = Instant::now() + Duration::from_secs(2);
            while got.is_none() {
                assert_ne!(
                    host.drive(Some(until), |e, _| {
                        if let Inbound::Event(Event::Result { status, result, .. }) = e {
                            got = Some((status, result));
                        }
                    })
                    .await?,
                    Progress::WaitDeadline
                );
                observed_spawn |= host.launcher_mut().pending_children() > 0;
            }
            assert_eq!(got, Some((RequestStatus::SentOk, Some(expected))));
            assert_eq!(usize::from(observed_spawn), children);
            timeout(Duration::from_secs(2), host.launcher_mut().drain_children()).await??;
            if children == 1 {
                assert_eq!(
                    host.launcher_mut().take_reaped().map(|r| r.exit),
                    Some(gnunet_arm_host::launch::ChildExit::Exited(1))
                );
            }
            host.disconnect(|_, _| {})?;
        }
        Ok(())
    })
}
#[test]
fn cancellation_and_disconnect_close_original_signal_without_killing_child() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        for disconnect in [false, true] {
            let dir = Dir::new()?;
            let trace = dir.0.join("trace");
            let c = cfg(
                &dir,
                Some(fixture()?.as_path()),
                format!("--output {} --hold-ms 150", trace.display()).as_bytes(),
            )?;
            let mut registry = ChildRegistry::new(64)?;
            let mut ops = [OperationSlot::EMPTY; 4];
            let mut slots = [FrameSlot::EMPTY; 8];
            let mut pool = [0; 512];
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                c.duplicate()?,
                domain.resolution(),
                launch(&c, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            let op = host.request_service_start(b"arm", StdioInheritance(0))?;
            let until = Instant::now() + Duration::from_secs(2);
            while host.launcher_mut().pending_children() == 0 {
                assert_ne!(
                    host.drive(Some(until), |_, _| panic!("premature result"))
                        .await?,
                    Progress::WaitDeadline
                );
            }
            if disconnect {
                let mut callbacks = 0;
                host.disconnect(|e, _| {
                    if let Inbound::Event(Event::Result {
                        operation,
                        status,
                        result,
                    }) = e
                    {
                        assert_eq!(operation, op);
                        assert_eq!(status, RequestStatus::Disconnected);
                        assert_eq!(result, None);
                        callbacks += 1;
                    }
                })?;
                assert_eq!(callbacks, 1);
            } else {
                host.operation_cancel(op)?;
                for _ in 0..3 {
                    let _ = host
                        .drive(Some(Instant::now() + Duration::from_millis(1)), |_, _| {
                            panic!("canceled callback")
                        })
                        .await?;
                }
            }
            timeout(Duration::from_secs(2), host.launcher_mut().drain_children()).await??;
            assert!(std::fs::read_to_string(trace)?.contains("released"));
            if !disconnect {
                host.disconnect(|_, _| panic!("canceled callback"))?;
            }
        }
        Ok(())
    })
}
#[test]
fn dropping_host_retains_original_live_child_wait_authority_in_caller_registry() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let trace = dir.0.join("drop-trace");
        let c = cfg(
            &dir,
            Some(fixture()?.as_path()),
            format!("--output {} --hold-ms 200", trace.display()).as_bytes(),
        )?;
        let mut registry = ChildRegistry::new(64)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 512];
        {
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                c.duplicate()?,
                domain.resolution(),
                launch(&c, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            host.request_service_start(b"arm", StdioInheritance(0))?;
            let until = Instant::now() + Duration::from_secs(2);
            while host.launcher_mut().pending_children() == 0 {
                assert_ne!(
                    host.drive(Some(until), |_, _| panic!("early completion"))
                        .await?,
                    Progress::WaitDeadline
                );
            }
            assert_eq!(host.launcher_mut().pending_children(), 1);
        }
        assert_eq!(registry.pending_children(), 1);
        timeout(Duration::from_secs(2), registry.drain_children()).await??;
        assert_eq!(registry.pending_children(), 0);
        assert_eq!(
            registry.take_reaped().map(|r| r.exit),
            Some(gnunet_arm_host::launch::ChildExit::Exited(0))
        );
        assert!(std::fs::read_to_string(trace)?.contains("released"));
        Ok(())
    })
}
#[test]
#[ignore = "actual 65-second own-child lifecycle; explicit acceptance command runs this witness"]
fn actual_sixty_second_signal_deadline_keeps_starting_without_readiness() -> Test {
    runtime()?.block_on(async {
        let mut domain=resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let trace = dir.0.join("sixty-second-trace");
        let c = cfg(&dir, Some(fixture()?.as_path()),
            format!("--output {} --hold-ms 65000", trace.display()).as_bytes())?;
        let mut registry = ChildRegistry::new(4)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 512];
        let mut host = ClientHost::connect(core(&mut ops, &mut slots, &mut pool)?,
            c.duplicate()?, domain.resolution(), launch(&c, &mut registry)?, Limits::default(),
            Clock::system()?, |_| panic!("initial MQ failed"))?;
        let started = Instant::now();
        host.request_service_start(b"arm", StdioInheritance(0))?;
        let mut observed = None;
        let until = started + Duration::from_secs(63);
        while observed.is_none() {
            assert_ne!(host.drive(Some(until), |event, _| {
                if let Inbound::Event(Event::Result { status, result, .. }) = event {
                    observed = Some((status, result));
                }
            }).await?, Progress::WaitDeadline);
        }
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(60));
        assert!(elapsed < Duration::from_secs(63));
        assert_eq!(observed, Some((RequestStatus::SentOk, Some(ResultCode::STARTING))));
        assert_eq!(host.launcher_mut().reap_completed()?, 0);
        assert_eq!(host.launcher_mut().pending_children(), 1);
        assert!(!std::fs::read_to_string(&trace)?.contains("released"),
            "EOF rather than timer caused completion");
        host.disconnect(|_, _| {})?;
        drop(host);
        assert_eq!(registry.pending_children(), 1);
        timeout(Duration::from_secs(8), registry.drain_children()).await??;
        assert_eq!(registry.take_reaped().map(|r| r.exit),
            Some(gnunet_arm_host::launch::ChildExit::Exited(0)));
        writeln!(io::stdout().lock(),
            "{{\"actual_deadline_us\":{},\"result\":2,\"child_alive_at_callback\":true,\"actual_exit\":0}}",
            elapsed.as_micros())?;
        Ok(())
    })
}
#[test]
fn one_signal_credit_defers_second_start_and_callback_reentry_until_cleanup() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        for callback_reentry in [false, true] {
            let dir = Dir::new()?;
            let c = cfg(&dir, None, b"")?;
            let mut registry = ChildRegistry::new(4)?;
            let mut ops = [OperationSlot::EMPTY; 4];
            let mut slots = [FrameSlot::EMPTY; 8];
            let mut pool = [0; 512];
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                c.duplicate()?,
                domain.resolution(),
                launch(&c, &mut registry)?,
                Limits {
                    max_startup_signals: 1,
                    ..Limits::default()
                },
                Clock::system()?,
                |_| panic!(),
            )?;
            host.request_service_start(b"arm", StdioInheritance(0))?;
            if !callback_reentry {
                host.request_service_start(b"ARM", StdioInheritance(0))?;
            }
            let mut results = 0;
            let mut reentrant_error = None;
            let until = Instant::now() + Duration::from_secs(2);
            while results != 2 {
                assert_ne!(
                    host.drive(Some(until), |e, context| {
                        if let Inbound::Event(Event::Result { status, result, .. }) = e {
                            assert_eq!(status, RequestStatus::SentOk);
                            assert_eq!(result, Some(ResultCode::IS_NOT_KNOWN));
                            results += 1;
                            if callback_reentry
                                && results == 1
                                && let Err(e) =
                                    context.request_service_start(b"aRm", StdioInheritance(0))
                            {
                                reentrant_error = Some(e);
                            }
                        }
                    })
                    .await?,
                    Progress::WaitDeadline
                );
            }
            assert!(reentrant_error.is_none());
            assert_eq!(host.launcher_mut().pending_children(), 0);
            host.disconnect(|_, _| panic!("duplicate callback"))?;
        }
        Ok(())
    })
}
#[test]
fn child_registry_credit_does_not_block_first_signal_cleanup_and_resumes_after_consuming_wait()
-> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let c = cfg(
            &dir,
            Some(fixture()?.as_path()),
            format!(
                "--output {} --hold-ms 20",
                dir.0.join("credit-trace").display()
            )
            .as_bytes(),
        )?;
        let mut registry = ChildRegistry::new(1)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 512];
        let launcher = LocalLauncher::new(
            c.duplicate()?,
            PathBuf::from(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
            LaunchLimits {
                max_children: 1,
                ..LaunchLimits::default()
            },
            &mut registry,
        )?;
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            c.duplicate()?,
            domain.resolution(),
            launcher,
            Limits {
                max_startup_signals: 2,
                ..Limits::default()
            },
            Clock::system()?,
            |_| panic!(),
        )?;
        host.request_service_start(b"arm", StdioInheritance(0))?;
        host.request_service_start(b"arm", StdioInheritance(0))?;
        let mut results = 0;
        let mut reaped = 0;
        let until = Instant::now() + Duration::from_secs(3);
        while results != 2 || reaped != 2 {
            if Instant::now() >= until {
                return Err("bounded child-credit progress stopped".into());
            }
            let _ = host
                .drive(Some(Instant::now() + Duration::from_millis(10)), |e, _| {
                    if let Inbound::Event(Event::Result { status, result, .. }) = e {
                        assert_eq!(status, RequestStatus::SentOk);
                        assert_eq!(result, Some(ResultCode::STARTING));
                        results += 1;
                    }
                })
                .await?;
            while let Some(wait) = host.launcher_mut().take_reaped() {
                assert_eq!(wait.exit, gnunet_arm_host::launch::ChildExit::Exited(0));
                reaped += 1;
            }
        }
        host.disconnect(|_, _| panic!("duplicate callback"))?;
        Ok(())
    })
}
#[test]
fn canceled_unperformed_local_setup_creates_no_child_and_missing_helper_is_real_setup_failure()
-> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let c = cfg(&dir, Some(fixture()?.as_path()), b"")?;
        let mut registry = ChildRegistry::new(4)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 512];
        let launcher = LocalLauncher::new(
            c.duplicate()?,
            dir.0.join("missing-helper"),
            LaunchLimits::default(),
            &mut registry,
        )?;
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            c.duplicate()?,
            domain.resolution(),
            launcher,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let canceled = host.request_service_start(b"arm", StdioInheritance(0))?;
        host.operation_cancel(canceled)?;
        for _ in 0..3 {
            let _ = host
                .drive(Some(Instant::now() + Duration::from_millis(1)), |_, _| {
                    panic!("canceled setup callback")
                })
                .await?;
        }
        assert_eq!(host.launcher_mut().pending_children(), 0);
        assert!(host.launcher_mut().take_error().is_none());
        host.request_service_start(b"arm", StdioInheritance(0))?;
        assert_eq!(
            result(&mut host).await?,
            (RequestStatus::SentOk, Some(ResultCode::START_FAILED))
        );
        assert_eq!(host.launcher_mut().pending_children(), 0);
        let error = host
            .launcher_mut()
            .take_error()
            .ok_or("missing actual spawn errno")?;
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        host.disconnect(|_, _| panic!("duplicate callback"))?;
        Ok(())
    })
}
#[test]
fn quiet_connected_mq_and_unbounded_drive_wake_on_owned_child_exit_to_release_registry_credit()
-> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::UnixListener,
            sync::oneshot,
        };
        let dir = Dir::new()?;
        let endpoint = dir.0.join("quiet.sock");
        let listener = UnixListener::bind(&endpoint)?;
        let (ready, mut established) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let mut test = [0; 4];
            s.read_exact(&mut test).await?;
            assert_eq!(&test, b"\0\x04\0\x0f");
            ready
                .send(())
                .map_err(|_| io::Error::other("owner closed"))?;
            // The actual MQ remains established and quiet. Deliberately no TEST
            // confirmation, so the already admitted local ARM requests stay local.
            assert_eq!(s.read(&mut [0]).await?, 0);
            s.shutdown().await?;
            Ok::<_, io::Error>(())
        });
        let mut c = cfg(
            &dir,
            Some(fixture()?.as_path()),
            format!(
                "--output {} --release-before-wait --hold-ms 150",
                dir.0.join("quiet-credit").display()
            )
            .as_bytes(),
        )?;
        c.set_value(
            b"arm",
            b"UNIXPATH",
            Some(endpoint.as_os_str().as_encoded_bytes()),
        )?;
        let mut registry = ChildRegistry::new(1)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 512];
        let launcher = LocalLauncher::new(
            c.duplicate()?,
            PathBuf::from(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
            LaunchLimits {
                max_children: 1,
                ..LaunchLimits::default()
            },
            &mut registry,
        )?;
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            c.duplicate()?,
            domain.resolution(),
            launcher,
            Limits {
                max_startup_signals: 1,
                ..Limits::default()
            },
            Clock::system()?,
            |_| panic!(),
        )?;
        host.request_service_start(b"arm", StdioInheritance(0))?;
        host.request_service_start(b"arm", StdioInheritance(0))?;
        let mut results = 0;
        let mut reaped = 0;
        let mut mq_ready = false;
        while results != 2 || reaped != 2 {
            timeout(
                Duration::from_secs(1),
                host.drive(None, |event, _| {
                    if let Inbound::Event(Event::Result { status, result, .. }) = event {
                        assert_eq!(status, RequestStatus::SentOk);
                        assert_eq!(result, Some(ResultCode::STARTING));
                        results += 1;
                    }
                }),
            )
            .await??;
            if !mq_ready {
                mq_ready = established.try_recv().is_ok();
            }
            while let Some(wait) = host.launcher_mut().take_reaped() {
                assert!(
                    mq_ready,
                    "socket retry/timer must not be the child wake source"
                );
                assert_eq!(wait.exit, gnunet_arm_host::launch::ChildExit::Exited(0));
                reaped += 1;
            }
        }
        assert!(!host.currently_up());
        host.disconnect(|_, _| panic!("duplicate result"))?;
        peer.await??;
        Ok(())
    })
}
#[test]
fn registry_echild_retires_original_pid_once_without_fabricating_wait_success() -> Test {
    const CHILD: &str = "GNUNET_ARM_OWNED_REGISTRY_ECHILD_TEST";
    if std::env::var_os(CHILD).is_none() {
        let run = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "registry_echild_retires_original_pid_once_without_fabricating_wait_success",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()?;
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(String::from_utf8_lossy(&run.stdout).contains("original_echild_retired=true"));
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let c = cfg(
            &dir,
            Some(fixture()?.as_path()),
            format!(
                "--output {} --hold-ms 20",
                dir.0.join("lost-authority").display()
            )
            .as_bytes(),
        )?;
        let mut registry = ChildRegistry::new(1)?;
        let mut ops = [OperationSlot::EMPTY; 2];
        let mut slots = [FrameSlot::EMPTY; 4];
        let mut pool = [0; 128];
        {
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                c.duplicate()?,
                domain.resolution(),
                launch(&c, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            host.request_service_start(b"arm", StdioInheritance(0))?;
            while host.launcher_mut().pending_children() == 0 {
                host.drive(None, |_, _| panic!("early callback")).await?;
            }
        }
        let raw = registry.child_pids().next().ok_or("original PID missing")?;
        let pid = nix::unistd::Pid::from_raw(i32::try_from(raw)?);
        // Deliberately violate only this fresh exec's registry wait contract to
        // verify a defensive ownership-loss boundary; the PID is its own child.
        assert_eq!(
            nix::sys::wait::waitpid(pid, None)?,
            nix::sys::wait::WaitStatus::Exited(pid, 0)
        );
        let error = match registry.reap_completed() {
            Err(error) => error,
            Ok(_) => return Err("consumed child cannot yield a new exit".into()),
        };
        let gnunet_arm_host::launch::LaunchError::Io(error) = error else {
            panic!("expected native ECHILD")
        };
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        assert_eq!(registry.pending_children(), 0);
        assert!(registry.child_pids().next().is_none());
        assert!(registry.take_reaped().is_none());
        assert_eq!(registry.reap_completed()?, 0);
        writeln!(io::stdout().lock(), "original_echild_retired=true")?;
        Ok(())
    })
}

#[test]
fn live_configuration_is_sampled_when_local_setup_begins_and_never_replays_created_child() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let trace = dir.0.join("live-local");
        let initial = cfg(&dir, None, b"")?;
        let live = gnunet_arm_host::LiveConfiguration::new(initial.duplicate()?);
        let mut registry = ChildRegistry::new(4)?;
        let mut operations = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut bytes = [0; 512];
        let launcher = launch(&initial, &mut registry)?;
        let mut host = ClientHost::connect_live(
            core(&mut operations, &mut slots, &mut bytes)?,
            live.clone(),
            domain.resolution(),
            launcher,
            Limits::default(),
            Clock::system()?,
            |_| panic!("initial config invalid"),
        )?;
        let original = host.request_service_start(b"arm", StdioInheritance(0))?;
        let executable = cfg(
            &dir,
            Some(fixture()?.as_path()),
            format!("--output {} --hold-ms 40", trace.display()).as_bytes(),
        )?;
        live.replace(executable)?;
        let until = Instant::now() + Duration::from_secs(2);
        while host.launcher_mut().pending_children() == 0 {
            assert_ne!(
                host.drive(Some(until), |_, _| panic!("result before actual spawn"))
                    .await?,
                Progress::WaitDeadline
            );
        }
        live.replace(initial)?;
        let mut original_results = 0;
        loop {
            let mut done = false;
            assert_ne!(
                host.drive(Some(until), |event, _| {
                    if let Inbound::Event(Event::Result {
                        operation,
                        status,
                        result,
                    }) = event
                    {
                        assert_eq!(operation, original);
                        assert_eq!(status, RequestStatus::SentOk);
                        assert_eq!(result, Some(ResultCode::STARTING));
                        original_results += 1;
                        done = true;
                    }
                })
                .await?,
                Progress::WaitDeadline
            );
            if done {
                break;
            }
        }
        assert_eq!(original_results, 1);
        assert!(std::fs::read_to_string(&trace)?.contains("started"));
        host.request_service_start(b"arm", StdioInheritance(0))?;
        assert_eq!(
            result(&mut host).await?,
            (RequestStatus::SentOk, Some(ResultCode::IS_NOT_KNOWN))
        );
        timeout(Duration::from_secs(2), host.launcher_mut().drain_children()).await??;
        let mut exits = 0;
        while let Some(wait) = host.launcher_mut().take_reaped() {
            assert_eq!(wait.exit, gnunet_arm_host::launch::ChildExit::Exited(0));
            exits += 1;
        }
        assert_eq!(exits, 1);
        host.disconnect(|_, _| panic!("original result replayed"))?;
        Ok(())
    })
}
