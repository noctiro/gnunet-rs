//! Actual local ARM IPC/process/readiness witnesses using the shared native port.
#![expect(
    clippy::expect_used,
    reason = "Finite owned-resource fixtures require each actual setup/result"
)]
#![expect(
    clippy::panic,
    reason = "Unexpected native/wire state is a finite witness failure"
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite actual native outcome assertions fail the witness while setup errors propagate"
)]
use gnunet_arm_core::wire::{
    ArmAbi, List, MonitorStatus, Request, ResultCode, ResultReply, ServiceInfo, ServiceStatus,
    Status, WireId,
};
use gnunet_arm_service_core::{
    ClientSlot, FrameSlot, ListenerSlot, Owner, OwnerScope, Phase, ServiceSlot,
};
use gnunet_arm_service_host::{
    addresses::Address,
    listeners::ManagedListeners,
    reactor::{Clock, Driver, Error, Limits, State, SystemClock},
    registry::{self, Registry},
};
use gnunet_config::{BinaryPathCache, Configuration, ProjectData};
use gnunet_service_runtime::service::ServiceOptions;
use gnunet_service_runtime::{
    Activation, BoundListeners,
    process::{ChildRegistry, EnvironmentSnapshot},
};
use std::{
    cell::Cell,
    error::Error as StdError,
    ffi::OsString,
    future::Future,
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};
type Test = Result<(), Box<dyn StdError>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let p = PathBuf::from("/private/tmp").join(format!(
            "arm-react-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
struct Children(ChildRegistry);
impl Drop for Children {
    fn drop(&mut self) {
        for child in self.0.children().cloned().collect::<Vec<_>>() {
            drop(self.0.signal(&child, libc::SIGKILL));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.0.pending_children() > 0 && Instant::now() < deadline {
            drop(self.0.reap_completed());
            while self.0.take_reaped().is_some() {}
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn helper() -> &'static Path {
    static HELPER: OnceLock<PathBuf> = OnceLock::new();
    HELPER
        .get_or_init(|| {
            std::env::current_exe()
                .expect("current actual test executable")
                .parent()
                .and_then(Path::parent)
                .expect("Cargo target debug directory")
                .join("gnunet-arm-spawn-helper")
        })
        .as_path()
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn fixture() -> Result<PathBuf, Box<dyn StdError>> {
    static BUILT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let p = PathBuf::from("/private/tmp")
                .join(format!("arm-react-child-{}", std::process::id()));
            let source =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/process_fixture.c");
            let out = std::process::Command::new("cc")
                .arg(source)
                .args(["-Wall", "-Wextra", "-Werror"])
                .arg("-o")
                .arg(&p)
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).into_owned());
            }
            Ok(p)
        })
        .clone()
        .map_err(Into::into)
}
fn config(directory: &Directory) -> Configuration {
    let mut c = Configuration::default();
    for (k, v) in [
        (
            b"UNIXPATH".as_slice(),
            directory.0.join("arm.sock").as_os_str().as_bytes(),
        ),
        (b"START_USER_SERVICES", b"YES"),
        (b"START_SYSTEM_SERVICES", b"NO"),
    ] {
        c.set_value(b"arm", k, Some(v)).expect("owned config");
    }
    c
}
fn add(c: &mut Configuration, name: &[u8], binary: &Path, mode: &[u8], control: bool) {
    for (k, v) in [
        (b"TYPE".as_slice(), b"SIMPLE".as_slice()),
        (b"BINARY", b"/different/unexecuted/argv0"),
        (b"PREFIX", binary.as_os_str().as_bytes()),
        (b"OPTIONS", mode),
        (b"RUN_PER_USER", b"YES"),
        (b"PIPECONTROL", if control { b"YES" } else { b"NO" }),
    ] {
        c.set_value(name, k, Some(v)).expect("fixture service");
    }
}
fn environment(directory: &Directory, mode: &str) -> EnvironmentSnapshot {
    EnvironmentSnapshot::from_values(
        [
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (
                OsString::from("GNUNET_PROCESS_TEST_OUTPUT"),
                directory.0.join("trace").into_os_string(),
            ),
            (
                OsString::from("GNUNET_PROCESS_TEST_MODE"),
                OsString::from(mode),
            ),
            (
                OsString::from("GNUNET_PROCESS_TEST_HOLD_MS"),
                OsString::from("2000"),
            ),
        ],
        directory.0.clone(),
    )
    .expect("explicit child environment")
}
fn registry(c: &Configuration, e: &EnvironmentSnapshot) -> Registry {
    Registry::from_config(
        c,
        e,
        &ProjectData::default(),
        &mut BinaryPathCache::new(),
        registry::Limits::default(),
    )
    .expect("source registry")
}
fn row() -> ServiceInfo<'static> {
    ServiceInfo {
        name: b"",
        binary: b"",
        status: ServiceStatus::STOPPED,
        last_exit_status: 0,
        restart_at: 0,
        last_started_at: 0,
    }
}
fn encoded(request: Request<'_>) -> Vec<u8> {
    let mut b = vec![0; request.encoded_len().expect("request length")];
    request.encode(&mut b).expect("official request");
    b
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&header);
    stream.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn alongside<C: Clock, F: Future>(
    driver: &mut Driver<'_, '_, '_, '_, '_, C>,
    future: F,
) -> Result<F::Output, Error> {
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(output) = future.as_mut().poll(cx) {
            return Poll::Ready(Ok(output));
        }
        match driver.poll_drive(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
async fn reply<C: Clock>(
    driver: &mut Driver<'_, '_, '_, '_, '_, C>,
    peer: &mut UnixStream,
) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), alongside(driver, frame(peer)))
        .await
        .expect("bounded actual frame")
        .expect("driver progress")
        .expect("stream frame")
}
async fn pump<C: Clock>(
    driver: &mut Driver<'_, '_, '_, '_, '_, C>,
    predicate: impl Fn(&Driver<'_, '_, '_, '_, '_, C>) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate(driver) {
        assert!(Instant::now() < deadline, "actual host condition deadline");
        match tokio::time::timeout(Duration::from_millis(5), driver.drive()).await {
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(e)) => panic!("driver error: {e}"),
        }
    }
}
async fn shutdown<C: Clock>(driver: &mut Driver<'_, '_, '_, '_, '_, C>) {
    driver.shutdown();
    pump(driver, |d| d.phase() == Phase::Closed).await;
}
macro_rules! owners {
    ($registry:ident,$managed:ident,$scope:ident,$slots:ident,$clients:ident,$ls:ident,$bytes:ident,$frames:ident,$owner:ident) => {
        let specs = $registry.specs();
        let mut $scope = OwnerScope::new();
        let mut $slots = (0..specs.len())
            .map(|_| ServiceSlot::new())
            .collect::<Vec<_>>();
        let mut $clients = (0..8).map(|_| ClientSlot::new()).collect::<Vec<_>>();
        let mut $ls = (0..$managed.len())
            .map(|_| ListenerSlot::new())
            .collect::<Vec<_>>();
        let mut $bytes = (0..32).map(|_| vec![0; 65535]).collect::<Vec<_>>();
        let mut $frames = $bytes
            .iter_mut()
            .map(|b| FrameSlot::new(b))
            .collect::<Vec<_>>();
        let mut $owner = Owner::new(
            &mut $scope,
            &specs,
            &mut $slots,
            &mut $clients,
            &mut $ls,
            &mut $frames,
            ArmAbi::U64Align8,
        )
        .expect("bounded formal owner");
    };
}
#[test]
fn actual_control_unix_test_list_fragment_cancel_unknown_and_malformed_eof() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let c = config(&dir);
        let env = environment(&dir, "hold-control");
        let registry = registry(&c, &env);
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let limits = Limits {
            io_slice: 1,
            ..Limits::default()
        };
        let mut state = State::new(control, limits)?;
        let mut rows = [];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        let mut peer = UnixStream::connect(dir.0.join("arm.sock")).await?;
        pump(&mut driver, |d| d.client_count() == 1).await;
        let test = encoded(Request::Test);
        peer.write_all(&test[..2]).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), async {
                loop {
                    driver.drive().await.expect("partial ordinary progress");
                }
            })
            .await
            .is_err()
        );
        peer.write_all(&test[2..]).await?;
        assert_eq!(reply(&mut driver, &mut peer).await, test);
        peer.write_all(&[0, 4, 253, 232]).await?;
        peer.write_all(&encoded(Request::List {
            reserved: 7,
            id: WireId(91),
        }))
        .await?;
        let b = reply(&mut driver, &mut peer).await;
        let list = List::decode(ArmAbi::U64Align8, &b)?;
        assert!(list.is_empty());
        assert_eq!(list.id()?, WireId(91));
        peer.write_all(&[0, 3, 0, 0]).await?;
        let mut one = [0];
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                alongside(&mut driver, peer.read(&mut one))
            )
            .await???,
            0
        );
        assert_eq!(driver.client_count(), 0);
        shutdown(&mut driver).await;
        assert!(!dir.0.join("arm.sock").exists());
        Ok(())
    })
}
#[test]
fn actual_spawn_monitor_spelling_pipe_term_consuming_reap_and_original_argv0() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"running", &fixture()?, b"control", true);
        let env = environment(&dir, "control");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        let mut monitor = UnixStream::connect(dir.0.join("arm.sock")).await?;
        monitor.write_all(&encoded(Request::Monitor)).await?;
        assert_eq!(
            Status::decode(&reply(&mut driver, &mut monitor).await)?.status,
            MonitorStatus::MONITORING_STARTED
        );
        let mut peer = UnixStream::connect(dir.0.join("arm.sock")).await?;
        peer.write_all(&encoded(Request::Start {
            reserved: 3,
            id: WireId(1),
            service: b"RuNnInG",
        }))
        .await?;
        let result = ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut peer).await)?;
        assert_eq!(result.result, ResultCode::STARTING);
        assert_eq!(
            Status::decode(&reply(&mut driver, &mut monitor).await)?.service,
            b"running"
        );
        pump(&mut driver, |_| {
            std::fs::read_to_string(dir.0.join("trace")).is_ok_and(|s| s.contains("ready=1"))
        })
        .await;
        peer.write_all(&encoded(Request::Stop {
            reserved: 0,
            id: WireId(2),
            service: b"RuNnInG",
        }))
        .await?;
        let status = reply(&mut driver, &mut monitor).await;
        let status = Status::decode(&status)?;
        assert_eq!(status.status, MonitorStatus::STOPPING);
        assert_eq!(status.service, b"RuNnInG");
        let result = ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut peer).await)?;
        assert_eq!(result.id, WireId(2));
        assert_eq!(result.result, ResultCode::STOPPED);
        let status = reply(&mut driver, &mut monitor).await;
        assert_eq!(Status::decode(&status)?.status, MonitorStatus::STOPPED);
        assert_eq!(driver.counters().spawned, 1);
        assert_eq!(driver.counters().reaped, 1);
        assert_eq!(driver.counters().term_attempts, 1);
        let trace = std::fs::read_to_string(dir.0.join("trace"))?;
        assert!(trace.contains("arg0=2f646966666572656e742f756e65786563757465642f6172677630"));
        assert!(trace.contains("control=15"));
        shutdown(&mut driver).await;
        Ok(())
    })
}
#[test]
fn actual_two_listener_demand_preserves_kernel_queues_until_original_child_accepts() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"echo", &fixture()?, b"accept", false);
        let env = environment(&dir, "accept");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(2);
        assert!(matches!(
            managed
                .bind_address(0, Address::Unix(dir.0.join("service.sock")), 0o700)
                .map_err(Error::Listener)?,
            gnunet_arm_service_host::listeners::BindOutcome::Bound { .. }
        ));
        assert!(matches!(
            managed
                .bind_address(0, Address::Tcp("127.0.0.1:0".parse()?), 0o700)
                .map_err(Error::Listener)?,
            gnunet_arm_service_host::listeners::BindOutcome::Bound { .. }
        ));
        let tcp = match managed.address(1) {
            Some(Address::Tcp(a)) => *a,
            _ => panic!("actual bound TCP"),
        };
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        let mut unix = UnixStream::connect(dir.0.join("service.sock")).await?;
        unix.write_all(b"queue").await?;
        let mut tcp = TcpStream::connect(tcp).await?;
        tcp.write_all(b"queue").await?;
        let mut u = [0; 11];
        let mut t = [0; 11];
        tokio::time::timeout(
            Duration::from_secs(3),
            alongside(&mut driver, async {
                unix.read_exact(&mut u).await?;
                tcp.read_exact(&mut t).await?;
                io::Result::Ok(())
            }),
        )
        .await???;
        assert_eq!(&u, b"child:queue");
        assert_eq!(&t, b"child:queue");
        pump(&mut driver, |d| d.counters().reaped == 1).await;
        assert_eq!(driver.counters().spawned, 1);
        let trace = std::fs::read_to_string(dir.0.join("trace"))?;
        assert!(trace.contains("accepted=2"));
        shutdown(&mut driver).await;
        assert!(!dir.0.join("service.sock").exists());
        Ok(())
    })
}
struct FaultClock {
    fail: Rc<Cell<bool>>,
}
impl Clock for FaultClock {
    fn utc(&mut self) -> io::Result<u64> {
        if self.fail.get() {
            Err(io::Error::other("owned clock failure"))
        } else {
            SystemClock.utc()
        }
    }
}
#[test]
fn admitted_child_and_lease_survive_clock_error_and_driver_reborrow() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"running", &fixture()?, b"hold-control", true);
        c.set_value(b"running", b"IMMEDIATE_START", Some(b"YES"))?;
        c.set_value(b"running", b"NOARMBIND", Some(b"YES"))?;
        let env = environment(&dir, "hold-control");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row()];
        let flag = Rc::new(Cell::new(true));
        let mut clock = FaultClock { fail: flag.clone() };
        let options = ServiceOptions::default();
        {
            let mut driver = Driver::new(
                &mut owner,
                &registry,
                &mut managed,
                &mut children.0,
                &mut state,
                &c,
                helper(),
                &env,
                &options,
                &mut rows,
                &mut clock,
            )?;
            assert!(matches!(driver.drive().await, Err(Error::Clock(_))));
            assert_eq!(driver.counters().spawned, 1);
        }
        assert_eq!(children.0.child_pids().count(), 1);
        assert_eq!(state.children().count(), 1);
        flag.set(false);
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        assert_eq!(driver.counters().spawned, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), driver.drive())
                .await
                .is_err()
        );
        shutdown(&mut driver).await;
        assert_eq!(driver.counters().reaped, 1);
        Ok(())
    })
}
#[test]
fn actual_host_child_capacity_refusal_has_no_ghost_and_does_not_block_original_term_or_reap() -> Test
{
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"first", &fixture()?, b"control", true);
        add(&mut c, b"second", &fixture()?, b"control", true);
        let env = environment(&dir, "control");
        let mut children = Children(ChildRegistry::new(1)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut limits = Limits::default();
        limits.process.launch.max_children = 1;
        let mut state = State::new(control, limits)?;
        let mut rows = [row(), row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        let mut peer = UnixStream::connect(dir.0.join("arm.sock")).await?;
        peer.write_all(&encoded(Request::Start {
            reserved: 0,
            id: WireId(1),
            service: b"first",
        }))
        .await?;
        assert_eq!(
            ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut peer).await)?.result,
            ResultCode::STARTING
        );
        pump(&mut driver, |_| {
            std::fs::read_to_string(dir.0.join("trace")).is_ok_and(|s| s.contains("ready=1"))
        })
        .await;
        peer.write_all(&encoded(Request::Start {
            reserved: 0,
            id: WireId(2),
            service: b"second",
        }))
        .await?;
        let result = ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut peer).await)?;
        assert_eq!(result.id, WireId(2));
        assert_eq!(result.result, ResultCode::START_FAILED);
        assert_eq!(driver.counters().spawned, 1);
        assert_eq!(driver.counters().spawn_refused, 1);
        assert!(matches!(
            driver.take_diagnostic(),
            Some(gnunet_arm_service_host::reactor::Diagnostic::Admission(
                Error::AdmissionCapacity
            ))
        ));
        peer.write_all(&encoded(Request::Stop {
            reserved: 0,
            id: WireId(3),
            service: b"first",
        }))
        .await?;
        assert_eq!(
            ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut peer).await)?.result,
            ResultCode::STOPPED
        );
        assert_eq!(driver.counters().reaped, 1);
        peer.write_all(&encoded(Request::Start {
            reserved: 0,
            id: WireId(4),
            service: b"second",
        }))
        .await?;
        assert_eq!(
            ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut peer).await)?.result,
            ResultCode::STARTING
        );
        assert_eq!(driver.counters().spawned, 2);
        shutdown(&mut driver).await;
        assert_eq!(driver.counters().reaped, 2);
        Ok(())
    })
}
#[test]
fn actual_nonzero_exit_restarts_at_idle_and_final_shutdown_cancels_the_original_timer() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"repeat", &fixture()?, b"exit1", false);
        c.set_value(b"repeat", b"IMMEDIATE_START", Some(b"YES"))?;
        c.set_value(b"repeat", b"NOARMBIND", Some(b"YES"))?;
        let env = environment(&dir, "exit1");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.counters().reaped >= 3).await;
        assert!(driver.counters().spawned >= 3);
        assert!(driver.service_info(0)?.backoff >= 2000);
        shutdown(&mut driver).await;
        let count = driver.counters().spawned;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            driver.drive().await?,
            gnunet_arm_service_host::reactor::Activity::Closed
        );
        assert_eq!(driver.counters().spawned, count);
        assert_eq!(driver.counters().reaped, count);
        Ok(())
    })
}
#[test]
fn empty_registry_driver_reborrow_rejects_foreign_owner_without_touching_original_stream() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let c = config(&dir);
        let env = environment(&dir, "hold-control");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        {
            let mut driver = Driver::new(
                &mut owner,
                &registry,
                &mut managed,
                &mut children.0,
                &mut state,
                &c,
                helper(),
                &env,
                &options,
                &mut rows,
                &mut clock,
            )?;
            pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        }
        let mut foreign_scope = OwnerScope::new();
        let mut foreign_clients = [ClientSlot::new()];
        let mut foreign = Owner::new(
            &mut foreign_scope,
            &[],
            &mut [],
            &mut foreign_clients,
            &mut [],
            &mut [],
            ArmAbi::U64Align8,
        )
        .map_err(Error::Core)?;
        assert!(matches!(
            Driver::new(
                &mut foreign,
                &registry,
                &mut managed,
                &mut children.0,
                &mut state,
                &c,
                helper(),
                &env,
                &options,
                &mut rows,
                &mut clock
            ),
            Err(Error::Mapping)
        ));
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        let mut peer = UnixStream::connect(dir.0.join("arm.sock")).await?;
        let test = encoded(Request::Test);
        peer.write_all(&test).await?;
        assert_eq!(reply(&mut driver, &mut peer).await, test);
        shutdown(&mut driver).await;
        Ok(())
    })
}
#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "Explicitly end the borrowed view to inspect external persisted socket ownership"
)]
fn late_control_admission_survives_real_child_drain_and_persisted_requester_closes_on_owner_drop()
-> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"slow", &fixture()?, b"hold-control", true);
        c.set_value(b"slow", b"IMMEDIATE_START", Some(b"YES"))?;
        c.set_value(b"slow", b"NOARMBIND", Some(b"YES"))?;
        let env = environment(&dir, "hold-control");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| {
            d.phase() == Phase::Serving
                && std::fs::read_to_string(dir.0.join("trace")).is_ok_and(|s| s.contains("ready=1"))
        })
        .await;
        let mut requester = UnixStream::connect(dir.0.join("arm.sock")).await?;
        requester
            .write_all(&encoded(Request::Stop {
                reserved: 0,
                id: WireId(1),
                service: b"ARM",
            }))
            .await?;
        pump(&mut driver, |d| d.phase() == Phase::Draining).await;
        assert!(dir.0.join("arm.sock").exists());
        let stopping =
            ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut requester).await)?;
        assert_eq!(stopping.result, ResultCode::STOPPING);
        let mut late = UnixStream::connect(dir.0.join("arm.sock")).await?;
        late.write_all(&encoded(Request::Test)).await?;
        assert_eq!(reply(&mut driver, &mut late).await, encoded(Request::Test));
        late.write_all(&encoded(Request::Start {
            reserved: 0,
            id: WireId(2),
            service: b"missing",
        }))
        .await?;
        assert_eq!(
            ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut late).await)?.result,
            ResultCode::IN_SHUTDOWN
        );
        pump(&mut driver, |d| d.phase() == Phase::Closed).await;
        assert_eq!(driver.counters().reaped, 1);
        assert!(!dir.0.join("arm.sock").exists());
        drop(driver);
        assert_eq!(state.persisted_count(), 1);
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), requester.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), late.read(&mut byte)).await??,
            0
        );
        drop(state);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), requester.read(&mut byte)).await??,
            0
        );
        Ok(())
    })
}
#[test]
fn expired_idle_restart_does_not_overtake_actual_fragmented_control_rx_or_nonempty_tx() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"repeat", &fixture()?, b"exit1", false);
        c.set_value(b"repeat", b"IMMEDIATE_START", Some(b"YES"))?;
        c.set_value(b"repeat", b"NOARMBIND", Some(b"YES"))?;
        let env = environment(&dir, "exit1");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(
            control,
            Limits {
                io_slice: 1,
                ..Limits::default()
            },
        )?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        let mut peer = UnixStream::connect(dir.0.join("arm.sock")).await?;
        pump(&mut driver, |d| {
            d.phase() == Phase::Serving && d.client_count() == 1 && d.counters().reaped == 1
        })
        .await;
        assert_eq!(driver.counters().timer_callbacks, 0);
        peer.write_all(&encoded(Request::Test)).await?;
        assert_eq!(reply(&mut driver, &mut peer).await, encoded(Request::Test));
        assert_eq!(driver.counters().spawned, 1);
        assert_eq!(driver.counters().timer_callbacks, 0);
        pump(&mut driver, |d| d.counters().spawned >= 2).await;
        assert!(driver.counters().timer_callbacks >= 1);
        shutdown(&mut driver).await;
        Ok(())
    })
}
struct FixedClock(Rc<Cell<u64>>);
impl Clock for FixedClock {
    fn utc(&mut self) -> io::Result<u64> {
        Ok(self.0.get())
    }
}
#[test]
fn actual_idle_registration_survives_backward_utc_and_uses_original_absolute_target_after_forward_jump()
-> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"repeat", &fixture()?, b"exit1", false);
        c.set_value(b"repeat", b"IMMEDIATE_START", Some(b"YES"))?;
        c.set_value(b"repeat", b"NOARMBIND", Some(b"YES"))?;
        let env = environment(&dir, "exit1");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row()];
        let now = Rc::new(Cell::new(10_000_000_000));
        let mut clock = FixedClock(now.clone());
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| {
            d.counters().reaped == 1 && d.counters().timer_callbacks == 1
        })
        .await;
        let original = driver.service_info(0)?.restart_at;
        assert!(original > now.get());
        assert_eq!(driver.counters().timer_callbacks, 1);
        now.set(now.get() - 1_000_000);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), async {
                loop {
                    driver.drive().await.expect("retained timer hint");
                }
            })
            .await
            .is_err()
        );
        assert_eq!(driver.counters().spawned, 1);
        assert_eq!(driver.counters().timer_callbacks, 1);
        now.set(original);
        pump(&mut driver, |d| d.counters().spawned == 2).await;
        assert_eq!(driver.counters().timer_callbacks, 2);
        assert_eq!(driver.service_info(0)?.last_started, original);
        shutdown(&mut driver).await;
        Ok(())
    })
}
#[test]
fn every_managed_unix_path_is_closed_before_any_actual_control_term_byte() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        for name in [b"first".as_slice(), b"second"] {
            add(&mut c, name, &fixture()?, b"control", true);
            c.set_value(name, b"IMMEDIATE_START", Some(b"YES"))?;
        }
        let paths = format!(
            "{}:{}",
            dir.0.join("one.sock").display(),
            dir.0.join("two.sock").display()
        );
        let env = EnvironmentSnapshot::from_values(
            [
                (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                (
                    OsString::from("GNUNET_PROCESS_TEST_OUTPUT"),
                    dir.0.join("trace").into_os_string(),
                ),
                (
                    OsString::from("GNUNET_PROCESS_TEST_MODE"),
                    OsString::from("control"),
                ),
                (
                    OsString::from("GNUNET_PROCESS_TEST_CLOSED_PATHS"),
                    OsString::from(paths),
                ),
            ],
            dir.0.clone(),
        )?;
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(2);
        for (index, name) in ["one.sock", "two.sock"].into_iter().enumerate() {
            assert!(matches!(
                managed
                    .bind_address(index, Address::Unix(dir.0.join(name)), 0o700)
                    .map_err(Error::Listener)?,
                gnunet_arm_service_host::listeners::BindOutcome::Bound { .. }
            ));
        }
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row(), row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| {
            d.phase() == Phase::Serving
                && std::fs::read_to_string(dir.0.join("trace"))
                    .is_ok_and(|s| s.matches("ready=1").count() == 2)
        })
        .await;
        assert!(dir.0.join("one.sock").exists() && dir.0.join("two.sock").exists());
        shutdown(&mut driver).await;
        assert_eq!(driver.counters().spawned, 2);
        assert_eq!(driver.counters().term_attempts, 2);
        assert_eq!(driver.counters().reaped, 2);
        let trace = std::fs::read_to_string(dir.0.join("trace"))?;
        assert_eq!(trace.matches("paths-closed=2").count(), 2);
        assert_eq!(trace.matches("control=15").count(), 2);
        Ok(())
    })
}
#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "Explicitly discard and reconstruct the driver borrow while actual partial TX stays in external State"
)]
fn canceled_drive_retains_real_partial_list_tx_and_blocked_peer_does_not_block_other_control()
-> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"large", &fixture()?, b"none", false);
        let binary = vec![b'x'; 60000];
        c.set_value(b"large", b"BINARY", Some(&binary))?;
        let env = environment(&dir, "none");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(
            control,
            Limits {
                io_slice: 512,
                ..Limits::default()
            },
        )?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        let (server, mut blocked) = UnixStream::pair()?;
        socket2::SockRef::from(&server).set_send_buffer_size(1024)?;
        assert!(driver.admit(
            gnunet_service_runtime::connection::Connection::from_unix(server),
            gnunet_service_runtime::service::PeerAddress::Unix
        )?);
        blocked
            .write_all(&encoded(Request::List {
                reserved: 0,
                id: WireId(77),
            }))
            .await?;
        pump(&mut driver, |d| d.counters().handed_off == 1).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), async {
                loop {
                    driver.drive().await.expect("partial actual TX progress");
                }
            })
            .await
            .is_err()
        );
        drop(driver);
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        let mut other = UnixStream::connect(dir.0.join("arm.sock")).await?;
        other.write_all(&encoded(Request::Test)).await?;
        assert_eq!(reply(&mut driver, &mut other).await, encoded(Request::Test));
        let bytes = reply(&mut driver, &mut blocked).await;
        let listing = List::decode(ArmAbi::U64Align8, &bytes)?;
        assert_eq!(listing.id()?, WireId(77));
        assert_eq!(listing.get(0)?.expect("original row").binary, binary);
        assert_eq!(driver.counters().handed_off, 2);
        shutdown(&mut driver).await;
        Ok(())
    })
}
#[test]
fn dedicated_registry_rejects_foreign_live_child_and_returns_foreign_actual_completion_without_core_reap()
-> Test {
    runtime()?.block_on(async {
        use gnunet_service_runtime::process::{self, NativeCommand, ProcessLimits, SpawnResult};
        let dir = Directory::new()?;
        let c = config(&dir);
        let env = environment(&dir, "none");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let target = fixture()?;
        let command = NativeCommand {
            filename: target.into_os_string(),
            argv: vec![OsString::from("foreign-argv")],
            environment: env.clone(),
            environment_changes: Vec::new(),
            cwd: None,
            stdio: 6,
            stdio_snapshot: None,
            listeners: Vec::new(),
            mappings: Vec::new(),
        };
        let SpawnResult::Admitted(foreign) = process::spawn(
            &c,
            helper(),
            command,
            ProcessLimits::default(),
            &mut children.0,
        )?
        else {
            panic!("actual foreign fixture admission");
        };
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        assert!(matches!(
            Driver::new(
                &mut owner,
                &registry,
                &mut managed,
                &mut children.0,
                &mut state,
                &c,
                helper(),
                &env,
                &options,
                &mut rows,
                &mut clock
            ),
            Err(Error::Mapping)
        ));
        assert!(children.0.owns(&foreign.child));
        let until = Instant::now() + Duration::from_secs(3);
        while children.0.owns(&foreign.child) {
            assert!(Instant::now() < until);
            children.0.reap_completed()?;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        let error = driver
            .drive()
            .await
            .expect_err("unrelated completed credit is not this daemon child");
        let Error::ForeignCompletion(receipt) = error else {
            panic!("actual foreign completion receipt");
        };
        assert_eq!(receipt.child, foreign.child);
        assert_eq!(
            receipt.exit,
            gnunet_service_runtime::process::ChildExit::Exited(0)
        );
        assert_eq!(driver.counters().reaped, 0);
        shutdown(&mut driver).await;
        Ok(())
    })
}

#[test]
fn ready_clients_and_each_stream_direction_progress_before_an_earlier_backlog_drains() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let c = config(&dir);
        let env = environment(&dir, "hold-control");
        let registry = registry(&c, &env);
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        let (first, mut first_peer) = UnixStream::pair()?;
        let (second, mut second_peer) = UnixStream::pair()?;
        assert!(driver.admit(
            gnunet_service_runtime::connection::Connection::from_unix(first),
            gnunet_service_runtime::service::PeerAddress::Unix
        )?);
        assert!(driver.admit(
            gnunet_service_runtime::connection::Connection::from_unix(second),
            gnunet_service_runtime::service::PeerAddress::Unix
        )?);
        first_peer
            .write_all(&encoded(Request::Test).repeat(32))
            .await?;
        second_peer
            .write_all(&encoded(Request::List {
                reserved: 0,
                id: WireId(0x73),
            }))
            .await?;
        for _ in 0..8 {
            let _activity = tokio::time::timeout(Duration::from_secs(1), driver.drive()).await??;
        }
        assert!(
            driver.counters().received < 32,
            "the first client's finite backlog must still be present"
        );
        let second =
            tokio::time::timeout(Duration::from_millis(100), frame(&mut second_peer)).await;
        assert!(
            second.is_ok(),
            "a ready second client must progress before an earlier backlog drains"
        );
        assert_eq!(List::decode(ArmAbi::U64Align8, &second??)?.id()?.0, 0x73);
        let first = tokio::time::timeout(Duration::from_millis(100), frame(&mut first_peer)).await;
        assert!(
            first.is_ok(),
            "an active stream's own TX must progress while its RX stays ready"
        );
        assert_eq!(first??, encoded(Request::Test));
        shutdown(&mut driver).await;
        Ok(())
    })
}

#[test]
fn queued_managed_demand_progresses_while_control_input_remains_ready() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"demand", &fixture()?, b"accept", false);
        c.set_value(b"demand", b"START_ON_DEMAND", Some(b"YES"))?;
        let env = environment(&dir, "accept");
        let registry = registry(&c, &env);
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let mut managed = ManagedListeners::new(1);
        let path = dir.0.join("demand.sock");
        let _bound = managed
            .bind_address(0, Address::Unix(path.clone()), 0o700)
            .map_err(Error::Listener)?;
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits::default())?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| d.phase() == Phase::Serving).await;
        let (control, mut peer) = UnixStream::pair()?;
        assert!(driver.admit(
            gnunet_service_runtime::connection::Connection::from_unix(control),
            gnunet_service_runtime::service::PeerAddress::Unix
        )?);
        let mut queued = UnixStream::connect(path).await?;
        queued.write_all(b"queue").await?;
        peer.write_all(&encoded(Request::Test).repeat(64)).await?;
        pump(&mut driver, |d| d.counters().spawned == 1).await;
        assert!(
            driver.counters().received < 64,
            "ready managed demand must run before an earlier control backlog drains"
        );
        let mut response = [0; 11];
        let read = alongside(&mut driver, queued.read_exact(&mut response)).await?;
        let _count = read?;
        assert_eq!(&response, b"child:queue");
        shutdown(&mut driver).await;
        Ok(())
    })
}

#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "Explicitly end the borrowed view to inspect external persisted socket ownership"
)]
fn persisted_self_stop_malformed_message_keeps_actual_socket_until_external_state_drop() -> Test {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut c = config(&dir);
        add(&mut c, b"slow", &fixture()?, b"hold-control", true);
        c.set_value(b"slow", b"IMMEDIATE_START", Some(b"YES"))?;
        c.set_value(b"slow", b"NOARMBIND", Some(b"YES"))?;
        let env = environment(&dir, "hold-control");
        let mut children = Children(ChildRegistry::new(8)?);
        children.0.prepare()?;
        let registry = registry(&c, &env);
        let mut managed = ManagedListeners::new(0);
        owners!(
            registry, managed, scope, slots, clients, ls, bytes, frames, owner
        );
        let control = BoundListeners::bind(&c, b"arm", Activation::default()).await?;
        let mut state = State::new(control, Limits { clients: 2, ..Limits::default() })?;
        let mut rows = [row()];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children.0,
            &mut state,
            &c,
            helper(),
            &env,
            &options,
            &mut rows,
            &mut clock,
        )?;
        pump(&mut driver, |d| {
            d.phase() == Phase::Serving
                && std::fs::read_to_string(dir.0.join("trace")).is_ok_and(|s| s.contains("ready=1"))
        })
        .await;
        let mut requester = UnixStream::connect(dir.0.join("arm.sock")).await?;
        requester
            .write_all(&encoded(Request::Stop {
                reserved: 0,
                id: WireId(1),
                service: b"ARM",
            }))
            .await?;
        pump(&mut driver, |d| d.phase() == Phase::Draining).await;
        assert!(dir.0.join("arm.sock").exists());
        let stopping =
            ResultReply::decode(ArmAbi::U64Align8, &reply(&mut driver, &mut requester).await)?;
        assert_eq!(stopping.result, ResultCode::STOPPING);
        // Registered fixed-size type15 with five bytes: safe generic MQ error.
        requester.write_all(&[0, 5, 0, 15, 0]).await?;
        pump(&mut driver, |d| d.client_count()==0).await;
        assert_eq!(driver.phase(),Phase::Draining);
        assert_eq!(driver.counters().reaped,0);
        drop(driver);
        let retained=state.persisted_count();
        let mut byte=[0];
        let observed=tokio::time::timeout(Duration::from_millis(30),requester.read(&mut byte)).await;
        assert!(observed.is_err(),"persisted requester was physically closed during child drain: read={observed:?}, retained={retained}");
        assert_eq!(retained,1);
        let mut driver=Driver::new(&mut owner,&registry,&mut managed,&mut children.0,&mut state,&c,helper(),&env,&options,&mut rows,&mut clock)?;
        assert_eq!(driver.counters().closed, 0);
        let (additional, mut additional_peer) = UnixStream::pair()?;
        assert!(driver.admit(
            gnunet_service_runtime::connection::Connection::from_unix(additional),
            gnunet_service_runtime::service::PeerAddress::Unix,
        )?);
        let (excess, mut excess_peer) = UnixStream::pair()?;
        assert!(matches!(driver.admit(
            gnunet_service_runtime::connection::Connection::from_unix(excess),
            gnunet_service_runtime::service::PeerAddress::Unix,
        ), Err(Error::Capacity)));
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), excess_peer.read(&mut byte)).await??, 0);
        assert_eq!(driver.client_count(), 1);
        pump(&mut driver, |d| d.phase() == Phase::Closed).await;
        assert_eq!(driver.counters().reaped, 1);
        assert!(!dir.0.join("arm.sock").exists());
        drop(driver);
        assert_eq!(state.persisted_count(), 1);
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), additional_peer.read(&mut byte)).await??, 0);
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), requester.read(&mut byte))
                .await
                .is_err()
        );
        drop(state);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), requester.read(&mut byte)).await??,
            0
        );
        Ok(())
    })
}
