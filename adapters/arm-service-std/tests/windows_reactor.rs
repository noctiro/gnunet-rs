//! Native Windows child lifecycle and original managed-listener transfer.
#[cfg(windows)]
mod windows {
    use gnunet_arm_core::wire::{ArmAbi, ServiceInfo, ServiceStatus};
    use gnunet_arm_service_core::{
        ClientSlot, FrameSlot, ListenerSlot, Owner, OwnerScope, Phase, ServiceSlot,
    };
    use gnunet_arm_service_host::{
        addresses::Address,
        listeners::ManagedListeners,
        process::{ChildRegistry, EnvironmentSnapshot, LaunchContext},
        reactor::{Activity, Driver, Limits, State, SystemClock},
        registry::{self, Registry},
    };
    use gnunet_config::{BinaryPathCache, Configuration, ProcessEnvironment, ProjectData};
    use gnunet_service_runtime::{
        Activation, BoundListeners, LocalListenerAccess,
        service::{Listener, ServiceOptions},
    };
    use gnunet_service_startup::{
        CapturedStartup, ReadyStatus, StopSignals, capture_from_environment,
    };
    use std::{
        error::Error,
        ffi::{OsStr, OsString},
        fs,
        future::{Future, poll_fn},
        io,
        net::Ipv4Addr,
        path::PathBuf,
        task::{Context, Poll, Waker},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    type Failure = Box<dyn Error>;
    const ROLE: &str = "GNUNET_ARM_NATIVE_FIXTURE";
    fn check(condition: bool, message: &'static str) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    fn core<T>(result: Result<T, gnunet_arm_service_core::Error>) -> io::Result<T> {
        result.map_err(|error| io::Error::other(format!("ARM state: {error:?}")))
    }
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            let mut nonce = [0; 16];
            gnunet_native::entropy::fill(&mut nonce)?;
            let name = format!("gn-arm-native-{:032x}", u128::from_be_bytes(nonce));
            let parent = std::env::temp_dir();
            gnunet_native::filesystem::Directory::open(&parent)?
                .create_private_directory(OsStr::new(&name))?;
            Ok(Self(parent.join(name)))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    struct Children(ChildRegistry);
    impl Drop for Children {
        fn drop(&mut self) {
            let originals: Vec<_> = self.0.children().cloned().collect();
            for original in originals {
                let _cleanup = self.0.terminate(&original, 0xffff_ff02);
            }
        }
    }
    #[derive(Clone, Copy)]
    enum StopRoute {
        Pipe,
        Native,
        BeforeImport,
    }
    async fn child(captured: CapturedStartup, activation: Activation) -> Result<(), Failure> {
        check(activation.len() == 1, "original managed listener was lost")?;
        let bound = BoundListeners::from_activation(activation)?;
        let Listener::Tcp(listener) = bound
            .listeners()
            .into_iter()
            .next()
            .ok_or("missing imported listener")?
        else {
            return Err("managed TCP listener changed family".into());
        };
        let (mut stream, _) = listener.accept().await?;
        let mut payload = [0; 3];
        stream.read_exact(&mut payload).await?;
        check(payload == *b"ARM", "original queued payload changed")?;
        stream.write_all(&payload).await?;
        let mut parent = captured
            .parent_control
            .ok_or("missing original supervisor")?
            .register()?;
        parent.ready.signal(ReadyStatus::AcceptRegistered).await?;
        let mut stop = StopSignals::new(Some(parent.control))?;
        poll_fn(|cx| stop.poll_stop(cx)).await?;
        fs::write("cooperative-stop", b"received original control")?;
        Ok(())
    }
    async fn parent(route: StopRoute) -> Result<(), Failure> {
        let directory = Directory::new()?;
        let executable = std::env::current_exe()?;
        let mut config = Configuration::default();
        for (key, value) in [
            (b"START_USER_SERVICES".as_slice(), b"YES".as_slice()),
            (b"START_SYSTEM_SERVICES", b"NO"),
        ] {
            config.set_value(b"arm", key, Some(value))?;
        }
        let filename = match route {
            StopRoute::Pipe => executable.as_os_str(),
            StopRoute::Native | StopRoute::BeforeImport => executable
                .file_stem()
                .ok_or("missing native image basename")?,
        };
        let image = gnunet_native::os_bytes::encode(filename);
        for (key, value) in [
            (b"TYPE".as_slice(), b"SIMPLE".as_slice()),
            (b"PREFIX", image.as_ref()),
            (b"BINARY", b"gnunet-arm-native-child"),
            (b"RUN_PER_USER", b"YES"),
            (b"IMMEDIATE_START", b"YES"),
            (
                b"PIPECONTROL",
                match route {
                    StopRoute::Pipe => b"YES",
                    StopRoute::Native | StopRoute::BeforeImport => b"NO",
                },
            ),
        ] {
            config.set_value(b"native", key, Some(value))?;
        }
        let registry = Registry::from_config(
            &config,
            &ProcessEnvironment,
            &ProjectData::default(),
            &mut BinaryPathCache::new(),
            registry::Limits::default(),
        )?;
        check(registry.services().len() == 1, "fixture registry changed")?;
        let mut values: Vec<_> = std::env::vars_os().collect();
        values.push((ROLE.into(), OsString::from("child")));
        if matches!(route, StopRoute::BeforeImport) {
            values.push((
                "GNUNET_ARM_IMPORT_GATE".into(),
                directory.0.join("import-gate").into_os_string(),
            ));
        }
        if matches!(route, StopRoute::Native | StopRoute::BeforeImport) {
            values.push((
                "pAtH".into(),
                executable
                    .parent()
                    .ok_or("missing image directory")?
                    .as_os_str()
                    .into(),
            ));
        }
        let environment =
            EnvironmentSnapshot::from_values(values, directory.0.clone(), Default::default())?;
        let mut children = Children(ChildRegistry::new(1)?);
        let mut managed = ManagedListeners::new(2);
        let _bound = managed
            .bind_address(
                0,
                Address::Tcp((Ipv4Addr::LOCALHOST, 0).into()),
                LocalListenerAccess::Owner,
            )
            .await?;
        let Address::Tcp(address) = managed.address(0).ok_or("missing original listener")? else {
            return Err("listener family changed".into());
        };
        let address = *address;
        if matches!(route, StopRoute::BeforeImport) {
            let _second = managed
                .bind_address(
                    0,
                    Address::Tcp((Ipv4Addr::LOCALHOST, 0).into()),
                    LocalListenerAccess::Owner,
                )
                .await?;
        }
        let mut queued = tokio::net::TcpStream::connect(address).await?;
        queued.write_all(b"ARM").await?;
        let specs = registry.specs();
        let mut scope = OwnerScope::new();
        let mut services = [ServiceSlot::new()];
        let mut clients = [ClientSlot::new()];
        let mut listeners: Vec<_> = (0..managed.len()).map(|_| ListenerSlot::new()).collect();
        let mut bytes = [0; 65535];
        let mut frames = [FrameSlot::new(&mut bytes)];
        let mut owner = core(Owner::new(
            &mut scope,
            &specs,
            &mut services,
            &mut clients,
            &mut listeners,
            &mut frames,
            ArmAbi::U64Align8,
        ))?;
        let control = BoundListeners::from_activation(Activation::default())?;
        let mut state = State::new(
            control,
            Limits {
                settlement_budget: if matches!(route, StopRoute::BeforeImport) {
                    1
                } else {
                    128
                },
                ..Limits::default()
            },
        )?;
        let mut rows = [ServiceInfo {
            name: b"",
            binary: b"",
            status: ServiceStatus::STOPPED,
            last_exit_status: 0,
            restart_at: 0,
            last_started_at: 0,
        }];
        let mut clock = SystemClock;
        let options = ServiceOptions::default();
        {
            let mut driver = Driver::new(
                &mut owner,
                &registry,
                &mut managed,
                &mut children.0,
                &mut state,
                LaunchContext {
                    environment: &environment,
                },
                &options,
                &mut rows,
                &mut clock,
            )?;
            if matches!(route, StopRoute::BeforeImport) {
                while driver.counters().spawned == 0 {
                    let _activity = driver.drive().await?;
                }
                driver.shutdown();
            } else {
                while driver.counters().startup_ready == 0 {
                    let _activity = driver.drive().await?;
                }
                let mut echo = [0; 3];
                queued.read_exact(&mut echo).await?;
                check(
                    echo == *b"ARM",
                    "queued listener transfer changed stream bytes",
                )?;
                // Cancel a real idle drive, then drop the complete temporary borrow.
                // Registry, child control, listener and stream owners stay external.
                let mut idle = false;
                for _ in 0..16 {
                    let mut future = std::pin::pin!(driver.drive());
                    match future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                    {
                        Poll::Pending => {
                            idle = true;
                            break;
                        }
                        Poll::Ready(Ok(Activity::Progress)) => {}
                        Poll::Ready(other) => {
                            return Err(format!("unexpected idle drive: {other:?}").into());
                        }
                    }
                }
                check(idle, "original driver did not retain an idle wait")?;
            }
        }
        if matches!(route, StopRoute::BeforeImport) {
            let original = managed.id(0).ok_or("missing first managed lease")?;
            let mut closed = false;
            for _ in 0..128 {
                if managed.descriptor(original).is_none() {
                    closed = true;
                    break;
                }
                let mut driver = Driver::new(
                    &mut owner,
                    &registry,
                    &mut managed,
                    &mut children.0,
                    &mut state,
                    LaunchContext {
                        environment: &environment,
                    },
                    &options,
                    &mut rows,
                    &mut clock,
                )?;
                let mut drive = std::pin::pin!(driver.drive());
                if let Poll::Ready(Err(error)) =
                    drive.as_mut().poll(&mut Context::from_waker(Waker::noop()))
                {
                    return Err(error.into());
                }
            }
            check(
                closed && state.counters().term_attempts == 0,
                "managed sources were not retired before native stop",
            )?;
            // A private publisher descriptor must still own the exact endpoint
            // while the target is blocked before provider materialization.
            let _retained_endpoint = tokio::net::TcpStream::connect(address).await?;
        }
        {
            let mut driver = Driver::new(
                &mut owner,
                &registry,
                &mut managed,
                &mut children.0,
                &mut state,
                LaunchContext {
                    environment: &environment,
                },
                &options,
                &mut rows,
                &mut clock,
            )?;
            driver.shutdown();
            while driver.phase() != Phase::Closed {
                let _activity = driver.drive().await?;
            }
            let counters = driver.counters();
            check(
                counters.spawned == 1
                    && counters.startup_ready
                        == u64::from(!matches!(route, StopRoute::BeforeImport))
                    && counters.term_attempts == 1
                    && counters.reaped == 1
                    && counters.preparation_retired == 0,
                "native lifecycle manufactured or lost an observation",
            )?;
            if let Some(diagnostic) = driver.take_diagnostic() {
                return Err(format!("native ARM diagnostic: {diagnostic:?}").into());
            }
        }
        check(
            directory.0.join("cooperative-stop").exists() == matches!(route, StopRoute::Pipe),
            "cooperative control was replaced by native termination",
        )?;
        check(
            children.0.pending_children() == 0 && children.0.take_reaped().is_none(),
            "original child or consuming receipt was abandoned",
        )?;
        Ok(())
    }
    pub fn run() -> Result<(), Failure> {
        let child_role = std::env::var_os(ROLE).is_some();
        #[expect(
            unsafe_code,
            reason = "Fresh child entry before runtime or competing native owners, receiving exclusively inherited immutable activation metadata"
        )]
        let captured = if child_role {
            // SAFETY: this is the first child ownership action before runtime.
            Some(unsafe { capture_from_environment() }?)
        } else {
            None
        };
        let (captured, activation) = match captured {
            Some(mut captured) => {
                if let Some(gate) = std::env::var_os("GNUNET_ARM_IMPORT_GATE") {
                    let until = std::time::Instant::now() + Duration::from_secs(15);
                    while !std::path::Path::new(&gate).is_file() {
                        if std::time::Instant::now() >= until {
                            return Err("private import gate expired".into());
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                let incoming = captured
                    .activation
                    .take()
                    .ok_or("missing managed activation")?;
                (
                    Some(captured),
                    Activation::from_imported(incoming.materialize()?)?,
                )
            }
            None => (None, Activation::default()),
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(30), async {
                    if let Some(captured) = captured {
                        child(captured, activation).await
                    } else {
                        parent(StopRoute::Pipe).await?;
                        parent(StopRoute::Native).await?;
                        parent(StopRoute::BeforeImport).await
                    }
                })
                .await
                .map_err(io::Error::other)?
            })
    }
}
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows::run()
}
#[cfg(not(windows))]
fn main() {}
