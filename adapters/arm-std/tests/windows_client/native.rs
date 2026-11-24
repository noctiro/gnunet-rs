use gnunet_arm_core::{
    FrameSlot,
    client::{Client, Event, Inbound, OperationSlot, StdioInheritance},
    wire::{ArmAbi, RequestStatus, ResultCode},
};
use gnunet_arm_host::{ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LocalLauncher};
use gnunet_config::{BinaryPathCache, Configuration};
use gnunet_native::os_bytes;
use gnunet_service_runtime::process::EnvironmentSnapshot;
use gnunet_service_startup::{CapturedStartup, ReadyStatus, capture_from_environment};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::{Instant, timeout};
type Failure = Box<dyn Error>;
const ROLE: &str = "GNUNET_ARM_WINDOWS_CLIENT_FIXTURE";
const ROOT: &str = "GNUNET_ARM_WINDOWS_CLIENT_DIRECTORY";
fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let name = format!("gn-arm-client-{:032x}", u128::from_be_bytes(nonce));
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
struct Registry(ChildRegistry);
impl Drop for Registry {
    fn drop(&mut self) {
        for child in self.0.children() {
            let _cleanup = self.0.terminate(child, 0xdead_0010);
        }
    }
}
async fn file(path: &Path) -> io::Result<()> {
    loop {
        match fs::metadata(path) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
            Err(error) => return Err(error),
        }
    }
}
async fn child(captured: CapturedStartup) -> Result<(), Failure> {
    let root = PathBuf::from(std::env::var_os(ROOT).ok_or("missing child directory")?);
    fs::write(root.join("captured"), [])?;
    file(&root.join("import")).await?;
    check(
        captured.activation.is_none(),
        "local ARM acquired an unexpected activation declaration",
    )?;
    let mut parent = captured
        .parent_control
        .ok_or("missing original bootstrap")?
        .register()?;
    // ARM waits for the child's status. The qualified control direction does
    // not send a greeting before readiness.
    parent.ready.signal(ReadyStatus::AcceptRegistered).await?;
    fs::write(root.join("ready"), [])?;
    file(&root.join("finish")).await?;
    Ok(())
}
#[derive(Clone, Copy, Debug)]
enum Cancellation {
    None,
    Operation,
    Disconnect,
}
async fn parent(cancellation: Cancellation) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let executable = directory.0.join("native program.exe");
    fs::copy(std::env::current_exe()?, &executable)?;
    let config_path = directory.0.join("config with spaces.conf");
    let mut config = Configuration::default();
    config.set_value(
        b"arm",
        b"BINARY",
        Some(&os_bytes::encode(executable.as_os_str())),
    )?;
    config.set_value(
        b"arm",
        b"CONFIG",
        Some(&os_bytes::encode(config_path.as_os_str())),
    )?;
    config.set_value(b"TESTING", b"WEAKRANDOM", Some(b"YES"))?;
    let environment = EnvironmentSnapshot::from_values(
        std::env::vars_os().chain([
            (OsString::from(ROLE), "child".into()),
            (OsString::from(ROOT), directory.0.as_os_str().to_owned()),
        ]),
        std::env::current_dir()?,
        Default::default(),
    )?;
    let mut registry = Registry(ChildRegistry::new(4)?);
    let mut cache = BinaryPathCache::default();
    let mut launcher = LocalLauncher::with_environment(
        config,
        LaunchLimits {
            max_children: 4,
            ..Default::default()
        },
        environment,
        &mut registry.0,
        &mut cache,
    )?;
    let plan = launcher.command_plan()?.ok_or("missing command")?;
    check(
        plan.argv
            == [
                executable.into_os_string(),
                "-c".into(),
                config_path.into_os_string(),
            ],
        "native backslashes or spaces changed in planning",
    )?;
    let mut operations = [OperationSlot::EMPTY; 4];
    let mut slots = [FrameSlot::EMPTY; 8];
    let mut pool = [0; 512];
    let core = Client::new(&mut operations, &mut slots, &mut pool, 1, ArmAbi::U64Align8)?;
    let mut host = ClientHost::connect_unix(
        core,
        directory.0.join("absent.sock"),
        launcher,
        Limits::default(),
        Clock::system()?,
        |_| {},
    )?;
    let operation = host.request_service_start(b"arm", StdioInheritance(4))?;
    let mut callbacks = 0;
    while !directory.0.join("captured").exists() {
        host.drive(
            Some(Instant::now() + Duration::from_millis(20)),
            |event, _| {
                if matches!(event, Inbound::Event(Event::Result { .. })) {
                    callbacks += 1;
                }
            },
        )
        .await?;
        if let Some(error) = host.launcher_mut().take_error() {
            return Err(error.into());
        }
        if let Some(reaped) = host.launcher_mut().take_reaped() {
            return Err(format!("child exited before capture: {}", reaped.exit_code).into());
        }
    }
    check(
        callbacks == 0 && host.launcher_mut().pending_children() == 1,
        "creation became readiness",
    )?;
    match cancellation {
        Cancellation::None => {}
        Cancellation::Operation => host.operation_cancel(operation)?,
        Cancellation::Disconnect => {
            let mut failed = false;
            host.disconnect(|event, _| {
                if let Inbound::Event(Event::Result {
                    operation: original,
                    status,
                    result,
                }) = event
                {
                    callbacks += 1;
                    failed = original == operation
                        && status == RequestStatus::Disconnected
                        && result.is_none();
                }
            })?;
            check(
                failed && callbacks == 1,
                "disconnect lost its original failure callback",
            )?;
        }
    }
    fs::write(directory.0.join("import"), [])?;
    if matches!(cancellation, Cancellation::None) {
        let mut started = false;
        while !started {
            host.drive(None, |event, _| {
                if let Inbound::Event(Event::Result { result, .. }) = event {
                    callbacks += 1;
                    started = result == Some(ResultCode::STARTING);
                }
            })
            .await?;
        }
        check(callbacks == 1, "local start callback repeated")?;
    }
    host.launcher_mut().settle_startups().await?;
    file(&directory.0.join("ready")).await?;
    check(
        host.launcher_mut().pending_startups() == 0 && host.launcher_mut().pending_children() == 1,
        "startup settlement became process exit",
    )?;
    fs::write(directory.0.join("finish"), [])?;
    host.launcher_mut().drain_children().await?;
    check(
        host.launcher_mut().take_error().is_none(),
        "cancellation abandoned native bootstrap",
    )?;
    let reaped = host
        .launcher_mut()
        .take_reaped()
        .ok_or("missing original consuming exit")?;
    check(
        reaped.exit_code == 0 && host.launcher_mut().pending_children() == 0,
        "original process did not retire cleanly",
    )?;
    match cancellation {
        Cancellation::Operation => {
            check(callbacks == 0, "canceled operation delivered a callback")?
        }
        Cancellation::Disconnect => check(
            callbacks == 1,
            "disconnected operation delivered a second callback",
        )?,
        Cancellation::None => {}
    }
    host.disconnect(|_, _| {})?;
    Ok(())
}
pub(super) fn run() -> Result<(), Failure> {
    let captured = if std::env::var_os(ROLE).is_some() {
        #[expect(
            unsafe_code,
            reason = "Standalone fixture captures native startup before creating files, runtime or threads"
        )]
        // SAFETY: no competing native activation/handle owners exist in this fresh process.
        Some(unsafe { capture_from_environment() }?)
    } else {
        None
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        if let Some(captured) = captured {
            return timeout(Duration::from_secs(30), child(captured))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "ARM client fixture child")
                })?;
        }
        for cancellation in [
            Cancellation::None,
            Cancellation::Operation,
            Cancellation::Disconnect,
        ] {
            timeout(Duration::from_secs(30), parent(cancellation))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("ARM client fixture: {cancellation:?}"),
                    )
                })??;
        }
        Ok(())
    })
}
