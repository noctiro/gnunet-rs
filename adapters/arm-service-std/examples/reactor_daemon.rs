//! Actual finite ARM daemon reactor fixture, with explicit config/helper/ready paths.
//! This is an integration entrypoint, not the complete official PROGRAM/CLI.
use gnunet_arm_core::wire::{ArmAbi, ServiceInfo, ServiceStatus};
use gnunet_arm_service_core::{
    ClientSlot, FrameSlot, ListenerSlot, Owner, OwnerScope, Phase, ServiceSlot,
};
use gnunet_arm_service_host::{
    listeners::ManagedListeners,
    reactor::{Activity, Driver, Limits, State, SystemClock},
    registry::{self, Registry},
};
use gnunet_config::{BinaryPathCache, Configuration, ProjectData};
use gnunet_service_runtime::{
    Activation, BoundListeners, CreatedPath,
    process::{ChildRegistry, EnvironmentSnapshot},
    service_options,
};
use std::{
    error::Error,
    fs::OpenOptions,
    future::poll_fn,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::signal::unix::{SignalKind, signal};
struct Children(ChildRegistry);
impl Drop for Children {
    fn drop(&mut self) {
        for child in self.0.children().cloned().collect::<Vec<_>>() {
            drop(self.0.signal(&child, libc::SIGKILL));
        }
        let until = Instant::now() + Duration::from_secs(2);
        while self.0.pending_children() > 0 && Instant::now() < until {
            drop(self.0.reap_completed());
            while self.0.take_reaped().is_some() {}
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let config = PathBuf::from(args.next().ok_or("CONFIG required")?);
    let helper = PathBuf::from(args.next().ok_or("HELPER required")?);
    let ready = PathBuf::from(args.next().ok_or("owned READY required")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut children = Children(ChildRegistry::new(256)?);
            children.0.prepare()?;
            let mut term = signal(SignalKind::terminate())?;
            let mut interrupt = signal(SignalKind::interrupt())?;
            let mut config_data = Configuration::default();
            config_data.parse(&config)?;
            // This fixture does not claim unsupported generic privilege/diagnostic stages.
            if config_data.have_value(b"arm", b"USERNAME")
                || matches!(
                    config_data.get_yesno(b"arm", b"RESOURCE_DIAGNOSTICS"),
                    Ok(true)
                )
            {
                return Err(
                    "fixture does not implement selected privilege/resource-diagnostic stage"
                        .into(),
                );
            }
            let environment = EnvironmentSnapshot::system()?;
            let registry = Registry::from_config(
                &config_data,
                &environment,
                &ProjectData::default(),
                &mut BinaryPathCache::new(),
                registry::Limits::default(),
            )?;
            let specs = registry.specs();
            let mut managed = ManagedListeners::new(4096);
            managed
                .bind_registry(&config_data, &registry, &environment, 4096)
                .map_err(|e| io::Error::other(format!("managed listeners: {e:?}")))?;
            let mut scope = OwnerScope::new();
            let mut services = (0..specs.len())
                .map(|_| ServiceSlot::new())
                .collect::<Vec<_>>();
            let mut clients = (0..32).map(|_| ClientSlot::new()).collect::<Vec<_>>();
            let mut listeners = (0..managed.len())
                .map(|_| ListenerSlot::new())
                .collect::<Vec<_>>();
            let mut bytes = (0..256).map(|_| vec![0; 65535]).collect::<Vec<_>>();
            let mut frames = bytes
                .iter_mut()
                .map(|buffer| FrameSlot::new(buffer))
                .collect::<Vec<_>>();
            let mut owner = Owner::new(
                &mut scope,
                &specs,
                &mut services,
                &mut clients,
                &mut listeners,
                &mut frames,
                ArmAbi::U64Align8,
            )
            .map_err(|e| io::Error::other(format!("owner: {e:?}")))?;
            let control = BoundListeners::bind(&config_data, b"arm", Activation::default()).await?;
            let options = service_options(
                &config_data,
                b"arm",
                gnunet_service_runtime::service::ShutdownMode::Immediate,
            )?;
            let mut state = State::new(control, Limits::default())?;
            let row = ServiceInfo {
                name: b"",
                binary: b"",
                status: ServiceStatus::STOPPED,
                last_exit_status: 0,
                restart_at: 0,
                last_started_at: 0,
            };
            let mut rows = vec![row; specs.len()];
            let mut clock = SystemClock;
            let mut driver = Driver::new(
                &mut owner,
                &registry,
                &mut managed,
                &mut children.0,
                &mut state,
                &config_data,
                &helper,
                &environment,
                &options,
                &mut rows,
                &mut clock,
            )?;
            let mut ready_guard = None;
            loop {
                if ready_guard.is_none() && driver.phase() == Phase::Serving {
                    let mut output = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&ready)?;
                    let guard = CreatedPath::capture(ready.clone())?;
                    writeln!(output, "{}", std::process::id())?;
                    drop(output);
                    ready_guard = Some(guard);
                }
                let activity = poll_fn(|cx| {
                    if term.poll_recv(cx).is_ready() || interrupt.poll_recv(cx).is_ready() {
                        driver.shutdown();
                    }
                    driver.poll_drive(cx)
                })
                .await?;
                if activity == Activity::Closed {
                    break;
                }
            }
            drop(ready_guard);
            io::Result::Ok(())?;
            Ok(())
        })
}
