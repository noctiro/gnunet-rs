//! Embedded readiness and orderly route retirement through the original application port.
use super::*;
use crate::coordinator::{
    application::{self, Command, Controller},
    provider::{RouteCompletion, RouteOutcome, RouteRequest},
};
use gnunet_service_runtime::{clock::SystemClock, local::Listener};
use gnunet_vpn::RouteAction;
use std::{
    cell::Cell,
    fs::DirBuilder,
    num::NonZeroU16,
    os::unix::fs::DirBuilderExt,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{runtime::Builder, sync::Notify, task::LocalSet, time::timeout};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, Box<dyn StdError>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        };
        let path = base.join(format!("gvpn-{}-{nonce:x}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}

async fn route(control: &Controller, action: RouteAction) -> io::Result<RouteRequest> {
    loop {
        match control.next(Duration::ZERO) {
            Some(Command::Route(request)) if request.action == action => return Ok(request),
            Some(_) => return Err(io::Error::other("unexpected VPN command")),
            None => tokio::time::sleep(Duration::from_millis(1)).await,
        }
    }
}

#[test]
fn application_discovery_defaults_to_regex_and_validates_only_its_selected_limits()
-> Result<(), Box<dyn StdError>> {
    let mut config = Configuration::default();
    let original = ApplicationSettings::read(&config)?;
    if !original.uses_regex() {
        return Err("application VPN omitted default automatic discovery".into());
    }
    config.set_number(b"vpn-rust", b"REGEX_SEARCHES", 0)?;
    if ApplicationSettings::read(&config).is_ok() {
        return Err("invalid selected REGEX bounds were accepted".into());
    }
    config.set_value(b"vpn-rust", b"EXIT_DISCOVERY", Some(b"configured"))?;
    if ApplicationSettings::read(&config)?.uses_regex() {
        return Err("explicit configured exit policy retained a REGEX dependency".into());
    }
    if !original.uses_regex() {
        return Err("prepared discovery policy changed with the original config".into());
    }
    let mut fixed = Configuration::default();
    let exit = format!("{} any any 0-65535 linux", "00".repeat(32));
    fixed.set_value(b"vpn-rust", b"CONFIGURED_EXITS", Some(exit.as_bytes()))?;
    if ApplicationSettings::read(&fixed).is_ok() {
        return Err("automatic discovery silently ignored configured exits".into());
    }
    fixed.set_value(b"vpn-rust", b"EXIT_DISCOVERY", Some(b"configured"))?;
    if ApplicationSettings::read(&fixed)?.uses_regex() {
        return Err("explicit fixed exits retained an automatic fallback".into());
    }
    Ok(())
}

#[test]
fn embedded_readiness_requires_native_settings_and_live_cadet() -> Result<(), Box<dyn StdError>> {
    let scratch = Scratch::new()?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    LocalSet::new().block_on(&runtime, async {
        timeout(Duration::from_secs(5), async {
            let vpn = scratch.0.join("vpn");
            let cadet = scratch.0.join("cadet");
            let (control, provider) = application::channel(
                NonZeroU16::new(1280)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?,
                NonZeroU16::MIN,
            )?;
            let stop = Rc::new(Notify::new());
            let ready = Rc::new(Cell::new(false));
            let task = tokio::task::spawn_local({
                let stop = stop.clone();
                let ready = ready.clone();
                let vpn = vpn.clone();
                let cadet = cadet.clone();
                async move {
                    serve_embedded(
                        EmbeddedSettings {
                            settings: ApplicationSettings::read(&Configuration::default())?,
                            endpoints: LocalEndpoints {
                                discovery: DiscoveryEndpoint::Regex(vpn.with_file_name("regex")),
                                vpn,
                                cadet,
                            },
                            clock: Arc::new(SystemClock),
                            provider: Box::new(provider),
                        },
                        async {
                            stop.notified().await;
                            Ok(())
                        },
                        || {
                            ready.set(true);
                            Ok(())
                        },
                    )
                    .await
                }
            });

            let install = route(&control, RouteAction::Install).await?;
            if ready.get() {
                return Err("VPN announced readiness before settings receipt".into());
            }
            control.complete_route(RouteCompletion {
                id: install.id,
                outcome: RouteOutcome::Installed,
            })?;
            let mut packet = [0; 20];
            packet[0] = 0x45;
            packet[3] = 20;
            loop {
                match control.receive(&packet) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::NotConnected => {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if ready.get() {
                return Err("VPN announced readiness without a live CADET service".into());
            }
            let cadet = Listener::bind(cadet)?;
            let (_stream, _) = cadet.accept().await?;
            while !ready.get() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            stop.notify_one();
            let remove = route(&control, RouteAction::Remove).await?;
            if install.id.epoch() != remove.id.epoch() || install.id == remove.id {
                return Err("VPN route removal did not retain the original provider epoch".into());
            }
            control.complete_route(RouteCompletion {
                id: remove.id,
                outcome: RouteOutcome::Removed,
            })?;
            task.await??;
            if vpn.exists() || !matches!(control.next(Duration::ZERO), Some(Command::Closed)) {
                return Err("VPN did not retire its private listener and provider".into());
            }
            Ok::<(), Box<dyn StdError>>(())
        })
        .await?
    })
}
