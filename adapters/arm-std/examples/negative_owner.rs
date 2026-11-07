//! Real Rust ARM ClientHost against the isolated normal-C negative fixture peer.
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_arm_core::{
    FrameSlot,
    client::{
        Client, ConnectionStatus, Event, Inbound, OperationId, OperationSlot, StdioInheritance,
    },
    wire::ArmAbi,
};
use gnunet_arm_host::{
    ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LocalLauncher, Progress,
};
use gnunet_config::Configuration;
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let endpoint = PathBuf::from(args.next().ok_or("endpoint")?);
    let profile = args
        .next()
        .ok_or("profile")?
        .into_string()
        .map_err(|_| "profile UTF8")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(endpoint, &profile))
}
async fn run(endpoint: PathBuf, profile: &str) -> Result<()> {
    let mut domain = resolution_domain::Domain::new(Configuration::default())?;
    domain.start()?;
    let mut cfg = Configuration::new(Default::default());
    cfg.set_value(
        b"arm",
        b"UNIXPATH",
        Some(endpoint.as_os_str().as_encoded_bytes()),
    )?;
    let mut registry = ChildRegistry::new(2)?;
    let launcher = LocalLauncher::new(
        cfg.duplicate()?,
        std::env::current_exe()?,
        LaunchLimits::default(),
        &mut registry,
    )?;
    let mut operations = [OperationSlot::EMPTY; 4];
    let mut frames = [FrameSlot::EMPTY; 8];
    let mut pool = [0; 1024];
    let core = Client::new(
        &mut operations,
        &mut frames,
        &mut pool,
        1,
        ArmAbi::U64Align8,
    )?;
    let mut host = ClientHost::connect(
        core,
        cfg,
        domain.resolution(),
        launcher,
        Limits {
            io_slice_bytes: 1,
            ..Default::default()
        },
        Clock::system()?,
        |_| {},
    )?;
    let mut bad: Option<OperationId> = None;
    let mut keep: Option<OperationId> = None;
    let mut bad_callbacks = 0;
    let mut keep_callbacks = 0;
    let mut disconnected = false;
    let until = Instant::now() + Duration::from_secs(5);
    while keep_callbacks == 0 || (profile.starts_with("malformed-") && !disconnected) {
        let mut error: Option<Box<dyn Error>> = None;
        let progress = host
            .drive(Some(until), |inbound, port| {
                let outcome = (|| -> Result<()> {
                    match inbound {
                        Inbound::Event(Event::Connection(status)) => {
                            let n = match status {
                                ConnectionStatus::Connected => 1,
                                ConnectionStatus::Disconnected => 0,
                                ConnectionStatus::Error => -1,
                            };
                            writeln!(
                                io::stdout().lock(),
                                "{{\"event\":\"connection\",\"status\":{n}}}"
                            )?;
                            if status == ConnectionStatus::Error {
                                return Err("initial endpoint error".into());
                            }
                            if status == ConnectionStatus::Disconnected {
                                disconnected = true;
                            }
                            if status == ConnectionStatus::Connected && bad.is_none() {
                                bad = Some(if profile == "wrong-result-list" {
                                    port.request_service_start(b"wrong", StdioInheritance(0))?
                                } else {
                                    port.request_service_list()?
                                });
                                keep = Some(port.request_service_stop(b"keep")?);
                            }
                        }
                        Inbound::Event(Event::ListDisconnected { operation }) => {
                            if Some(operation) != bad {
                                return Err("foreign list callback".into());
                            }
                            bad_callbacks += 1;
                            writeln!(
                                io::stdout().lock(),
                                "{{\"event\":\"bad-list\",\"status\":2,\"count\":0}}"
                            )?;
                        }
                        Inbound::List { operation, list } => {
                            if Some(operation) != bad {
                                return Err("foreign list callback".into());
                            }
                            bad_callbacks += 1;
                            writeln!(
                                io::stdout().lock(),
                                "{{\"event\":\"bad-list\",\"status\":0,\"count\":{}}}",
                                list.len()
                            )?;
                        }
                        Inbound::Event(Event::Result {
                            operation,
                            status,
                            result,
                        }) => {
                            let label = if Some(operation) == keep {
                                keep_callbacks += 1;
                                "keep"
                            } else if Some(operation) == bad {
                                bad_callbacks += 1;
                                "bad-result"
                            } else {
                                return Err("foreign result callback".into());
                            };
                            writeln!(
                                io::stdout().lock(),
                                "{{\"event\":\"{label}\",\"status\":{},\"result\":{}}}",
                                status as u32,
                                result.map_or(0, |r| r.0)
                            )?;
                        }
                    }
                    Ok(())
                })();
                if let Err(e) = outcome {
                    error = Some(e);
                }
            })
            .await?;
        if let Some(e) = error {
            return Err(e);
        }
        if progress == Progress::WaitDeadline {
            return Err("original deadline elapsed".into());
        }
    }
    let mut extra = 0;
    host.disconnect(|_, _| {
        extra += 1;
    })?;
    if extra != 0 {
        return Err("unexpected original pending callback during explicit disconnect".into());
    }
    drop(host);
    if registry.pending_children() != 0 {
        return Err("unexpected child".into());
    }
    writeln!(
        io::stdout().lock(),
        "{{\"event\":\"done\",\"bad\":{bad_callbacks},\"keep\":{keep_callbacks},\"failed\":0}}"
    )?;
    Ok(())
}
