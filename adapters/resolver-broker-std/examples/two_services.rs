//! Actual ARM+STATISTICS hosts sharing one caller-owned process Resolver reactor.
use gnunet_arm_core::{
    FrameSlot,
    client::{Client, ConnectionStatus, Event, Inbound, OperationSlot},
    wire::ArmAbi,
};
use gnunet_arm_host::{ChildRegistry, ClientHost, Clock, LaunchLimits, LocalLauncher};
use gnunet_client::{statistics::Selector, statistics_handle::GetFlow};
use gnunet_config::Configuration;
use gnunet_ipc_unix::handle::{Event as StatisticsEvent, StatisticsHandle};
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, Progress, SystemClock, broker};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
fn emit(value: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{value}")?;
    out.flush()
}
async fn run(cfg: Configuration) -> Result {
    let native = gnunet_resolver_broker::native_profile()?;
    let profile = FamilyProfile::new(
        native.encode(gnunet_resolver_broker::Family::V4),
        native.encode(gnunet_resolver_broker::Family::V6),
    )?;
    let (ctx, mut driver) = broker::<8, 128>(
        LiveConfiguration::new(cfg.duplicate()?),
        Default::default(),
        profile,
        Arc::new(SystemClock),
    )?;
    let mut registry = ChildRegistry::new(4)?;
    let launcher = LocalLauncher::new(
        cfg.duplicate()?,
        std::env::current_exe()?,
        LaunchLimits::default(),
        &mut registry,
    )?;
    let mut operations = [OperationSlot::EMPTY; 4];
    let mut frames = [FrameSlot::EMPTY; 4];
    let mut bytes = [0; 1024];
    let core = Client::new(
        &mut operations,
        &mut frames,
        &mut bytes,
        1,
        ArmAbi::U64Align8,
    )?;
    let mut unavailable = false;
    let mut arm = ClientHost::connect(
        core,
        cfg.duplicate()?,
        ctx.resolution_context(),
        launcher,
        Default::default(),
        Clock::system()?,
        |_| unavailable = true,
    )?;
    if unavailable {
        return Err("ARM configuration unavailable".into());
    }
    let mut statistics_instance = gnunet_client::statistics_handle::Instance::new();
    let mut statistics_authority = Some(&mut statistics_instance);
    let mut statistics: Option<StatisticsHandle<'_, 8, 128, 1, 8, 4>> = None;
    let mut list_id = None;
    let mut get_id = None;
    let mut up = false;
    let mut listed = false;
    let mut got = false;
    let mut pending_reported = false;
    let until = Instant::now() + Duration::from_secs(5);
    while !(listed && got) {
        if up && statistics.is_none() {
            list_id = Some(arm.request_service_list()?);
            let mut handle = StatisticsHandle::from_config(
                statistics_authority
                    .take()
                    .ok_or("statistics owner already constructed")?,
                &cfg,
                ctx.resolution_context(),
                b"s",
                Default::default(),
            )?
            .ok_or("statistics disabled")?;
            get_id = Some(handle.get(Selector {
                subsystem: b"s",
                name: b"n",
            })?);
            statistics = Some(handle);
        }
        let mut failure = None;
        let mut control = Box::pin(arm.drive(Some(until), |event, _| {
            let result = (|| -> io::Result<()> {
                match event {
                    Inbound::Event(Event::Connection(ConnectionStatus::Connected)) => {
                        up = true;
                        emit("ARM_UP|1")?;
                    }
                    Inbound::List { operation, list } => {
                        if Some(operation) != list_id || !list.is_empty() {
                            return Err(io::Error::other("wrong ARM list"));
                        }
                        listed = true;
                        emit("ARM_LIST|0")?;
                    }
                    _ => {}
                }
                Ok(())
            })();
            if let Err(e) = result {
                failure = Some(e);
            }
        }));
        let mut statistics_failure = None;
        let mut stats = statistics.as_mut().map(|h| {
            Box::pin(h.drive(Some(until), |event, _| {
                match event {
                    StatisticsEvent::GetValue { .. } => {
                        statistics_failure = Some(io::Error::other("unexpected statistic"))
                    }
                    StatisticsEvent::GetComplete(end) => {
                        if Some(end.get) != get_id || end.result.is_err() {
                            statistics_failure =
                                Some(io::Error::other("wrong statistics completion"));
                        } else {
                            got = true;
                            if let Err(e) = emit("STATS_END|1") {
                                statistics_failure = Some(e);
                            }
                        }
                    }
                    _ => {}
                }
                GetFlow::Continue
            }))
        });
        let mut resolving = Box::pin(driver.drive_waiting(Some(until), |_| {}));
        tokio::time::timeout_at(
            until,
            poll_fn(|cx| {
                if let Poll::Ready(r) = control.as_mut().poll(cx) {
                    return Poll::Ready(r.map_err(io::Error::other).and_then(|p| {
                        if p == gnunet_arm_host::Progress::WaitDeadline {
                            Err(io::ErrorKind::TimedOut.into())
                        } else {
                            Ok(())
                        }
                    }));
                }
                if let Some(stats) = &mut stats
                    && let Poll::Ready(r) = stats.as_mut().poll(cx)
                {
                    return Poll::Ready(r.map_err(io::Error::other).and_then(|p| {
                        if p == gnunet_ipc_unix::handle::Progress::WaitDeadline {
                            Err(io::ErrorKind::TimedOut.into())
                        } else {
                            Ok(())
                        }
                    }));
                }
                if !pending_reported && ctx.pending_requests().map_err(io::Error::other)? == 2 {
                    pending_reported = true;
                    emit("SHARED_PENDING|2")?;
                    return Poll::Ready(Ok(()));
                }
                if let Poll::Ready(r) = resolving.as_mut().poll(cx) {
                    return Poll::Ready(r.map_err(io::Error::other).and_then(|p| {
                        if p == Progress::WaitDeadline {
                            Err(io::ErrorKind::TimedOut.into())
                        } else {
                            Ok(())
                        }
                    }));
                }
                Poll::Pending
            }),
        )
        .await??;
        drop(control);
        drop(stats);
        drop(resolving);
        if let Some(e) = failure.or(statistics_failure) {
            return Err(e.into());
        }
    }
    if let Some(h) = &mut statistics {
        h.destroy(false)?;
    }
    arm.disconnect(|_, _| {})?;
    drop(statistics);
    drop(arm);
    driver.disconnect()?;
    if registry.pending_children() != 0 {
        return Err("unexpected launched child".into());
    }
    Ok(())
}
fn main() -> Result {
    let mut args = std::env::args_os().skip(1);
    let file = args.next().ok_or("config")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut cfg = Configuration::default();
    cfg.parse(std::path::PathBuf::from(file))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(cfg))
}
