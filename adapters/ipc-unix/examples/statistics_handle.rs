//! Actual-daemon probe of the queued official STATISTICS Unix handle.
//! Usage: statistics_handle roundtrip CONFIG
//!        statistics_handle restart CONFIG READY_FILE
//! The restart controller owns the C daemon and injects its crash only after READY.
#![forbid(unsafe_code)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{DestroyOutcome, GetFlow, SetterAdmission},
};
use gnunet_config::Configuration;
use gnunet_ipc_unix::handle::{Event, Limits, Progress, StatisticsHandle};
use std::{error::Error, fs::OpenOptions, io::Write, path::Path, time::Duration};
use tokio::time::Instant;
type Handle<'owner> = StatisticsHandle<'owner, 32, 256, 8, 32, 16>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SUBSYSTEM: &[u8] = b"rust-handle-v0291";
fn ensure(condition: bool, text: &'static str) -> Result<()> {
    if condition { Ok(()) } else { Err(text.into()) }
}
fn emit(arguments: std::fmt::Arguments<'_>) -> std::io::Result<()> {
    writeln!(std::io::stdout().lock(), "{arguments}")
}
fn progress(value: Progress) -> Result<()> {
    ensure(
        value == Progress::Activity,
        "drive stopped before required event",
    )
}
fn selector(name: &[u8]) -> Selector<'_> {
    Selector {
        subsystem: SUBSYSTEM,
        name,
    }
}
fn create<'owner>(
    instance: &'owner mut gnunet_client::statistics_handle::Instance,
    configuration: &Configuration,
    resolution: gnunet_client_host::resolution::SharedResolution,
) -> Result<Handle<'owner>> {
    Ok(Handle::from_config(
        instance,
        configuration,
        resolution,
        SUBSYSTEM,
        Limits {
            max_frame_bytes: 1024,
            write_chunk_bytes: 3,
        },
    )?
    .ok_or("STATISTICS disabled")?)
}
fn seed<'owner>(client: &mut Handle<'owner>) -> Result<()> {
    ensure(
        client.update(b"zero-noop", 0, true)? == SetterAdmission::Noop,
        "zero update queued work",
    )?;
    ensure(
        client.connection_epoch().is_none(),
        "create/noop eagerly connected",
    )?;
    for (name, value) in [(b"a" as &[u8], 10), (b"b", 20), (b"c", 30)] {
        client.set(name, value, true)?;
    }
    Ok(())
}
async fn roundtrip<'owner>(mut client: Handle<'owner>) -> Result<()> {
    seed(&mut client)?;
    client.set(b"counter", 41, true)?;
    ensure(
        client.update(b"counter", 1, true)? == SetterAdmission::Coalesced,
        "pending setter did not coalesce",
    )?;
    let watch = client.watch(selector(b"counter"))?;
    let get = client.get(selector(b"counter"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut get_done, mut watch_initial, mut row_ok, mut callback_error) =
        (false, false, false, false);
    while !get_done || !watch_initial {
        progress(
            client
                .drive(Some(deadline), |event, _| {
                    match event {
                        Event::GetValue { get: id, statistic } => {
                            row_ok = id == get && statistic.value == 42 && statistic.persistent();
                        }
                        Event::GetComplete(done) => {
                            get_done = done.get == get && done.result.is_ok();
                        }
                        Event::WatchValue {
                            watch: id,
                            selector,
                            notification,
                        } => {
                            watch_initial = id == watch
                                && selector.name == b"counter"
                                && notification.value == 42
                                && notification.persistent();
                            // WATCH's returned flow must be ignored as in the C API.
                            return GetFlow::AbortIteration;
                        }
                        Event::ConnectionLost { .. } => callback_error = true,
                        _ => {}
                    }
                    GetFlow::Continue
                })
                .await?,
        )?;
    }
    ensure(row_ok && !callback_error, "initial C GET/WATCH mismatch")?;
    client.update(b"counter", 1, true)?;
    let mut watch_updated = false;
    while !watch_updated {
        progress(
            client
                .drive(Some(deadline), |event, _| {
                    if let Event::WatchValue {
                        watch: id,
                        selector,
                        notification,
                    } = event
                    {
                        watch_updated = id == watch
                            && selector.name == b"counter"
                            && notification.value == 43
                            && notification.persistent();
                    }
                    GetFlow::Continue
                })
                .await?,
        )?;
    }
    let cancelled = client.get(selector(b""))?;
    let followup = client.get(selector(b"counter"))?;
    let (mut cancelled_rows, mut followup_rows, mut followup_done) = (0, 0, false);
    while !followup_done {
        progress(
            client
                .drive(Some(deadline), |event, context| {
                    match event {
                        Event::GetValue { get: id, .. } if id == cancelled => {
                            cancelled_rows += 1;
                            if context.get_cancel(cancelled).is_err()
                                || context.get_callbacks_enabled(cancelled)
                                || !context.owns_get(cancelled)
                            {
                                callback_error = true;
                            }
                        }
                        Event::GetValue { get: id, statistic } => {
                            if id == followup && statistic.value == 43 {
                                followup_rows += 1;
                            } else {
                                callback_error = true;
                            }
                        }
                        Event::GetComplete(done) => {
                            if done.get == followup && done.result.is_ok() {
                                followup_done = true;
                            } else {
                                callback_error = true;
                            }
                        }
                        _ => {}
                    }
                    GetFlow::Continue
                })
                .await?,
        )?;
    }
    ensure(
        cancelled_rows == 1 && followup_rows == 1 && !callback_error,
        "cancelled GET leaked callbacks or consumed replacement END",
    )?;
    ensure(
        !client.owns_get(cancelled) && !client.get_callbacks_enabled(cancelled),
        "cancelled context not retired",
    )?;
    let aborted = client.get(selector(b""))?;
    let (mut abort_rows, mut abort_done) = (0, false);
    while !abort_done {
        progress(
            client
                .drive(Some(deadline), |event, _| {
                    match event {
                        Event::GetValue { get: id, .. } => {
                            if id != aborted {
                                callback_error = true;
                            }
                            abort_rows += 1;
                            return GetFlow::AbortIteration;
                        }
                        Event::GetComplete(done) => {
                            abort_done = done.get == aborted && done.result.is_ok();
                        }
                        _ => {}
                    }
                    GetFlow::Continue
                })
                .await?,
        )?;
    }
    ensure(
        abort_rows == 1 && !callback_error,
        "iterator abort lost its successful END continuation",
    )?;
    client.watch_cancel(watch)?;
    ensure(
        !client.owns_watch(watch),
        "cancelled watch retained authority",
    )?;
    // Warm established socket, then leave a non-transmitted envelope so the
    // official destroy(sync_first) branch actually sends its processing barrier.
    client.set(b"barrier", 99, true)?;
    client.destroy(true)?;
    let mut report = None;
    while report.is_none() {
        let step = client
            .drive(Some(deadline), |event, _| {
                if let Event::Destroyed(value) = event {
                    report = Some(value);
                }
                GetFlow::Continue
            })
            .await?;
        ensure(
            !matches!(step, Progress::Idle | Progress::WaitDeadline),
            "destroy wait expired",
        )?;
    }
    let report = report.ok_or("missing destroy report")?;
    ensure(
        report.outcome == DestroyOutcome::ProcessingConfirmed && report.unconfirmed_mutations == 0,
        "C processing confirmation missing",
    )?;
    emit(format_args!(
        "{{\"case\":\"roundtrip\",\"passed\":true,\"value\":43,\"cancelled_rows\":{cancelled_rows},\"abort_rows\":{abort_rows},\"destroy\":\"ProcessingConfirmed\",\"unconfirmed\":0}}"
    ))?;
    Ok(())
}
async fn restart<'owner>(mut client: Handle<'owner>, ready: &Path) -> Result<()> {
    seed(&mut client)?;
    let first = client.watch(selector(b"a"))?;
    let survivor = client.watch(selector(b"b"))?;
    let deadline = Instant::now() + Duration::from_secs(12);
    let (mut initial_a, mut initial_b, mut invalid) = (false, false, false);
    while !initial_a || !initial_b {
        progress(
            client
                .drive(Some(deadline), |event, _| {
                    if let Event::WatchValue {
                        watch,
                        selector,
                        notification,
                    } = event
                    {
                        if watch == first && selector.name == b"a" && notification.value == 10 {
                            initial_a = true;
                        } else if watch == survivor
                            && selector.name == b"b"
                            && notification.value == 20
                        {
                            initial_b = true;
                        } else {
                            invalid = true;
                        }
                    }
                    GetFlow::Continue
                })
                .await?,
        )?;
    }
    ensure(!invalid, "wrong initial logical watch")?;
    client.watch_cancel(first)?;
    let replacement = client.watch(selector(b"c"))?;
    let mut initial_c = false;
    while !initial_c {
        progress(
            client
                .drive(Some(deadline), |event, _| {
                    if let Event::WatchValue {
                        watch,
                        selector,
                        notification,
                    } = event
                    {
                        initial_c = watch == replacement
                            && selector.name == b"c"
                            && notification.value == 30;
                        if !initial_c {
                            invalid = true;
                        }
                    }
                    GetFlow::Continue
                })
                .await?,
        )?;
    }
    ensure(
        !invalid && !client.owns_watch(first),
        "cancelled watch hole retained authority",
    )?;
    let old_epoch = client.connection_epoch();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ready)?;
    writeln!(file, "{}", std::process::id())?;
    let (mut lost, mut seen_b, mut seen_c) = (false, false, false);
    while !seen_b || !seen_c {
        progress(client.drive(Some(deadline), |event, _| {
            match event {
                Event::ConnectionLost { .. } => lost = true,
                Event::WatchValue { watch, selector, notification } => {
                    if !lost { invalid = true; }
                    if watch == survivor && selector.name == b"b" && notification.wid == 0 { seen_b = true; }
                    else if watch == replacement && selector.name == b"c" && notification.wid == 1 { seen_c = true; }
                    else { invalid = true; }
                    if emit(format_args!("{{\"case\":\"restart-watch\",\"name\":\"{}\",\"wid\":{},\"value\":{}}}", String::from_utf8_lossy(selector.name), notification.wid, notification.value)).is_err() { invalid = true; }
                }
                _ => {}
            }
            GetFlow::Continue
        }).await?)?;
    }
    ensure(
        lost && !invalid && client.connection_epoch() != old_epoch,
        "watch reconnect epoch/WID binding mismatch",
    )?;
    client.destroy(false)?;
    ensure(client.is_closed(), "restart probe did not destroy owner")?;
    emit(format_args!(
        "{{\"case\":\"restart\",\"passed\":true,\"cancelled_watch_suppressed\":true,\"survivor_wid\":0,\"replacement_wid\":1}}"
    ))?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    ensure(
        args.len() == 3 || args.len() == 4,
        "usage: statistics_handle roundtrip CONFIG | restart CONFIG READY_FILE",
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut configuration = Configuration::new(Default::default());
    configuration.parse(Path::new(&args[2]))?;
    runtime.block_on(async {
        let mut domain = resolution_domain::Domain::new(configuration.duplicate()?)?;
        domain.start()?;
        let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
        let client = create(
            &mut statistics_instance_1,
            &configuration,
            domain.resolution(),
        )?;
        match args[1].to_str() {
            Some("roundtrip") if args.len() == 3 => roundtrip(client).await,
            Some("restart") if args.len() == 4 => restart(client, Path::new(&args[3])).await,
            _ => Err("unknown probe mode".into()),
        }
    })
}
