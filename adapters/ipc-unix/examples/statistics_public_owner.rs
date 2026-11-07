//! Independent normal Rust public-owner observer; no protocol implementation.
#![forbid(unsafe_code)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{GetFlow, GetId, WatchId},
};
use gnunet_config::Configuration;
use gnunet_ipc_unix::handle::{Event, Limits, Progress, StatisticsHandle};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::pin,
    task::Poll,
    time::Duration,
};
use tokio::{io::AsyncReadExt, time::Instant};

type Owner<'owner> = StatisticsHandle<'owner, 64, 512, 32, 64, 64>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[derive(Default)]
struct Context<'owner> {
    mode: u8,
    rows: u32,
    get: Option<GetId<'owner>>,
    watches: Vec<WatchId<'owner>>,
}
enum Either<A, B> {
    First(A),
    Second(B),
}
async fn choose<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = pin!(a);
    let mut b = pin!(b);
    poll_fn(|cx| {
        if let Poll::Ready(v) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::First(v));
        }
        b.as_mut().poll(cx).map(Either::Second)
    })
    .await
}
fn emit(text: impl std::fmt::Display) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{text}")?;
    out.flush()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn decode(value: &str) -> Result<Vec<u8>> {
    if value == "-" || value == "_" {
        return Ok(Vec::new());
    }
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err("invalid hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn callback<'owner>(
    event: Event<'owner, '_>,
    contexts: &mut [Context<'owner>],
    context: &mut gnunet_ipc_unix::handle::CallbackContext<'owner, '_, 64, 512, 32, 64, 64>,
) -> Result<GetFlow> {
    match event {
        Event::GetValue { get, statistic } => {
            let id = contexts
                .iter()
                .position(|c| c.get == Some(get))
                .ok_or("original GET owner missing")?;
            let c = &mut contexts[id];
            c.rows += 1;
            emit(format!(
                "{{\"event\":\"row\",\"kind\":\"get\",\"id\":{id},\"row\":{},\"sub_hex\":\"{}\",\"name_hex\":\"{}\",\"value\":\"{}\",\"persistent\":{}}}",
                c.rows,
                hex(statistic.selector.subsystem),
                hex(statistic.selector.name),
                statistic.value,
                u8::from(statistic.persistent())
            ))?;
            if c.mode == 2 {
                context.get_cancel(get)?;
                c.get = None;
                if context.get_callbacks_enabled(get) {
                    return Err("cancelled GET retained callback authority".into());
                }
                emit(format!("{{\"event\":\"callback_cancel\",\"id\":{id}}}"))?;
            }
            if c.mode == 1 {
                return Ok(GetFlow::AbortIteration);
            }
        }
        Event::GetComplete(done) => {
            let id = contexts
                .iter()
                .position(|c| c.get == Some(done.get))
                .ok_or("original GET continuation owner missing")?;
            let c = &mut contexts[id];
            c.get = None;
            if c.mode != 3 {
                emit(format!(
                    "{{\"event\":\"cont\",\"id\":{id},\"success\":{}}}",
                    if done.result.is_ok() { 1 } else { -1 }
                ))?;
            }
        }
        Event::WatchValue {
            watch,
            selector,
            notification,
        } => {
            let id = contexts
                .iter()
                .position(|c| c.watches.contains(&watch))
                .ok_or("original WATCH owner missing")?;
            let c = &mut contexts[id];
            c.rows += 1;
            emit(format!(
                "{{\"event\":\"row\",\"kind\":\"watch\",\"id\":{id},\"row\":{},\"sub_hex\":\"{}\",\"name_hex\":\"{}\",\"value\":\"{}\",\"persistent\":{}}}",
                c.rows,
                hex(selector.subsystem),
                hex(selector.name),
                notification.value,
                u8::from(notification.persistent())
            ))?;
            emit(format!(
                "{{\"event\":\"watch_metadata\",\"id\":{id},\"flags\":{},\"reserved\":{}}}",
                notification.flags, notification.reserved
            ))?;
            if c.mode == 1 {
                return Ok(GetFlow::AbortIteration);
            }
        }
        Event::ConnectionLost { epoch, cause } => emit(format!(
            "{{\"event\":\"connection_lost\",\"epoch\":{},\"cause\":\"{cause:?}\"}}",
            epoch.value()
        ))?,
        Event::Destroyed(report) => emit(format!(
            "{{\"event\":\"destroyed_report\",\"outcome\":\"{:?}\",\"unconfirmed\":{},\"discarded\":{}}}",
            report.outcome, report.unconfirmed_mutations, report.queued_mutations_discarded
        ))?,
        Event::ConnectionUnavailable { .. } => emit("{\"event\":\"configuration_unavailable\"}")?,
        _ => {}
    }
    Ok(GetFlow::Continue)
}
fn batch<'owner>(
    text: &str,
    instances: &mut std::slice::IterMut<'owner, gnunet_client::statistics_handle::Instance>,
    owner: &mut Option<Owner<'owner>>,
    contexts: &mut [Context<'owner>],
    config: &Configuration,
    resolution: &gnunet_client_host::resolution::SharedResolution,
    admitting: &mut bool,
) -> Result<bool> {
    for line in text.lines() {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        match words[0] {
            "CREATE" => {
                let sub = decode(words[1])?;
                *owner = Owner::from_config(
                    instances
                        .next()
                        .ok_or("statistics instance capacity exhausted")?,
                    config,
                    resolution.clone(),
                    &sub,
                    Limits::default(),
                )?;
                *admitting = owner.is_some();
                emit(format!(
                    "{{\"event\":\"create\",\"present\":{}}}",
                    owner.is_some()
                ))?;
            }
            op @ ("SET" | "UPDATE") => {
                let name = decode(words[1])?;
                let persist = words[3] != "0";
                if *admitting && let Some(h) = owner {
                    if op == "SET" {
                        h.set(&name, words[2].parse()?, persist)?;
                    } else {
                        h.update(&name, words[2].parse()?, persist)?;
                    }
                }
                emit(format!("{{\"event\":\"call\",\"api\":\"{op}\"}}"))?;
            }
            "GET" => {
                let id: usize = words[1].parse()?;
                let sub = decode(words[2])?;
                let name = decode(words[3])?;
                let c = &mut contexts[id];
                c.mode = words[4].parse()?;
                c.rows = 0;
                c.get = if *admitting {
                    owner
                        .as_mut()
                        .map(|h| {
                            h.get(Selector {
                                subsystem: &sub,
                                name: &name,
                            })
                        })
                        .transpose()?
                } else {
                    None
                };
                emit(format!(
                    "{{\"event\":\"get\",\"id\":{id},\"present\":{}}}",
                    c.get.is_some()
                ))?;
            }
            "GCANCEL" => {
                let id: usize = words[1].parse()?;
                if let Some(get) = contexts[id].get.take() {
                    owner.as_mut().ok_or("no owner")?.get_cancel(get)?;
                }
                emit(format!("{{\"event\":\"get_cancel\",\"id\":{id}}}"))?;
            }
            "WATCH" => {
                let id: usize = words[1].parse()?;
                let sub = decode(words[2])?;
                let name = decode(words[3])?;
                contexts[id].mode = words[4].parse()?;
                let watch = if *admitting {
                    owner
                        .as_mut()
                        .map(|h| {
                            h.watch(Selector {
                                subsystem: &sub,
                                name: &name,
                            })
                        })
                        .transpose()?
                } else {
                    None
                };
                if let Some(watch) = watch {
                    contexts[id].watches.push(watch);
                }
                emit(format!(
                    "{{\"event\":\"watch\",\"id\":{id},\"result\":{}}}",
                    if watch.is_some() { 1 } else { -1 }
                ))?;
            }
            "WCANCEL" => {
                let id: usize = words[1].parse()?;
                let canceled = if contexts[id].watches.is_empty() {
                    false
                } else {
                    let wid = contexts[id].watches.remove(0);
                    owner.as_mut().ok_or("no watch owner")?.watch_cancel(wid)?;
                    true
                };
                emit(format!(
                    "{{\"event\":\"watch_cancel\",\"id\":{id},\"result\":{}}}",
                    if canceled { 1 } else { -1 }
                ))?;
            }
            "DESTROY" => {
                let sync = words[1] != "0";
                emit(format!(
                    "{{\"event\":\"destroy_begin\",\"sync\":{}}}",
                    u8::from(sync)
                ))?;
                *admitting = false;
                if let Some(h) = owner {
                    h.destroy(sync)?;
                }
                emit(format!(
                    "{{\"event\":\"destroy_return\",\"sync\":{}}}",
                    u8::from(sync)
                ))?;
            }
            "STOP" => return Ok(true),
            _ => return Err("unknown observer command".into()),
        }
    }
    Ok(false)
}
async fn run(args: Vec<String>) -> Result<()> {
    if args.len() != 4 {
        return Err("usage: observer PATH DISABLE TRANSPORT".into());
    }
    let mut config = Configuration::new(gnunet_config::Limits::default());
    if args[3] != "missing" && !args[3].starts_with("tcp") {
        config.set_value(b"statistics", b"UNIXPATH", Some(args[1].as_bytes()))?;
    }
    if args[2] != "missing" {
        config.set_value(b"statistics", b"DISABLE", Some(args[2].as_bytes()))?;
    }
    config.set_value(
        b"statistics",
        b"PORT",
        Some(if args[3].starts_with("tcp") {
            args[1].as_bytes()
        } else {
            b"0"
        }),
    )?;
    if args[3] != "missing-hostname" {
        config.set_value(
            b"statistics",
            b"HOSTNAME",
            Some(match args[3].as_str() {
                "tcp4" => b"127.0.0.1",
                "tcp6" => b"::1",
                _ => b"localhost",
            }),
        )?;
    }
    let mut domain = resolution_domain::Domain::new(config.duplicate()?)?;
    domain.start()?;
    let resolution = domain.resolution();
    let mut instances: [gnunet_client::statistics_handle::Instance; 64] =
        core::array::from_fn(|_| gnunet_client::statistics_handle::Instance::new());
    let mut instances = instances.iter_mut();
    let mut owner: Option<Owner<'_>> = None;
    let mut contexts: Vec<Context> = (0..64).map(|_| Context::default()).collect();
    let mut admitting = false;
    let mut input = Vec::new();
    let mut buffer = [0_u8; 65536];
    let mut stdin = tokio::io::stdin();
    emit("{\"event\":\"ready\",\"version\":0,\"ok\":1,\"syserr\":-1}")?;
    loop {
        while let Some(index) = input.windows(7).position(|s| s == b"COMMIT\n") {
            let text = std::str::from_utf8(&input[..index])?;
            let stop = batch(
                text,
                &mut instances,
                &mut owner,
                &mut contexts,
                &config,
                &resolution,
                &mut admitting,
            )?;
            emit("{\"event\":\"commit\"}")?;
            input.drain(..index + 7);
            if stop {
                drop(owner);
                emit("{\"event\":\"exit\"}")?;
                return Ok(());
            }
        }
        let mut callback_error = None;
        let io = async {
            if let Some(h) = owner.as_mut() {
                h.drive(
                    Some(Instant::now() + Duration::from_millis(1)),
                    |event, context| match callback(event, &mut contexts, context) {
                        Ok(flow) => flow,
                        Err(error) => {
                            callback_error = Some(error);
                            GetFlow::AbortIteration
                        }
                    },
                )
                .await
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok(Progress::Idle)
            }
        };
        let progress = choose(stdin.read(&mut buffer), io).await;
        if let Some(error) = callback_error {
            return Err(error);
        }
        match progress {
            Either::First(read) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                input.extend_from_slice(&buffer[..n]);
                if input.len() > 262144 {
                    return Err("observer command batch too large".into());
                }
            }
            Either::Second(progress) => {
                if matches!(progress?, Progress::Idle | Progress::Closed) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    }
    drop(owner);
    emit("{\"event\":\"exit\"}")?;
    Ok(())
}
fn main() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(std::env::args().collect()))
}
