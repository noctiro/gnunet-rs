//! Finite official PEERSTORE commands over an explicit caller-selected Unix MQ.
use super::peer::{hexadecimal as hex, parse as peer};
use gnunet::clients::peerstore::{
    Client, EndpointSource, Filter, Instance, Limits, Operation, Outcome, Progress, Record,
    RecordPhase,
};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    path::PathBuf,
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, PartialEq)]
enum Action {
    Store,
    Iterate,
    Monitor,
}
struct Command {
    action: Action,
    socket: PathBuf,
    subsystem: Vec<u8>,
    peer: Option<[u8; 32]>,
    key: Option<Vec<u8>>,
    value: Vec<u8>,
    replace: bool,
    expiry: u64,
    milliseconds: u64,
    initial: bool,
    limit: Option<u64>,
}
fn text(value: &OsStr) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| "expected UTF-8 argument".into())
}
fn parse(args: &[OsString]) -> Result<Command> {
    let action = match args.first().map(OsString::as_os_str) {
        Some(value) if value == "store" => Action::Store,
        Some(value) if value == "iterate" => Action::Iterate,
        Some(value) if value == "monitor" => Action::Monitor,
        _ => return Err("expected peerstore store|iterate|monitor; see peerstore --help".into()),
    };
    let required = if action == Action::Store { 6 } else { 3 };
    if args.len() < required {
        return Err("missing PEERSTORE arguments; see peerstore --help".into());
    }
    let mut command = Command {
        action,
        socket: PathBuf::from(&args[1]),
        subsystem: text(&args[2])?.as_bytes().to_vec(),
        peer: None,
        key: None,
        value: Vec::new(),
        replace: false,
        expiry: u64::MAX,
        milliseconds: 10_000,
        initial: false,
        limit: None,
    };
    if action == Action::Store {
        command.peer = Some(peer(&args[3])?);
        command.key = Some(text(&args[4])?.as_bytes().to_vec());
        let file = File::open(&args[5])?;
        if !file.metadata()?.is_file() {
            return Err("VALUE_FILE must be a regular file".into());
        }
        file.take(65_536).read_to_end(&mut command.value)?;
        if command.value.len() > 65_535 {
            return Err("value exceeds the official frame limit".into());
        }
    }
    let mut at = required;
    while at < args.len() {
        let flag = text(&args[at])?;
        at += 1;
        match flag {
            "--replace" if action == Action::Store => command.replace = true,
            "--initial" if action == Action::Monitor => command.initial = true,
            _ => {
                let value = args.get(at).ok_or("missing PEERSTORE option value")?;
                at += 1;
                match flag {
                    "--peer" if action != Action::Store => {
                        command.peer = Some(peer(value)?);
                    }
                    "--key" if action != Action::Store => {
                        command.key = Some(text(value)?.as_bytes().to_vec());
                    }
                    "--timeout-ms" if action != Action::Monitor => {
                        command.milliseconds = text(value)?.parse()?;
                    }
                    "--duration-ms" if action == Action::Monitor => {
                        command.milliseconds = text(value)?.parse()?;
                    }
                    "--limit" if action == Action::Iterate => {
                        let limit = text(value)?.parse()?;
                        if limit == 0 {
                            return Err("record limit must be nonzero".into());
                        }
                        command.limit = Some(limit);
                    }
                    "--expiry" if action == Action::Store => {
                        command.expiry = if value == "forever" {
                            u64::MAX
                        } else {
                            text(value)?.parse()?
                        };
                    }
                    _ => return Err(format!("unknown PEERSTORE option: {flag}").into()),
                }
            }
        }
    }
    if command.milliseconds == 0 {
        return Err("timeout/duration must be nonzero".into());
    }
    Ok(command)
}
fn row(out: &mut impl Write, value: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

async fn wait<'id>(
    client: &mut Client<'id>,
    deadline: Instant,
    mut interrupt: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> Result<Option<Progress<'id>>> {
    let driving = client.drive(Some(deadline));
    let mut driving = std::pin::pin!(driving);
    poll_fn(|cx| {
        if let Poll::Ready(interrupted) = interrupt.as_mut().poll(cx) {
            return Poll::Ready(interrupted.map(|()| None).map_err(Into::into));
        }
        driving
            .as_mut()
            .poll(cx)
            .map(|result| result.map(Some).map_err(Into::into))
    })
    .await
}
async fn observe<'id>(
    client: &mut Client<'id>,
    operation: Operation<'id>,
    command: &Command,
    deadline: Instant,
    out: &mut impl Write,
) -> Result<()> {
    let interrupt = tokio::signal::ctrl_c();
    let mut interrupt = std::pin::pin!(interrupt);
    let mut cancelled = false;
    let mut records = 0u64;
    loop {
        // Once cancellation begins, continue driving only its original finite
        // STOP/suffix debt; never poll the completed signal future again.
        let progress = if cancelled {
            client.drive(Some(deadline)).await?
        } else if let Some(progress) = wait(client, deadline, interrupt.as_mut()).await? {
            progress
        } else {
            cancelled = true;
            let cancellation = client.cancel(operation)?;
            row(
                out,
                serde_json::json!({"event":"peerstore_cancel","local":format!("{cancellation:?}")}),
            )?;
            continue;
        };
        match progress {
            Progress::Connected(epoch) => row(
                out,
                serde_json::json!({"event":"peerstore_connected","epoch":epoch.diagnostic()}),
            )?,
            Progress::Record(observation) => {
                let envelope = observation.record()?;
                let record = envelope.record;
                let phase = match observation.phase() {
                    RecordPhase::Iteration => "iteration",
                    RecordPhase::Initial => "initial",
                    RecordPhase::Live => "live",
                };
                row(
                    out,
                    serde_json::json!({"event":"peerstore_record","phase":phase,"epoch":observation.epoch().diagnostic(),"peer_hex":hex(&record.peer),"subsystem_hex":record.subsystem.map(hex),"key_hex":record.key.map(hex),"value_hex":hex(record.value),"expiry":record.expiry}),
                )?;
                records = records.checked_add(1).ok_or("record counter overflow")?;
                if !cancelled {
                    if command.limit.is_some_and(|limit| records >= limit) {
                        cancelled = true;
                        let cancellation = client.cancel(operation)?;
                        row(
                            out,
                            serde_json::json!({"event":"peerstore_cancel","local":format!("{cancellation:?}"),"reason":"record_limit"}),
                        )?;
                    } else if client.credit(operation)? == 0 {
                        client.next(operation, 256)?;
                    }
                }
            }
            Progress::Sync { epoch, .. } => row(
                out,
                serde_json::json!({"event":"peerstore_sync","epoch":epoch.diagnostic()}),
            )?,
            Progress::Completed { outcome, .. } => {
                let success = matches!(outcome, Outcome::StoreResult(1) | Outcome::IterationEnd(1));
                match outcome {
                    Outcome::StoreResult(result) => row(
                        out,
                        serde_json::json!({"event":"peerstore_store_result","result":result}),
                    )?,
                    Outcome::IterationEnd(result) => row(
                        out,
                        serde_json::json!({"event":"peerstore_iteration_end","result":result,"records":records}),
                    )?,
                    Outcome::Local { reason, submission } => row(
                        out,
                        serde_json::json!({"event":"peerstore_local_end","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"records":records}),
                    )?,
                }
                return if success || (cancelled && command.action != Action::Store) {
                    Ok(())
                } else {
                    Err(format!("PEERSTORE operation ended with {outcome:?}").into())
                };
            }
            Progress::Lost {
                epoch,
                cause,
                monitor_retained,
            } => row(
                out,
                serde_json::json!({"event":"peerstore_lost","epoch":epoch.map(|epoch|epoch.diagnostic()),"cause":format!("{cause:?}"),"monitor_retained":monitor_retained}),
            )?,
            Progress::WaitDeadline if command.action == Action::Monitor && !cancelled => {
                let cancellation = client.cancel(operation)?;
                row(
                    out,
                    serde_json::json!({"event":"peerstore_monitor_end","reason":"duration","local":format!("{cancellation:?}"),"records":records}),
                )?;
                return Ok(());
            }
            Progress::WaitDeadline => {
                return Err("PEERSTORE deadline; service completion was not observed".into());
            }
            Progress::Capacity(_) => return Err("PEERSTORE response capacity exhausted".into()),
            Progress::Unavailable(error) => return Err(error.into()),
            Progress::Closed => {
                return Err("PEERSTORE client closed without a terminal result".into());
            }
            Progress::ConnectRetry { error, retry_after } => row(
                out,
                serde_json::json!({"event":"peerstore_connect_retry","error":error.to_string(),"retry_after_micros":retry_after.as_micros()}),
            )?,
            _ => {}
        }
    }
}
pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args.is_empty() || args.first().is_some_and(|arg| arg == "--help") {
        writeln!(
            out,
            "peerstore store <UNIXPATH> <SUBSYSTEM> <PEER> <KEY> <VALUE_FILE> [--replace] [--expiry MICROS|forever] [--timeout-ms N]"
        )?;
        writeln!(
            out,
            "peerstore iterate <UNIXPATH> <SUBSYSTEM> [--peer PEER] [--key KEY] [--limit N] [--timeout-ms N]"
        )?;
        writeln!(
            out,
            "peerstore monitor <UNIXPATH> <SUBSYSTEM> [--peer PEER] [--key KEY] [--initial] [--duration-ms N]"
        )?;
        writeln!(
            out,
            "PEER accepts an official GNUnet identity or 64 hex digits. Timeout/duration defaults to 10000 ms. Expiry is absolute Unix microseconds; default forever. Output uses exact byte hex. Local cancellation/STOP writing is not a service ACK."
        )?;
        return Ok(());
    }
    let command = parse(args)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let duration = Duration::from_millis(command.milliseconds);
            let wall = Instant::now()
                .checked_add(duration)
                .ok_or("timeout is not representable")?;
            let source = EndpointSource::unix(command.socket.clone());
            let now = source.clock().sample()?.now.as_micros();
            let micros = u64::try_from(duration.as_micros())?;
            let expires = now
                .checked_add(micros)
                .and_then(|expiry| {
                    expiry.checked_add(if command.action == Action::Monitor {
                        5_000_000
                    } else {
                        0
                    })
                })
                .filter(|expiry| *expiry < u64::MAX - 5_000_000)
                .ok_or("operation deadline is not representable")?;
            let mut instance = Instance::new();
            let limits = Limits {
                operations: 1,
                ..Limits::default()
            };
            let mut client = if command.action == Action::Monitor {
                Client::new_monitor(&mut instance, source, limits)?
            } else {
                Client::new(&mut instance, source, limits)?
            };
            let result = async {
                let filter = Filter {
                    peer: command.peer,
                    subsystem: Some(&command.subsystem),
                    key: command.key.as_deref(),
                };
                let operation = match command.action {
                    Action::Store => client.store(
                        Record {
                            peer: command.peer.ok_or("store peer missing")?,
                            expiry: command.expiry,
                            subsystem: Some(&command.subsystem),
                            key: command.key.as_deref(),
                            value: &command.value,
                        },
                        u32::from(command.replace),
                        expires,
                    )?,
                    Action::Iterate => client.iterate(filter, expires)?,
                    Action::Monitor => client.monitor(filter, command.initial, expires)?,
                };
                let deadline = if command.action == Action::Monitor {
                    wall
                } else {
                    wall.checked_add(Duration::from_secs(6))
                        .ok_or("drain deadline overflow")?
                };
                observe(&mut client, operation, &command, deadline, out).await
            }
            .await;
            let cleanup = client.close();
            match (result, cleanup) {
                (Err(primary), Err(cleanup)) => {
                    Err(format!("{primary}; client close: {cleanup}").into())
                }
                (Err(primary), _) => Err(primary),
                (_, Err(cleanup)) => Err(cleanup.into()),
                _ => Ok(()),
            }
        })
}
