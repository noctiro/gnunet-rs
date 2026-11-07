//! Explicit durable native probe observations; history never becomes fresh proof.
use super::{
    publication::hex,
    service::{duration, target},
};
use gnunet::{
    crypto::Entropy,
    fs::{Limits as UriLimits, Uri},
    fs_host::{
        Buffers,
        ipc::EndpointSource,
        network::{DownloadOptions, probe},
        probe_task::{
            self as task, Attempt, Control, Kind, Limits, Observation, Phase, Receipt, Status, Task,
        },
        search::availability::Summary,
    },
    types::{AbsoluteTime, Error as ProtocolError},
};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    error::Error,
    ffi::OsStr,
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
}
fn phase(value: Phase) -> &'static str {
    match value {
        Phase::Ready => "ready",
        Phase::Running => "running",
        Phase::Paused => "paused",
        Phase::Cancelled => "cancelled",
        Phase::Exhausted => "exhausted",
    }
}
fn kind(value: Kind) -> &'static str {
    match value {
        Kind::Success => "success",
        Kind::Inconclusive => "inconclusive",
        Kind::SetupDeadline => "setup_deadline",
        Kind::Cancelled => "cancelled",
        Kind::Authentication => "authentication",
        Kind::Protocol => "protocol",
        Kind::Clock => "clock",
        Kind::Resource => "resource",
        Kind::Transport => "transport",
        Kind::Setup => "setup",
        Kind::Local => "local",
        Kind::Other => "other",
    }
}
fn attempt(value: Attempt) -> Value {
    json!({"ordinal":value.ordinal,"intent_record":value.intent_record,"leaf":value.leaf,"admitted_us":value.admitted.as_micros(),"deadline_us":value.deadline.as_micros()})
}
fn summary(value: Summary) -> Value {
    let errors = value.errors();
    json!({"attempts":value.attempts(),"successes":value.successes(),"trials":value.trials(),"rank":value.rank(),"certainty":value.certainty(),"cancelled":value.cancelled(),"setup_deadlines":value.setup_deadlines(),"source_elapsed_us":value.source_elapsed().0,"queries_written":value.queries_written(),"errors":{"setup":errors.setup,"resource":errors.resource,"transport":errors.transport,"authentication":errors.authentication,"protocol":errors.protocol,"clock":errors.clock,"local":errors.local,"other":errors.other},"fresh_observation":false})
}
fn status_value(value: Status) -> Value {
    json!({"phase":phase(value.phase),"active_owner":value.active,"historical":summary(value.historical),"pending":value.pending.map(attempt),"interrupted":value.interrupted,"history_bytes":value.history_bytes,"state_records":value.state_records,"state_fenced":value.fenced})
}
fn observation(value: &Observation) -> Value {
    json!({"attempt":attempt(value.attempt),"kind":kind(value.kind),"bytes":value.progress.plaintext_bytes,"blocks":value.progress.blocks,"encoded_bytes":value.progress.encoded_bytes,"queries_written":value.queries_written,"started_us":value.started.map(|v|v.as_micros()),"last_checked_us":value.last_checked.map(|v|v.as_micros()),"retired":value.retired,"wanted":match value.wanted{Control::Continue=>"continue",Control::Pause=>"pause",Control::Cancel=>"cancel"},"fresh_observation":false})
}
fn receipt(value: Option<&Receipt>) -> Value {
    value.map(|receipt|json!({"attempt":attempt(receipt.attempt()),"kind":kind(receipt.kind()),"body_hash":hex(&receipt.body_hash())})).unwrap_or(Value::Null)
}
fn open_limits() -> Limits {
    Limits {
        max_attempts: u32::MAX,
        max_trials: i32::MAX as u32,
        max_history_bytes: u64::MAX,
        ..Limits::default()
    }
}
fn local_error(error: &task::Cause) -> Value {
    match error {
        task::Cause::Storage(error) => {
            let failure = error.failure();
            json!({"kind":"storage","cause":error.to_string(),"stage":failure.stage,"certainty":format!("{:?}",failure.certainty),"classification":format!("{:?}",failure.kind)})
        }
        _ => json!({"kind":"local","cause":error.to_string()}),
    }
}
fn native(recorded: Option<&probe::Recorded>) -> Value {
    match recorded {
        None => Value::Null,
        Some(recorded) => match recorded.result() {
            Ok(actual) => {
                let progress = actual.progress();
                let range = actual.range();
                json!({"kind":"success","current_native":true,"leaf":actual.leaf(),"range_start":range.start,"range_end":range.end,"bytes":progress.plaintext_bytes,"blocks":progress.blocks,"encoded_bytes":progress.encoded_bytes,"queries_written":actual.queries_written(),"started_us":actual.started().as_micros(),"finished_us":actual.finished().as_micros(),"elapsed_us":actual.elapsed().0,"retired":actual.retired(),"transcript_frames":recorded.frames().len(),"last_response_bytes":actual.last_response().len()})
            }
            Err(failure) => {
                let progress = failure.progress();
                let range = failure.range();
                json!({"kind":"failure","cause":failure.cause().to_string(),"current_native":true,"leaf":failure.leaf(),"range_start":range.as_ref().map(|v|v.start),"range_end":range.as_ref().map(|v|v.end),"bytes":progress.plaintext_bytes,"blocks":progress.blocks,"encoded_bytes":progress.encoded_bytes,"queries_written":failure.queries_written(),"started_us":failure.started().map(|v|v.as_micros()),"last_checked_us":failure.last_checked().map(|v|v.as_micros()),"retired":failure.retired(),"transcript_frames":recorded.frames().len(),"last_response_bytes":failure.last_response().len()})
            }
        },
    }
}
fn history(task: &Task, event: &str) -> Value {
    let manifest = task.manifest();
    json!({"event":event,"task_id":hex(task.task_id()),"uri":std::str::from_utf8(&manifest.uri).ok(),"uri_bytes":manifest.uri,"origin":manifest.origin.map(|origin|hex(&origin)),"anonymity":manifest.options.transfer.anonymity,"local_only":manifest.options.transfer.local_only,"target_peer":hex(&manifest.options.transfer.target),"status":status_value(task.status()),"observations":task.observations().map(observation).collect::<Vec<_>>(),"revalidated_history":true,"fresh_observation":false})
}

pub(super) fn create(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let uri = Uri::parse(args[1].as_ref().as_bytes(), UriLimits::default())?;
    let options = match uri {
        Uri::Content(_) => probe::Options::new(AbsoluteTime::from_micros(0)),
        Uri::Location(location) => probe::Options::from(DownloadOptions::location(
            location,
            AbsoluteTime::from_micros(0),
        )),
        _ => return Err("probe task requires a resolved CHK or signed LOC URI".into()),
    };
    let trials = match args.get(2) {
        Some(value) => value
            .as_ref()
            .to_str()
            .ok_or("max-trials must be UTF-8 digits")?
            .parse::<u32>()?,
        None => 8,
    };
    let limits = Limits {
        max_attempts: 32.max(trials),
        max_trials: trials,
        ..Limits::default()
    };
    let task = Task::create(args[0].as_ref(), uri, options, limits)?;
    row(out, &history(&task, "fs_probe_task_created"))?;
    Ok(())
}
struct EntropySource(File);
impl Entropy for EntropySource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), ProtocolError> {
        self.0
            .read_exact(output)
            .map_err(|_| ProtocolError::Entropy)
    }
}

pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let source = EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let mut task = Task::open(args[1].as_ref(), open_limits())?;
    let interval = match args.get(2) {
        Some(value) => duration(Some(value))?,
        None => 5_000_000,
    };
    let deadline = target(&source, interval)?;
    let leaf = match args.get(3) {
        Some(value) => value
            .as_ref()
            .to_str()
            .ok_or("leaf must be UTF-8 digits")?
            .parse::<u64>()?,
        None => probe::sample_leaf(
            task.manifest().content()?,
            &mut EntropySource(File::open("/dev/urandom")?),
        )?,
    };
    let mut buffers = Buffers::new();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let stop = Cell::new(false);
            let mut original =
                std::pin::pin!(
                    task.run(source, &mut buffers, leaf, deadline, |_| if stop.get() {
                        Control::Pause
                    } else {
                        Control::Continue
                    })
                );
            let actual = poll_fn(|cx| {
                if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready() {
                    stop.set(true);
                }
                original.as_mut().poll(cx)
            })
            .await;
            Ok::<_, io::Error>(actual)
        })?;
    match result {
        Ok(outcome) => {
            let success = outcome.recorded.result().is_ok();
            row(
                out,
                &json!({"event":if success{"fs_probe_task_observed"}else{"fs_probe_task_interrupted"},"task_id":hex(task.task_id()),"kind":kind(outcome.receipt.kind()),"leaf":leaf,"native":native(Some(&outcome.recorded)),"current_native":true,"ledger_terminal":"accepted","receipt":receipt(Some(&outcome.receipt)),"persistent_historical":status_value(outcome.status),"fresh_observation":success}),
            )?;
            let (actual, _frames) = outcome.recorded.into_parts();
            actual
                .map(|_| ())
                .map_err(|error| Box::new(error) as Box<dyn Error>)
        }
        Err(error) => {
            row(
                out,
                &json!({"event":"fs_probe_task_interrupted","task_id":hex(task.task_id()),"kind":"local_failure","leaf":leaf,"native":native(error.recorded.as_ref()),"current_native":error.recorded.is_some(),"ledger_terminal":"unconfirmed","ledger_error":local_error(&error.cause),"receipt":receipt(error.receipt.as_ref()),"persistent_historical":error.status.map(status_value),"fresh_observation":error.recorded.as_ref().is_some_and(|recorded|recorded.result().is_ok())}),
            )?;
            Err(error as Box<dyn Error>)
        }
    }
}

pub(super) fn status(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let task = Task::open(args[0].as_ref(), open_limits())?;
    row(out, &history(&task, "fs_probe_task_status"))?;
    Ok(())
}
fn local_control(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
    cancel: bool,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(args[0].as_ref(), open_limits())?;
    let actual = if cancel {
        task.cancel()
    } else {
        task.abandon_interrupted()
    };
    match actual {
        Ok(_) => {
            row(
                out,
                &history(
                    &task,
                    if cancel {
                        "fs_probe_task_cancelled"
                    } else {
                        "fs_probe_task_abandoned"
                    },
                ),
            )?;
            Ok(())
        }
        Err(cause) => {
            row(
                out,
                &json!({"event":"fs_probe_task_interrupted","task_id":hex(task.task_id()),"kind":"local_failure","ledger_error":local_error(&cause),"persistent_historical":status_value(task.status()),"current_native":false,"fresh_observation":false}),
            )?;
            Err(Box::new(cause))
        }
    }
}
pub(super) fn abandon(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    local_control(args, out, false)
}
pub(super) fn cancel(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    local_control(args, out, true)
}
