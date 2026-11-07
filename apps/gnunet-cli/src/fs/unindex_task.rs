//! Explicit persisted unindex through the original source/native/WAL owners.
use super::{
    metadata_options,
    publication::hex,
    service::{datastore_client, duration, target},
    unindex::add_keywords,
};
use gnunet::fs_host::{
    Buffers,
    ipc::EndpointSource,
    network::unindex,
    unindex_task::{self as task, Control, Limits, Phase, Status, Task},
};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    error::Error,
    ffi::OsStr,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
    task::Poll,
    time::Duration,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::Instant,
};
fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
}
fn status_value(s: Status) -> Value {
    let phase = match s.phase {
        Phase::Ready => "ready",
        Phase::Running => "running",
        Phase::Paused => "paused",
        Phase::Failed => "failed",
        Phase::Complete => "complete",
        Phase::Cancelled => "cancelled",
        Phase::Interrupted => "interrupted",
    };
    json!({"phase":phase,"active":s.active,"state_fenced":s.fenced,"runs":s.runs,"original_mutation_intents":s.operations,
        "historical_accepted_operations":s.accepted,"unfinished_original":s.pending.map(|op|json!({"kind":op.kind,"digest_hex":hex(&op.digest)})),
        "explicitly_abandoned_uncertain":s.abandoned_uncertain,"original_not_submitted":s.not_submitted,"source_hash_bound":s.source_bound,"keywords_bound":s.keywords_bound,"completed_keyword_selections":s.completed_keywords})
}
fn history(task: &Task, event: &str) -> Value {
    json!({"event":event,"task_id_hex":hex(task.task_id()),"filename_bytes":task.manifest().filename.as_os_str().as_bytes(),
        "max_operations":task.manifest().max_operations,"extra_keyword_bytes":task.manifest().extra_keywords,
        "metadata_selection":format!("{:?}",task.manifest().metadata),"status":status_value(task.status()),
        "scope":"private original task history; no fresh source authentication, current store absence or remote deletion claim"})
}
fn open_limits() -> Limits {
    Limits {
        max_operations: u32::MAX,
        ..Limits::default()
    }
}
struct CreateArguments<'a> {
    path: &'a OsStr,
    file: &'a OsStr,
    words: Vec<Vec<u8>>,
    metadata: metadata_options::Arguments,
    limits: Limits,
}
fn create_arguments<T: AsRef<OsStr>>(args: &[T]) -> Result<CreateArguments<'_>, Box<dyn Error>> {
    let mut words = Vec::new();
    let mut limits = Limits::default();
    let mut metadata = metadata_options::Arguments::default();
    let mut positional = Vec::new();
    positional.try_reserve_exact(2)?;
    let mut max_operations = false;
    let mut literal = false;
    let mut i = 0;
    while i < args.len() {
        let value = args[i].as_ref();
        let raw = value.as_bytes();
        if !literal && raw == b"--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && metadata.consume(args, &mut i, false)? {
            continue;
        }
        if !literal && matches!(raw, b"--max-operations" | b"--keywords") {
            i += 1;
            let value = args
                .get(i)
                .ok_or("unindex task option requires a value")?
                .as_ref();
            if raw == b"--keywords" {
                add_keywords(value.as_bytes(), &mut words)?;
            } else {
                if max_operations {
                    return Err("--max-operations may be specified only once".into());
                }
                limits.max_operations = value
                    .to_str()
                    .ok_or("max-operations requires UTF-8 digits")?
                    .parse()?;
                max_operations = true;
            }
        } else if !literal && raw.starts_with(b"--keywords=") {
            add_keywords(&raw[11..], &mut words)?;
        } else {
            if !literal && raw.starts_with(b"-") {
                return Err("unknown unindex-task-create option".into());
            }
            if positional.len() == 2 {
                return Err("unindex-task-create requires exactly task and file paths".into());
            }
            positional.push(value);
        }
        i += 1;
    }
    if positional.len() != 2 {
        return Err("unindex-task-create requires task and file paths".into());
    }
    Ok(CreateArguments {
        path: positional[0],
        file: positional[1],
        words,
        metadata,
        limits,
    })
}
pub(super) fn create(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let selected = create_arguments(args)?;
    let metadata = selected.metadata.select()?;
    let task = Task::create(
        selected.path,
        selected.file,
        &selected.words,
        metadata,
        selected.limits,
    )?;
    row(out, &history(&task, "fs_unindex_task_created"))?;
    Ok(())
}

#[cfg(test)]
mod create_tests {
    use super::*;
    #[test]
    fn task_metadata_uses_the_same_flags_and_preserves_literal_option_paths()
    -> Result<(), Box<dyn Error>> {
        let selected = create_arguments(&["-D", "task", "file", "--max-operations", "17"])?;
        if selected.limits.max_operations != 17
            || selected.metadata.select()?.automatic_keywords_enabled()
        {
            return Err("unindex task metadata/budget selection changed".into());
        }
        let literal = create_arguments(&["--", "-D", "--meta"])?;
        if literal.path != OsStr::new("-D")
            || literal.file != OsStr::new("--meta")
            || !literal.metadata.select()?.format_extraction_enabled()
            || create_arguments(&["task", "file", "--meta", "title:value"]).is_ok()
        {
            return Err("unindex task literal or manual-metadata boundary changed".into());
        }
        Ok(())
    }
}
pub(super) fn status(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let task = Task::open(args[0].as_ref(), open_limits())?;
    row(out, &history(&task, "fs_unindex_task_status"))?;
    Ok(())
}
pub(super) fn cancel(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(args[0].as_ref(), open_limits())?;
    task.cancel()?;
    row(out, &history(&task, "fs_unindex_task_cancelled"))?;
    Ok(())
}
pub(super) fn restart(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(args[0].as_ref(), open_limits())?;
    let old = task.status().pending;
    task.restart_uncertain()?;
    row(
        out,
        &json!({"event":"fs_unindex_task_new_attempt_authorized","original_unknown":old.map(|o|json!({"kind":o.kind,"digest_hex":hex(&o.digest)})),"old_request_acknowledged":false,"new_native_request_issued":false,"task":history(&task,"fs_unindex_task_status")}),
    )?;
    Ok(())
}
fn native(report: &unindex::Report) -> Value {
    let p = report.observation;
    json!({"file_id_hex":report.file_id.as_ref().map(|id|hex(id)),"content":report.content.map(|c|json!({"key_hex":hex(&c.key),"query_hex":hex(&c.query),"size":c.size})),
        "hashed_bytes":p.hashed_bytes,"encoded_blocks":p.encoded.blocks,"encoded_plaintext_bytes":p.encoded.plaintext_bytes,"encoded_bytes":p.encoded.encoded_bytes,
        "current_content_positive_statuses":p.content_positive,"current_content_zero_statuses":p.content_zero,"current_keyword_positive_statuses":p.keyword_positive,"current_keyword_zero_statuses":p.keyword_zero,
        "historical_remove_receipts_reused":p.retained_removals,"historical_keyword_selections_reused":p.retained_keyword_selections,"historical_fs_ack_reused":report.retained_unindexed,
        "current_keyword_queries":p.keyword_queries,"current_keyword_rows":p.keyword_rows,"current_keyword_matches":p.keyword_matches,"current_keyword_ends":p.keyword_ends,
        "last_current_remove_status":p.last_status,"last_store_submitted":p.last_store_submitted,"current_fs_admitted":report.fs_admitted,
        "current_fs_written_bytes":p.fs_written_bytes,"current_unindexed_response":report.unindexed,"current_fs_response_retained":report.response().is_some(),"zero_remove_status":"actual raw service result; absence/backend failure remain ambiguous","scope":"selected stable-file local cleanup workflow; no remote deletion or complete historical advertisement removal claim"})
}
#[derive(Debug)]
struct Failure {
    original: Result<task::Report, Box<task::Failure>>,
    signal: Option<io::Error>,
    output: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.original {
            Ok(r) => write!(f, "unindex task original outcome: {r:?}")?,
            Err(e) => write!(f, "{e}; original typed facts: {e:?}")?,
        }
        if let Some(e) = &self.signal {
            write!(f, "; signal: {e}")?;
        }
        if let Some(e) = &self.output {
            write!(f, "; output: {e}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_ref()
            .err()
            .map(|e| e.as_ref() as &dyn Error)
            .or_else(|| self.signal.as_ref().map(|e| e as _))
            .or_else(|| self.output.as_ref().map(|e| e as _))
    }
}
pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let interval = duration(args.get(3))?;
    let hard = Instant::now()
        .checked_add(Duration::from_micros(interval))
        .ok_or("unindex-task native deadline overflow")?;
    let mut task = Task::open(args[2].as_ref(), open_limits())?;
    let fs = EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let ds = EndpointSource::unix_with_clock(Path::new(args[1].as_ref()).to_path_buf(), fs.clock());
    let deadline = target(&fs, interval)?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut interrupt=signal(SignalKind::interrupt())?;let mut terminate=signal(SignalKind::terminate())?;
        let stop=Cell::new(false);let mut signal_error=None;
        let mut identity=gnunet::datastore_host::Instance::new();let mut wire=Vec::new();wire.try_reserve_exact(65535)?;wire.resize(65535,0);
        let mut slots=[gnunet::datastore_host::Slot::new(&mut wire)];let mut reservations=[];
        let store=datastore_client(&mut identity,&mut slots,&mut reservations,ds)?;let mut buffers=Buffers::new();
        let original={
            let mut actual=std::pin::pin!(task.run(&mut buffers,fs,store,deadline,hard,|_|if stop.get(){Control::Pause}else{Control::Continue}));
            poll_fn(|cx| {
                if !stop.get() {
                    for signals in [&mut interrupt,&mut terminate] {
                        if let Poll::Ready(value)=signals.poll_recv(cx) {
                            stop.set(true);if value.is_none() && signal_error.is_none() {signal_error=Some(io::Error::new(io::ErrorKind::UnexpectedEof,"unindex task signal source closed"));}break;
                        }
                    }
                }
                // Keep polling the same owner through original cancellation and
                // actual physical cleanup; never replace a partially driven job.
                actual.as_mut().poll(cx)
            }).await
        };
        let (status,actual)=match &original {
            Ok(r)=>(r.status,Some(&r.native)),
            Err(e)=>(e.status,e.native.as_ref().map(|n|&n.report).or(e.completed.as_ref())),
        };
        let value=json!({"event":if original.is_ok(){"fs_unindex_task_complete"}else{"fs_unindex_task_stopped"},"status":status_value(status),"native":actual.map(native),
            "cause":original.as_ref().err().map(ToString::to_string),"original_typed_failures":original.as_ref().err().map(|e|format!("{e:?}")),
            "pause_requested":stop.get(),"signal_error":signal_error.as_ref().map(ToString::to_string)});
        let output=row(out,&value).err();
        if original.is_err() || signal_error.is_some() || output.is_some() {return Err(Box::new(Failure {original,signal:signal_error,output}) as Box<dyn Error>);}
        Ok(())
    })
}
