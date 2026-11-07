//! Explicit durable search lifecycle; historical status grants no current result proof.
use super::{
    publication::hex,
    search::anonymity_option,
    service::{duration, target},
};
use gnunet::{
    fs::{Limits as UriLimits, Uri, ublock},
    fs_host::{
        durable::store,
        ipc,
        search::{
            self, QueryInfo, ResultRecord, Step,
            task::{
                self, Control, Counts, Event, Limits, Phase, Progress, Status, StopReason, Task,
            },
        },
    },
    types::AbsoluteTime,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    io::{self, Write},
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
        Phase::PauseRequested => "pause_requested",
        Phase::Paused => "paused",
        Phase::CancelRequested => "cancel_requested",
        Phase::Cancelled => "cancelled",
        Phase::Failed => "failed",
    }
}
fn reason(value: StopReason) -> &'static str {
    match value {
        StopReason::CallerPause => "caller_pause",
        StopReason::Deadline => "caller_deadline",
        StopReason::Cancelled => "cancelled",
    }
}
fn counts(value: Counts) -> Value {
    json!({"observations":value.observations,"results":value.results,"visible":value.visible,"queries":value.queries})
}
fn status(value: Status) -> Value {
    json!({"phase":phase(value.phase),"active_owner":value.active,"interrupted":value.interrupted,
        "recorded_observations":value.recorded_observations,"historical":counts(value.historical),
        "state_records":value.state_records,"state_fenced":value.fenced,"results_currently_revalidated":false})
}
fn progress(value: Progress) -> Value {
    json!({"historical":counts(value.historical),"recorded_observations":value.recorded_observations,
        "replayed_observations_this_run":value.replayed_observations,"new_observations_this_run":value.new_observations,
        "results_this_run":value.results,"visible_results_this_run":value.visible_results,"queries_this_run":value.queries,
        "new_visible_results_this_run":value.new_visible_results,"state_records":value.state_records})
}
fn cause(value: &task::Cause) -> Value {
    match value {
        task::Cause::Storage(error) => {
            let failure = error.failure();
            json!({"kind":"storage","stage":failure.stage,"classification":format!("{:?}",failure.kind),
                "certainty":format!("{:?}",failure.certainty),"error":error.to_string()})
        }
        task::Cause::Model(error) => {
            json!({"kind":"model","classification":format!("{error:?}"),"error":error.to_string()})
        }
        task::Cause::Search(error) => json!({"kind":"search","error":error.to_string()}),
        task::Cause::Protocol(error) => {
            json!({"kind":"protocol","classification":format!("{error:?}")})
        }
        task::Cause::State(message) => json!({"kind":"state_precondition","reason":message}),
    }
}
fn failure_row(value: &task::Failure) -> Value {
    json!({"event":"fs_search_task_failed","cause":value.cause.as_ref().map(cause),
        "cleanup_error":value.cleanup.as_ref().map(ToString::to_string),"state_failure":value.state_failure.as_ref().map(cause),
        "progress":progress(value.progress),"requested_stop":value.requested_stop.map(reason),
        "query_failures":value.query_failures.iter().map(|failure|json!({"query_id":failure.query.index(),"cause":failure.cause.to_string()})).collect::<Vec<_>>(),
        "deadline_observation":value.deadline_observation.as_ref().map(ToString::to_string),"error":value.to_string()})
}
fn failed(out: &mut impl Write, error: Box<task::Failure>) -> Box<dyn Error> {
    let _diagnostic = row(out, &failure_row(&error));
    error
}
fn query(value: &QueryInfo<'_>) -> Value {
    json!({"label":std::str::from_utf8(value.label).ok(),"label_hex":hex(value.label),"lookup_key_hex":hex(value.query),
        "kind":format!("{:?}",value.kind),"namespace_hex":hex(value.namespace),
        "parent_results":value.parents.iter().map(|id|id.index()).collect::<Vec<_>>()})
}
fn record(value: &ResultRecord) -> Value {
    let metadata = value
        .metadata()
        .iter()
        .map(|owned| {
            let item = owned.item();
            json!({"kind":item.kind,"format":item.format as u32,"data_hex":hex(item.data),
            "plugin_hex":item.plugin.map(hex),"mime_hex":item.mime.map(hex)})
        })
        .collect::<Vec<_>>();
    json!({"uri":std::str::from_utf8(value.raw_uri()).ok(),"uri_bytes":value.raw_uri(),"visible":value.visible(),
        "mandatory_missing":value.mandatory_missing(),"optional_support":value.applicability(),
        "matched_query_ids":value.matched_queries().iter().map(|id|id.index()).collect::<Vec<_>>(),
        "source_namespace_query_id":value.source_namespace_query().map(|id|id.index()),
        "followed_update_query_id":value.continuation().map(|id|id.index()),"metadata":metadata})
}
fn observed(out: &mut impl Write, value: Progress, event: Event<'_>) -> io::Result<()> {
    match event {
        Event::Tick => Ok(()),
        Event::Restored {
            result,
            record: restored,
            query: source,
            continuation,
        } => row(
            out,
            &json!({
            "event":"fs_search_task_restored_result","result_id":result.index(),"record":record(restored),
            "historical_observation_revalidated":true,"current_freshness_or_availability_claim":false,
            "source_query":source.as_ref().map(query),"continuation_query":continuation.as_ref().map(query),"progress":progress(value)}),
        ),
        Event::Live {
            step,
            record: current,
            query: source,
            continuation,
        } => match step {
            Step::Result { result } | Step::Update { result } | Step::Pending { result } => {
                let event = match step {
                    Step::Result { .. } => "fs_search_task_result",
                    Step::Update { .. } => "fs_search_task_update",
                    _ => "fs_search_task_pending",
                };
                let current = current.ok_or_else(|| {
                    io::Error::other("search task event lost its current real result")
                })?;
                row(
                    out,
                    &json!({"event":event,"result_id":result.index(),"record":record(current),
                    "source_query":source.as_ref().map(query),"continuation_query":continuation.as_ref().map(query),"progress":progress(value)}),
                )
            }
            Step::Rejected { query: id, cause } => row(
                out,
                &json!({"event":"fs_search_task_rejected","query_id":id.index(),"cause":cause.to_string()}),
            ),
            Step::Failed { query: id, cause } => row(
                out,
                &json!({"event":"fs_search_task_query_failed","query_id":id.index(),"cause":cause.to_string()}),
            ),
            Step::Native {
                query: id,
                step: ipc::Step::Retry { cause, retry_after },
            } => row(
                out,
                &json!({"event":"fs_search_task_retry","query_id":id.index(),
                "cause":cause.to_string(),"retry_after":{"seconds":retry_after.as_secs(),"nanoseconds":retry_after.subsec_nanos()}}),
            ),
            Step::Native {
                query: id,
                step: ipc::Step::Unavailable(cause),
            } => row(
                out,
                &json!({"event":"fs_search_task_unavailable","query_id":id.index(),"cause":cause.to_string()}),
            ),
            Step::Ignored | Step::Native { .. } => Ok(()),
        },
    }
}
fn quota(raw: Option<&impl AsRef<OsStr>>, maximum: usize) -> Result<Option<usize>, Box<dyn Error>> {
    raw.map(|raw| -> Result<usize, Box<dyn Error>> {
        let text = raw
            .as_ref()
            .to_str()
            .ok_or("new-visible-results-per-run must be UTF-8 digits")?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err("new-visible-results-per-run must be nonnegative decimal digits".into());
        }
        let value = text.parse::<usize>()?;
        if value > maximum {
            return Err(format!(
                "new-visible-results-per-run exceeds task result capacity {maximum}"
            )
            .into());
        }
        Ok(value)
    })
    .transpose()
}
/// Keep original task/native failures when stdout delivery independently fails.
struct RunFailure {
    task: Option<Box<task::Failure>>,
    outcome: Option<task::Outcome>,
    output: Option<io::Error>,
    diagnostic: Option<io::Error>,
}
impl fmt::Debug for RunFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchTaskCliFailure")
            .field("task", &self.task)
            .field("outcome_retained", &self.outcome.is_some())
            .field("output", &self.output)
            .field("diagnostic", &self.diagnostic)
            .finish()
    }
}
impl fmt::Display for RunFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FS search task run stopped")?;
        if let Some(error) = &self.task {
            write!(f, ": {error}")?;
        }
        if let Some(done) = &self.outcome {
            for failure in &done.query_failures {
                write!(f, "; query {}: {}", failure.query.index(), failure.cause)?;
            }
        }
        if let Some(error) = &self.output {
            write!(f, "; result output: {error}")?;
        }
        if let Some(error) = &self.diagnostic {
            write!(f, "; diagnostic output: {error}")?;
        }
        Ok(())
    }
}
impl Error for RunFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(error) = &self.task {
            Some(error.as_ref())
        } else if let Some(failure) = self
            .outcome
            .as_ref()
            .and_then(|done| done.query_failures.first())
        {
            Some(&failure.cause)
        } else if let Some(error) = &self.output {
            Some(error)
        } else {
            self.diagnostic
                .as_ref()
                .map(|error| error as &(dyn Error + 'static))
        }
    }
}
struct CreateArguments<'a> {
    path: &'a OsStr,
    query: &'a OsStr,
    anonymity: u32,
}
fn create_arguments<T: AsRef<OsStr>>(args: &[T]) -> Result<CreateArguments<'_>, Box<dyn Error>> {
    let mut positional = Vec::new();
    positional.try_reserve_exact(2)?;
    let mut anonymity = None;
    let mut literal = false;
    let mut at = 0;
    while at < args.len() {
        let value = args[at].as_ref();
        let raw = value.as_bytes();
        if !literal && raw == b"--" {
            literal = true;
            at += 1;
            continue;
        }
        if !literal && anonymity_option(args, &mut at, &mut anonymity)? {
            continue;
        }
        if !literal && raw.starts_with(b"-") {
            return Err("unknown search-task-create option".into());
        }
        if positional.len() == 2 {
            return Err("search-task-create requires exactly task directory and URI".into());
        }
        positional.push(value);
        at += 1;
    }
    if positional.len() != 2 {
        return Err("search-task-create requires task directory and URI".into());
    }
    Ok(CreateArguments {
        path: positional[0],
        query: positional[1],
        anonymity: anonymity.unwrap_or(1),
    })
}
pub(super) fn create(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let selected = create_arguments(args)?;
    let query = Uri::parse(selected.query.as_bytes(), UriLimits::default())?;
    if !matches!(query, Uri::Keywords(_) | Uri::Namespace(_)) {
        return Err("search-task-create requires a KSK or SKS URI".into());
    }
    let options = search::Options {
        anonymity: selected.anonymity,
        local_only: false,
        deadline: AbsoluteTime::from_micros(0),
        limits: search::Limits::default(),
        block: ublock::Limits::default(),
        protocol: ipc::ProtocolLimits::default(),
        native: ipc::Limits::default(),
    };
    let task = Task::create(Path::new(selected.path), query, options, Limits::default())
        .map_err(|error| failed(out, error))?;
    row(
        out,
        &json!({"event":"fs_search_task_created","task_id":hex(task.task_id()),"status":status(task.status()),
        "query_uri":std::str::from_utf8(&task.manifest().query_uri).ok(),"query_uri_bytes":task.manifest().query_uri,
        "anonymity":task.manifest().options.anonymity}),
    )?;
    Ok(())
}
pub(super) fn status_command(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error))?;
    let manifest = task.manifest();
    row(
        out,
        &json!({"event":"fs_search_task_status","task_id":hex(task.task_id()),"status":status(task.status()),
        "query_uri":std::str::from_utf8(&manifest.query_uri).ok(),"query_uri_bytes":manifest.query_uri,
        "max_observations":manifest.max_observations,"anonymity":manifest.options.anonymity}),
    )?;
    Ok(())
}
pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let interval = duration(args.get(2))?;
    let path = Path::new(args[1].as_ref());
    let mut task =
        Task::open(path, store::Limits::default()).map_err(|error| failed(out, error))?;
    let limit = quota(args.get(3), task.manifest().options.limits.results)?;
    let source = ipc::EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let deadline = target(&source, interval)?;
    row(
        out,
        &json!({"event":"fs_search_task_run_started","task_id":hex(task.task_id()),"status":status(task.status()),
        "deadline_micros":deadline.as_micros(),"new_visible_results_per_run":limit,
        "anonymity":task.manifest().options.anonymity,
        "scope":"explicit search observation run; no whole-network completion or absence conclusion"}),
    )?;
    let mut output = None;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(task.run(source, deadline, |progress, event| {
            if output.is_none() {
                output = observed(out, progress, event).err();
            }
            if output.is_some() || limit.is_some_and(|limit| progress.new_visible_results >= limit)
            {
                Control::Pause
            } else {
                Control::Continue
            }
        }));
    match result {
        Ok(done) => {
            let diagnostic=row(out,&json!({"event":if done.reason==StopReason::Cancelled{"fs_search_task_cancelled"}else{"fs_search_task_paused"},
                "task_id":hex(task.task_id()),"reason":reason(done.reason),"status":status(task.status()),"progress":progress(done.progress),
                "query_failures":done.query_failures.iter().map(|failure|json!({"query_id":failure.query.index(),"cause":failure.cause.to_string()})).collect::<Vec<_>>(),
                "deadline_observation":done.deadline_observation.as_ref().map(ToString::to_string),
                "scope":"caller observation stopped; no whole-network completion or absence conclusion"})).err();
            if output.is_some() || diagnostic.is_some() || !done.query_failures.is_empty() {
                return Err(Box::new(RunFailure {
                    task: None,
                    outcome: Some(done),
                    output,
                    diagnostic,
                }));
            }
            Ok(())
        }
        Err(error) => {
            let diagnostic = row(out, &failure_row(&error)).err();
            Err(Box::new(RunFailure {
                task: Some(error),
                outcome: None,
                output,
                diagnostic,
            }))
        }
    }
}
pub(super) fn cancel(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error))?;
    task.request_cancel()?;
    if task.status().phase == Phase::Cancelled {
        row(
            out,
            &json!({"event":"fs_search_task_cancelled","task_id":hex(task.task_id()),"status":status(task.status())}),
        )?;
        return Ok(());
    }
    let done = task.settle_cancel().map_err(|error| failed(out, error))?;
    row(
        out,
        &json!({"event":"fs_search_task_cancelled","task_id":hex(task.task_id()),"reason":reason(done.reason),"status":status(task.status()),"progress":progress(done.progress)}),
    )?;
    Ok(())
}

#[cfg(test)]
mod anonymity_tests {
    use super::*;
    use std::{
        ffi::OsString,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn normal_dispatch_persists_the_exact_search_anonymity_for_reopen() -> Result<(), Box<dyn Error>>
    {
        let root = std::env::temp_dir().join(format!(
            "gnunet-fs-search-level-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        let root = Directory(root);
        for (name, level) in [("zero", 0), ("maximum", u32::MAX)] {
            let path = root.0.join(name);
            let args = [
                OsString::from("search-task-create"),
                path.as_os_str().to_owned(),
                OsString::from("gnunet://fs/ksk/query"),
                OsString::from("--anonymity"),
                OsString::from(level.to_string()),
            ];
            let mut out = Vec::new();
            super::super::run(&args, &mut out)?;
            let task = Task::open(&path, store::Limits::default())?;
            if task.manifest().options.anonymity != level {
                return Err(
                    "durable search anonymity was replaced during creation or reopen".into(),
                );
            }
            let row: Value = serde_json::from_slice(&out)?;
            if row.get("anonymity").and_then(Value::as_u64) != Some(u64::from(level)) {
                return Err("search task creation output lost the persisted level".into());
            }
        }
        Ok(())
    }
}
