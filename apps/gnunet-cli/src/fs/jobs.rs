//! Discover and drive registered original tasks through the bounded SDK worker.
use super::{publication::hex, service::duration};
use gnunet::{
    fs_host::{
        durable,
        ipc::EndpointSource,
        jobs::{
            self, Event, Execution, State, Worker,
            catalog::{Catalog, Directory, Kind, Policy},
        },
    },
    types::AbsoluteTime,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsStr,
    future::{Future, poll_fn},
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
}
fn kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Download => "download",
        Kind::Search => "search",
        Kind::Publication => "publication",
        Kind::Probe => "probe",
        Kind::Unindex => "unindex",
    }
}
fn directory(dir: &Directory) -> Value {
    let id = dir.identity();
    json!({"path":dir.path().to_str(),"path_bytes":dir.path().as_os_str().as_bytes(),"device":id.device,"inode":id.inode})
}
pub(super) fn create(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::create(args[0].as_ref(), Default::default())?;
    row(
        out,
        &json!({"event":"fs_jobs_created","catalog_id":hex(catalog.task_id())}),
    )?;
    Ok(())
}
pub(super) fn add(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let typed = match args[1].as_ref().to_str() {
        Some("download") => Kind::Download,
        Some("search") => Kind::Search,
        Some("publication") => Kind::Publication,
        Some("probe") => Kind::Probe,
        Some("unindex") => Kind::Unindex,
        _ => {
            return Err(
                "expected download, search, publication, probe or unindex task kind".into(),
            );
        }
    };
    let mut parent = None;
    let mut cache = None;
    let mut graph = None;
    let mut policy = Policy {
        slice_us: 5_000_000,
        quota: None,
        repeat_delay_us: None,
    };
    let mut cursor = 3;
    while cursor < args.len() {
        let option = args[cursor]
            .as_ref()
            .to_str()
            .ok_or("expected UTF-8 job option")?;
        let value = args.get(cursor + 1).ok_or("job option requires a value")?;
        match option {
            "--output-parent" => {
                if parent.replace(Path::new(value.as_ref())).is_some() {
                    return Err("duplicate output parent".into());
                }
            }
            "--cache" => {
                if cache.replace(Path::new(value.as_ref())).is_some() {
                    return Err("duplicate cache".into());
                }
            }
            "--graph" => {
                if graph.replace(Path::new(value.as_ref())).is_some() {
                    return Err("duplicate graph".into());
                }
            }
            "--slice" => policy.slice_us = duration(Some(value))?,
            "--repeat" => policy.repeat_delay_us = Some(duration(Some(value))?),
            "--quota" => {
                policy.quota = Some(
                    value
                        .as_ref()
                        .to_str()
                        .ok_or("quota must be UTF-8 digits")?
                        .parse()?,
                )
            }
            _ => return Err("unknown job option".into()),
        }
        cursor += 2;
    }
    let binding = jobs::bind(
        typed,
        Path::new(args[2].as_ref()),
        parent,
        cache,
        graph,
        policy,
        Default::default(),
    )?;
    let task_id = binding.task_id;
    let mut catalog = Catalog::open(args[0].as_ref(), Default::default())?;
    let id = catalog.register(binding)?;
    row(
        out,
        &json!({"event":"fs_job_registered","entry":id.index(),"task_id":hex(&task_id),"kind":kind(typed)}),
    )?;
    Ok(())
}
pub(super) fn list(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::open(args[0].as_ref(), Default::default())?;
    for record in catalog.entries() {
        let r = record.registration;
        row(
            out,
            &json!({"event":"fs_job_registered","entry":record.id.index(),"task_id":hex(&r.task_id),"kind":kind(r.kind),"enabled":record.enabled,"task":directory(&r.task),"output_parent":r.output_parent.as_ref().map(directory),"cache":r.cache.as_ref().map(directory),"graph":r.graph.as_ref().map(directory),"slice_us":r.policy.slice_us,"quota":r.policy.quota,"repeat_delay_us":r.policy.repeat_delay_us,"historical_task_inspected":false}),
        )?;
    }
    Ok(())
}
pub(super) fn enable(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let index = args[1]
        .as_ref()
        .to_str()
        .ok_or("entry must be UTF-8 digits")?
        .parse()?;
    let enabled = match args[2].as_ref().to_str() {
        Some("true") => true,
        Some("false") => false,
        _ => return Err("enabled must be true or false".into()),
    };
    let mut catalog = Catalog::open(args[0].as_ref(), Default::default())?;
    let id = catalog.entry_at(index).ok_or("unknown catalog entry")?.id;
    catalog.set_enabled(id, enabled)?;
    row(
        out,
        &json!({"event":"fs_job_enabled","entry":index,"enabled":enabled}),
    )?;
    Ok(())
}
fn phase(state: &State) -> &'static str {
    match state {
        State::Download(s) => match s.phase {
            durable::Phase::Ready => "ready",
            durable::Phase::Running => "running",
            durable::Phase::PauseRequested => "pause_requested",
            durable::Phase::Paused => "paused",
            durable::Phase::CancelRequested => "cancel_requested",
            durable::Phase::Cancelled => "cancelled",
            durable::Phase::Complete => "complete",
            durable::Phase::Failed => "failed",
        },
        State::Search(s) => match s.phase {
            gnunet::fs_host::search::task::Phase::Ready => "ready",
            gnunet::fs_host::search::task::Phase::Running => "running",
            gnunet::fs_host::search::task::Phase::PauseRequested => "pause_requested",
            gnunet::fs_host::search::task::Phase::Paused => "paused",
            gnunet::fs_host::search::task::Phase::CancelRequested => "cancel_requested",
            gnunet::fs_host::search::task::Phase::Cancelled => "cancelled",
            gnunet::fs_host::search::task::Phase::Failed => "failed",
        },
        State::Probe(s) => match s.phase {
            gnunet::fs_host::probe_task::Phase::Ready => "ready",
            gnunet::fs_host::probe_task::Phase::Running => "running",
            gnunet::fs_host::probe_task::Phase::Paused => "paused",
            gnunet::fs_host::probe_task::Phase::Cancelled => "cancelled",
            gnunet::fs_host::probe_task::Phase::Exhausted => "exhausted",
        },
        State::Unindex(s) => unindex_phase(s.phase),
        State::Publication(s) => match s.phase {
            gnunet::fs_host::publication::Phase::Ready => "ready",
            gnunet::fs_host::publication::Phase::Running => "running",
            gnunet::fs_host::publication::Phase::PauseRequested => "pause_requested",
            gnunet::fs_host::publication::Phase::Paused => "paused",
            gnunet::fs_host::publication::Phase::CancelRequested => "cancel_requested",
            gnunet::fs_host::publication::Phase::Cancelled => "cancelled",
            gnunet::fs_host::publication::Phase::Complete => "complete",
            gnunet::fs_host::publication::Phase::Failed => "failed",
            gnunet::fs_host::publication::Phase::Uncertain => "uncertain",
        },
    }
}
fn unindex_phase(phase: gnunet::fs_host::unindex_task::Phase) -> &'static str {
    use gnunet::fs_host::unindex_task::Phase;
    match phase {
        Phase::Ready => "ready",
        Phase::Running => "running",
        Phase::Paused => "paused",
        Phase::Failed => "failed",
        Phase::Complete => "complete",
        Phase::Cancelled => "cancelled",
        Phase::Interrupted => "interrupted",
    }
}
fn unindex_details(
    result: &Result<
        Box<gnunet::fs_host::unindex_task::Report>,
        Box<gnunet::fs_host::unindex_task::Failure>,
    >,
) -> Value {
    let (status, native, retained_unindexed) = match result {
        Ok(report) => (
            &report.status,
            Some(&report.native),
            Some(report.native.retained_unindexed),
        ),
        Err(failure) => (
            &failure.status,
            failure
                .completed
                .as_ref()
                .or_else(|| failure.native.as_ref().map(|native| &native.report)),
            None,
        ),
    };
    json!({
        "pending":status.pending.is_some(),
        "abandoned_uncertain":status.abandoned_uncertain,
        "new_content_positive":native.map(|r|r.observation.content_positive),
        "new_content_zero":native.map(|r|r.observation.content_zero),
        "new_keyword_positive":native.map(|r|r.observation.keyword_positive),
        "new_keyword_zero":native.map(|r|r.observation.keyword_zero),
        "retained_removals":native.map(|r|r.observation.retained_removals),
        "retained_keyword_selections":native.map(|r|r.observation.retained_keyword_selections),
        "fs_unindexed":native.map(|r|r.unindexed),
        "retained_unindexed":retained_unindexed.or_else(||native.map(|r|r.retained_unindexed)),
    })
}
fn probe_disposition(
    kind: gnunet::fs_host::probe_task::Kind,
    phase: gnunet::fs_host::probe_task::Phase,
) -> &'static str {
    use gnunet::fs_host::probe_task::{Kind, Phase};
    match kind {
        Kind::Success => "observed",
        Kind::Inconclusive => "inconclusive",
        Kind::SetupDeadline => "setup_deadline",
        Kind::Cancelled if phase == Phase::Cancelled => "cancelled",
        Kind::Cancelled => "paused",
        _ => "failed",
    }
}
fn probe_details(
    result: &Result<
        Box<gnunet::fs_host::probe_task::Outcome>,
        Box<gnunet::fs_host::probe_task::Failure>,
    >,
) -> (u32, Value) {
    let (receipt, recorded, terminal_recorded) = match result {
        Ok(outcome) => (Some(&outcome.receipt), Some(&outcome.recorded), true),
        Err(failure) => (failure.receipt.as_ref(), failure.recorded.as_ref(), false),
    };
    // Count only actual fresh native observations. Even when a later local
    // receipt/WAL step refuses, an original native proof or written deadline
    // remains visible; this projection cannot mint settlement authority.
    let trials = recorded.map_or(0, |recorded| match recorded.result() {
        Ok(_) => 1,
        Err(failure)
            if failure.queries_written() > 0
                && matches!(
                    failure.cause(),
                    gnunet::fs_host::network::Error::Deadline { .. }
                ) =>
        {
            1
        }
        Err(_) => 0,
    });
    let actual=recorded.map(|recorded|match recorded.result(){
        Ok(observed)=>json!({"result":"observed","cause":null,"leaf":observed.leaf(),"range":[observed.range().start,observed.range().end],"authenticated_blocks":observed.progress().blocks,"plaintext_bytes":observed.progress().plaintext_bytes,"queries_written":observed.queries_written(),"retired":observed.retired(),"path_frames":recorded.frames().len()}),
        Err(failure)=>json!({"result":"interrupted","cause":failure.cause().to_string(),"leaf":failure.leaf(),"authenticated_blocks":failure.progress().blocks,"plaintext_bytes":failure.progress().plaintext_bytes,"queries_written":failure.queries_written(),"retired":failure.retired(),"path_frames":recorded.frames().len()}),
    });
    (
        trials,
        json!({"terminal_recorded":terminal_recorded,"kind":receipt.map(|receipt|format!("{:?}",receipt.kind())),"native":actual}),
    )
}
fn event(event: &Event) -> Value {
    match event {
        Event::Skipped {
            entry,
            reason,
            state,
        } => {
            json!({"event":"fs_job_skipped","entry":entry.index(),"reason":format!("{reason:?}"),"after_phase":phase(state)})
        }
        Event::Settled(done) => {
            let (typed, disposition, cause, accepted, visible, files) = match &done.execution {
                Execution::NotStarted(cause) => {
                    let typed = if matches!(done.after.as_ref(), Some(State::Probe(_)))
                        || matches!(cause, jobs::Error::Probe(_) | jobs::Error::ProbeState(_))
                    {
                        "probe"
                    } else if matches!(done.after.as_ref(), Some(State::Unindex(_)))
                        || matches!(cause, jobs::Error::Unindex(_))
                    {
                        "unindex"
                    } else {
                        "unknown"
                    };
                    (typed, "not_started", Some(cause.to_string()), 0, 0, 0)
                }
                Execution::Download(result) => match result {
                    Ok(outcome) => (
                        "download",
                        match outcome.disposition {
                            durable::Disposition::Complete => "complete",
                            durable::Disposition::Paused => "paused",
                            durable::Disposition::Cancelled => "cancelled",
                        },
                        None,
                        0,
                        0,
                        outcome.progress.new_files,
                    ),
                    Err(cause) => (
                        "download",
                        "failed",
                        Some(cause.to_string()),
                        0,
                        0,
                        cause.progress.new_files,
                    ),
                },
                Execution::Search(result) => match result {
                    Ok(outcome) => (
                        "search",
                        match outcome.reason {
                            gnunet::fs_host::search::task::StopReason::CallerPause => "paused",
                            gnunet::fs_host::search::task::StopReason::Deadline => "deadline",
                            gnunet::fs_host::search::task::StopReason::Cancelled => "cancelled",
                        },
                        None,
                        0,
                        outcome.progress.new_visible_results,
                        0,
                    ),
                    Err(cause) => (
                        "search",
                        "failed",
                        Some(cause.to_string()),
                        0,
                        cause.progress.new_visible_results,
                        0,
                    ),
                },
                Execution::Probe(result) => match result {
                    Ok(outcome) => (
                        "probe",
                        probe_disposition(outcome.receipt.kind(), outcome.status.phase),
                        outcome
                            .recorded
                            .result()
                            .as_ref()
                            .err()
                            .map(|failure| failure.cause().to_string()),
                        0,
                        0,
                        0,
                    ),
                    Err(failure) => ("probe", "failed", Some(failure.to_string()), 0, 0, 0),
                },
                Execution::Unindex(result) => match result {
                    Ok(report) => ("unindex", unindex_phase(report.status.phase), None, 0, 0, 0),
                    Err(failure) => (
                        "unindex",
                        if failure.resumable() {
                            "paused"
                        } else if failure.status.phase
                            == gnunet::fs_host::unindex_task::Phase::Cancelled
                        {
                            "cancelled"
                        } else {
                            "failed"
                        },
                        Some(failure.to_string()),
                        0,
                        0,
                        0,
                    ),
                },
                Execution::Publication(result) => match result {
                    Ok(outcome) => (
                        "publication",
                        match outcome.reason {
                            gnunet::fs_host::publication::StopReason::Complete => "complete",
                            gnunet::fs_host::publication::StopReason::CallerPause => "paused",
                            gnunet::fs_host::publication::StopReason::Deadline => "deadline",
                            gnunet::fs_host::publication::StopReason::Cancelled => "cancelled",
                        },
                        outcome.cleanup.as_ref().map(ToString::to_string),
                        outcome.progress.new_accepted.accepted,
                        0,
                        0,
                    ),
                    Err(cause) => (
                        "publication",
                        "failed",
                        Some(cause.to_string()),
                        cause.progress.new_accepted.accepted,
                        0,
                        0,
                    ),
                },
            };
            let (new_trials, probe) = match &done.execution {
                Execution::Probe(result) => probe_details(result),
                _ => (0, Value::Null),
            };
            let unindex = match &done.execution {
                Execution::Unindex(result) => unindex_details(result),
                _ => Value::Null,
            };
            let download = match &done.execution {
                Execution::Download(Ok(outcome)) => {
                    json!({"progress":super::task::progress_value(outcome.progress),
                    "file_completion":outcome.file.as_ref().map(super::task::range_value)})
                }
                Execution::Download(Err(failure)) => {
                    json!({"progress":super::task::progress_value(failure.progress),
                    "file_completion":failure.file.as_ref().map(super::task::range_value)})
                }
                _ => Value::Null,
            };
            json!({"event":"fs_job_settled","entry":done.entry.index(),"task_id":hex(&done.task_id),"kind":typed,"disposition":disposition,"cause":cause,"new_accepted":accepted,"new_visible":visible,"new_files":files,"download":download,"new_trials":new_trials,"probe":probe,"unindex":unindex,"after_phase":done.after.as_ref().map(phase),"state_error":done.state_error.as_ref().map(ToString::to_string),"scheduling_error":done.scheduling_error.map(|error|error.to_string())})
        }
    }
}
pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let interval = match args.get(3) {
        Some(value) => duration(Some(value))?,
        None => 60_000_000,
    };
    let max_running = match args.get(4) {
        Some(value) => value
            .as_ref()
            .to_str()
            .ok_or("max-running must be UTF-8 digits")?
            .parse()?,
        None => 2,
    };
    let catalog = Catalog::open(args[0].as_ref(), Default::default())?;
    let fs = EndpointSource::unix(Path::new(args[1].as_ref()).to_path_buf());
    let clock = fs.clock();
    let until = AbsoluteTime::from_micros(
        clock
            .sample()?
            .now
            .as_micros()
            .checked_add(interval)
            .ok_or("worker deadline overflow")?,
    );
    let ds = EndpointSource::unix_with_clock(Path::new(args[2].as_ref()).to_path_buf(), clock);
    let sources = jobs::Sources::new(fs, ds)?;
    let mut worker = Worker::new(
        catalog,
        sources,
        jobs::Options {
            max_jobs: 1024,
            max_running,
            until,
            storage: Default::default(),
        },
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let stop=worker.stop_handle();
        let mut interrupt=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut output_error=None;let mut coordinator_error=None;
        loop {
            let actual={
                let mut next=std::pin::pin!(worker.next());
                poll_fn(|cx|{
                    if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready(){stop.request();}
                    next.as_mut().poll(cx)
                }).await
            };
            match actual {
                Ok(Some(actual))=>{
                    if output_error.is_none() && let Err(error)=row(out,&event(&actual)){output_error=Some(error);stop.request();}
                },
                Ok(None)=>break,
                Err(error)=>{coordinator_error=Some(error);break;},
            }
        }
        let stats=worker.stats();
        if output_error.is_none(){row(out,&json!({"event":"fs_jobs_stopped","stats":{"dispatched":stats.dispatched,"started":stats.started,"settled":stats.settled,"not_started":stats.not_started,"skipped":stats.skipped,"max_active":stats.max_active},"cause":coordinator_error.as_ref().map(ToString::to_string)}))?;}
        if let Some(error)=coordinator_error{return Err(Box::new(error) as Box<dyn Error>);}
        if let Some(error)=output_error{return Err(Box::new(error) as Box<dyn Error>);}
        Ok(())
    })
}
